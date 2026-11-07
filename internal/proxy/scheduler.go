package proxy

import (
	"container/list"
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var errFetchBusy = errors.New("fetch capacity unavailable")

// A bounded set of origin controllers, independent of URLs, response contents,
// or any application's data model. No provider credentials are kept here.
const maxFetchOrigins = 128

type fetchRoute struct {
	lanes           []laneControl
	peers           peerView
	peersAt         time.Time
	used, paused    time.Time
	active, waiting int
}

type fetchWaiter struct {
	ctx        context.Context
	route      *fetchRoute
	port       uint16
	avoid, pin int
	ready      chan *fetchPermit
	element    *list.Element
	group      *fetchQueue
}

type fetchPermit struct {
	epoch   uint64
	s       *fetchScheduler
	route   *fetchRoute
	lane    int
	started time.Time
	once    sync.Once
}

// fetchClass is a request's Vpngate-Priority.
type fetchClass uint8

const (
	classInteractive fetchClass = iota
	classBulk
)

// While both classes wait, every bulkEvery-th dispatch serves bulk work.
const bulkEvery = 8

type fetchQueueKey struct {
	route      *fetchRoute
	port       uint16
	avoid, pin int
	class      fetchClass
}
type fetchQueue struct {
	key     fetchQueueKey
	waiters list.List
	element *list.Element
}

type fetchScheduler struct {
	groups                                           map[fetchQueueKey]*fetchQueue
	pending                                          int
	g                                                *Gateway
	mu                                               sync.Mutex
	routes                                           map[string]*fetchRoute
	queues                                           [2]list.List // waiting groups by class
	queued                                           [2]int       // waiters by class
	bulkTurn                                         int          // interactive dispatches since bulk was served
	active                                           int
	random                                           uint64
	disabled                                         []bool
	healthUntil                                      time.Time
	wake                                             chan struct{}
	scratch                                          [2][]float64
	requests, completed, retries, rejected, timeouts atomic.Uint64
}

func newFetchScheduler(g *Gateway) *fetchScheduler {
	s := &fetchScheduler{g: g, routes: make(map[string]*fetchRoute), groups: make(map[fetchQueueKey]*fetchQueue), random: 0x517cc1b727220a95,
		disabled: make([]bool, len(g.lanes)), wake: make(chan struct{}, 1)}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-g.ctx.Done():
				return
			case <-tick.C:
			case <-s.wake:
			}
			s.dispatch()
		}
	}()
	return s
}

func (s *fetchScheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *fetchScheduler) route(key string, now time.Time) *fetchRoute {
	if r := s.routes[key]; r != nil {
		r.used = now
		return r
	}
	if len(s.routes) == maxFetchOrigins {
		oldKey := ""
		var oldest time.Time
		for key, r := range s.routes {
			if r.active == 0 && r.waiting == 0 && (oldKey == "" || r.used.Before(oldest)) {
				oldKey = key
				oldest = r.used
			}
		}
		if oldKey == "" {
			return nil
		}
		delete(s.routes, oldKey)
	}
	r := &fetchRoute{used: now, lanes: make([]laneControl, len(s.g.lanes))}
	for i := range r.lanes {
		r.lanes[i] = newLaneControl(float64(s.g.cfg.Fetch.InitialPerTunnel))
	}
	s.routes[key] = r
	return r
}

func laneAllows(ports []uint16, port uint16) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func (s *fetchScheduler) candidate(w *fetchWaiter, i int, now time.Time) bool {
	return (w.pin < 0 || w.pin == i) && (w.avoid != i || w.pin == i || len(s.g.lanes) == 1) &&
		!(s.disabled[i] && now.Before(s.healthUntil)) && w.route.lanes[i].allows(now) &&
		len(s.g.lanes[i].slots) < cap(s.g.lanes[i].slots) &&
		laneAllows(s.g.cfg.Tunnels[i].Ports, w.port)
}

func (s *fetchScheduler) randomBelow(n int) int {
	x := s.random
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	s.random = x
	return int(x % uint64(n))
}

func (s *fetchScheduler) choose(w *fetchWaiter, now time.Time) *fetchPermit {
	if s.active >= s.g.cfg.Fetch.MaxInflight || now.Before(w.route.paused) {
		return nil
	}
	best, bestScore := -1, 0.0
	consider := func(i int) {
		if !s.candidate(w, i, now) {
			return
		}
		if score := w.route.lanes[i].score(w.route.peers, now); best < 0 || score < bestScore {
			best, bestScore = i, score
		}
	}
	if w.pin >= 0 {
		consider(w.pin)
	} else {
		// Two choices normally suffice. A fallback scan ensures that scarce
		// available lanes are still used rather than idling behind a full lane.
		n := len(s.g.lanes)
		first := s.randomBelow(n)
		consider(first)
		if n > 1 {
			consider((first + 1 + s.randomBelow(n-1)) % n)
		}
		if best < 0 {
			for i := range s.g.lanes {
				consider(i)
			}
		}
		if best < 0 && w.avoid >= 0 {
			// Prefer a different exit, but a transient error must not strand
			// work when only the previous exit remains available.
			previous := w.avoid
			w.avoid = -1
			consider(previous)
			w.avoid = previous
		}
	}
	if best < 0 {
		return nil
	}
	l := s.g.lanes[best]
	select {
	case l.slots <- struct{}{}:
	default:
		return nil
	}
	s.active++
	w.route.active++
	w.route.lanes[best].dispatched()
	recordPeak(&l.peak, l.active.Add(1))
	l.requests.Add(1)
	return &fetchPermit{s: s, route: w.route, lane: best, started: now, epoch: w.route.lanes[best].epoch}
}

// acquire waits for a dispatch permit. It also returns the time spent
// waiting in the gateway, including when it fails.
func (s *fetchScheduler) acquire(ctx context.Context, key string, port uint16, avoid, pin int, class fetchClass) (*fetchPermit, time.Duration, error) {
	start := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	s.mu.Lock()
	now := time.Now()
	r := s.route(key, now)
	if r == nil {
		s.mu.Unlock()
		s.rejected.Add(1)
		return nil, time.Since(start), errFetchBusy
	}
	w := &fetchWaiter{ctx: ctx, route: r, port: port, avoid: avoid, pin: pin, ready: make(chan *fetchPermit, 1)}
	if s.pending == 0 {
		if p := s.choose(w, now); p != nil {
			s.mu.Unlock()
			return p, time.Since(start), nil
		}
	}
	if s.pending >= s.g.cfg.Fetch.MaxPending {
		s.mu.Unlock()
		s.rejected.Add(1)
		return nil, time.Since(start), errFetchBusy
	}
	keyQueue := fetchQueueKey{route: r, port: port, avoid: avoid, pin: pin, class: class}
	group := s.groups[keyQueue]
	if group == nil {
		group = &fetchQueue{key: keyQueue}
		group.element = s.queues[class].PushBack(group)
		s.groups[keyQueue] = group
	}
	w.group = group
	w.element = group.waiters.PushBack(w)
	s.pending++
	s.queued[class]++
	r.waiting++
	s.mu.Unlock()
	s.signal()
	select {
	case p := <-w.ready:
		return p, time.Since(start), nil
	case <-ctx.Done():
		s.mu.Lock()
		if w.element != nil {
			s.remove(w)
		}
		s.mu.Unlock()
		// Dispatch may win just before cancellation; release that reservation.
		select {
		case p := <-w.ready:
			p.finish(0, 0, 0)
		default:
		}
		return nil, time.Since(start), ctx.Err()
	}
}

func (s *fetchScheduler) remove(w *fetchWaiter) {
	w.group.waiters.Remove(w.element)
	w.element = nil
	w.route.waiting--
	s.pending--
	s.queued[w.group.key.class]--
	if w.group.waiters.Len() == 0 {
		s.queues[w.group.key.class].Remove(w.group.element)
		delete(s.groups, w.group.key)
	}
}

func (s *fetchScheduler) dispatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	// Capacity only shrinks during one call, so a class with nothing
	// dispatchable stays that way until the next call.
	var exhausted [2]bool
	for s.active < s.g.cfg.Fetch.MaxInflight {
		// Interactive work goes first; while both classes wait, bulk work
		// still gets every bulkEvery-th dispatch.
		first := classInteractive
		if s.queues[classBulk].Len() > 0 && (s.queues[classInteractive].Len() == 0 || s.bulkTurn >= bulkEvery-1) {
			first = classBulk
		}
		served := false
		for _, class := range [2]fetchClass{first, 1 - first} {
			if exhausted[class] {
				continue
			}
			if !s.dispatchFrom(class, now) {
				exhausted[class] = true
				continue
			}
			if class == classBulk {
				s.bulkTurn = 0
			} else if s.queues[classBulk].Len() > 0 {
				s.bulkTurn++
			}
			served = true
			break
		}
		if !served {
			return
		}
	}
}

// dispatchFrom serves one waiter of a class, taking its groups (destination
// and eligibility) in turn. A saturated origin costs one failed choice, not a
// scan of every request waiting behind it.
func (s *fetchScheduler) dispatchFrom(class fetchClass, now time.Time) bool {
	q := &s.queues[class]
	for n := q.Len(); n > 0 && q.Len() > 0; n-- {
		group := q.Front().Value.(*fetchQueue)
		w := group.waiters.Front().Value.(*fetchWaiter)
		var p *fetchPermit
		if w.ctx.Err() != nil {
			s.remove(w)
		} else if p = s.choose(w, now); p != nil {
			s.remove(w)
			w.ready <- p
		}
		if group.waiters.Len() > 0 {
			q.MoveToBack(group.element)
		}
		if p != nil {
			return true
		}
	}
	return false
}

func (p *fetchPermit) pauseOrigin(d time.Duration) {
	if d <= 0 {
		return
	}
	p.s.mu.Lock()
	until := time.Now().Add(d)
	if until.After(p.route.paused) {
		p.route.paused = until
	}
	p.s.mu.Unlock()
}

func (p *fetchPermit) blockLane(now time.Time) {
	p.s.mu.Lock()
	p.route.lanes[p.lane].cool(now, 60*time.Second, float64(p.s.g.cfg.Fetch.InitialPerTunnel))
	p.s.mu.Unlock()
}

// outcome: 1 complete success, -1 retryable upstream failure, 0 neutral
// (caller cancellation, terminal HTTP response, etc.). Retry-After applies to
// the destination, because a 429 need not be an IP-specific quota.
func (p *fetchPermit) finish(outcome int, latency time.Duration, pause time.Duration) {
	p.finishAt(time.Now(), outcome, latency, pause)
}

func (p *fetchPermit) finishAt(now time.Time, outcome int, latency time.Duration, pause time.Duration) {
	p.once.Do(func() {
		s := p.s
		s.mu.Lock()
		r := p.route
		c := &r.lanes[p.lane]
		c.inflight--
		r.active--
		r.used = now
		s.active--
		if pause > 0 && now.Add(pause).After(r.paused) {
			r.paused = now.Add(pause)
		}
		if p.epoch == c.epoch {
			initial := float64(s.g.cfg.Fetch.InitialPerTunnel)
			switch outcome {
			case 1:
				load := float64(s.g.lanes[p.lane].active.Load())
				if c.succeeded(now, latency, load, r.peers, initial, float64(s.g.cfg.PerTunnel)) {
					s.refreshPeers(r, now)
				}
			case -1:
				c.failed(now, initial)
			}
		}
		s.mu.Unlock()
		l := s.g.lanes[p.lane]
		l.active.Add(-1)
		<-l.slots
		s.signal()
	})
}

// refreshPeers recomputes an origin's peer view, at most once a window.
func (s *fetchScheduler) refreshPeers(r *fetchRoute, now time.Time) {
	if now.Sub(r.peersAt) < windowMin {
		return
	}
	r.peersAt = now
	latencies, ratios := s.scratch[0][:0], s.scratch[1][:0]
	for i := range r.lanes {
		if c := &r.lanes[i]; c.latency > 0 && now.Sub(c.decided) <= peerFresh {
			latencies = append(latencies, c.latency)
			ratios = append(ratios, c.ratio)
		}
	}
	r.peers = peerView{n: len(latencies)}
	if len(latencies) > 0 {
		r.peers.latency, r.peers.ratio = median(latencies), median(ratios)
	}
	s.scratch = [2][]float64{latencies, ratios}
}

func (s *fetchScheduler) setHealth(disabled []bool) bool {
	if len(disabled) != len(s.disabled) {
		return false
	}
	s.mu.Lock()
	copy(s.disabled, disabled)
	s.healthUntil = time.Now().Add(30 * time.Second)
	s.mu.Unlock()
	s.signal()
	return true
}

// Status lists the most recently used origins' controllers, within a size
// bound that keeps 500 tunnels and 128 origins well inside a control reply.
const (
	maxStatusControllers = 16
	maxStatusLanes       = 2048
)

type controllerStatus struct {
	Origin        string         `json:"origin"`
	Active        int            `json:"active"`
	Queued        int            `json:"queued"`
	PausedMS      int64          `json:"paused_ms"`
	PeerLatencyMS *float64       `json:"peer_latency_ms"`
	Lanes         []laneSnapshot `json:"lanes"`
}

func (s *fetchScheduler) status() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	blocked := 0
	fresh := now.Before(s.healthUntil)
	if fresh {
		for _, v := range s.disabled {
			if v {
				blocked++
			}
		}
	}
	keys := make([]string, 0, len(s.routes))
	for key := range s.routes {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int { return s.routes[b].used.Compare(s.routes[a].used) })
	initial := float64(s.g.cfg.Fetch.InitialPerTunnel)
	controllers := []controllerStatus{}
	truncated := len(keys) > maxStatusControllers
	entries := 0
	for _, key := range keys[:min(len(keys), maxStatusControllers)] {
		r := s.routes[key]
		out := controllerStatus{Origin: key, Active: r.active, Queued: r.waiting, Lanes: []laneSnapshot{}}
		if now.Before(r.paused) {
			out.PausedMS = r.paused.Sub(now).Milliseconds()
		}
		if r.peers.n > 0 && now.Sub(r.peersAt) <= peerFresh {
			v := round1(r.peers.latency)
			out.PeerLatencyMS = &v
		}
		for i := range r.lanes {
			c := &r.lanes[i]
			if c.inflight == 0 && c.lastSample.IsZero() && c.failures == 0 && !now.Before(c.until) && c.limit == initial {
				continue // never used: the initial state
			}
			if entries == maxStatusLanes {
				truncated = true
				break
			}
			entries++
			out.Lanes = append(out.Lanes, c.snapshot(now, s.g.cfg.Tunnels[i].ID))
		}
		controllers = append(controllers, out)
	}
	return map[string]any{"listen": s.g.cfg.Fetch.Listen, "active": s.active, "queued": s.pending, "origins": len(s.routes),
		"queued_interactive": s.queued[classInteractive], "queued_bulk": s.queued[classBulk],
		"unavailable_tunnels": blocked, "kernel_health_fresh": fresh,
		"max_inflight": s.g.cfg.Fetch.MaxInflight, "max_pending": s.g.cfg.Fetch.MaxPending,
		"initial_per_tunnel": s.g.cfg.Fetch.InitialPerTunnel, "timeout_seconds": s.g.cfg.Fetch.TimeoutSeconds,
		"max_attempts": s.g.cfg.Fetch.MaxAttempts,
		"requests":     s.requests.Load(), "successful_attempts": s.completed.Load(), "retries": s.retries.Load(),
		"rejected": s.rejected.Load(), "timeouts": s.timeouts.Load(), "http2": s.g.cfg.Fetch.UseHTTP2(),
		"tls_verification": !s.g.cfg.Fetch.InsecureSkipVerify,
		"controllers":      controllers, "controllers_truncated": truncated}
}
