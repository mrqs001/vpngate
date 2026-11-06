package proxy

import (
	"container/list"
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

var errFetchBusy = errors.New("fetch capacity unavailable")

// A bounded set of origin controllers, independent of URLs, response contents,
// or any application's data model. No provider credentials are kept here.
const maxFetchOrigins = 128

type routeLane struct {
	epoch                    uint64
	inflight                 int
	limit, baseline, latency float64
	updated, until           time.Time
	failures, strikes        int
}

type fetchRoute struct {
	lanes           []routeLane
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

type fetchQueueKey struct {
	route      *fetchRoute
	port       uint16
	avoid, pin int
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
	queue                                            list.List
	active                                           int
	random                                           uint64
	disabled                                         []bool
	healthUntil                                      time.Time
	wake                                             chan struct{}
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
	r := &fetchRoute{used: now, lanes: make([]routeLane, len(s.g.lanes))}
	for i := range r.lanes {
		r.lanes[i].limit = float64(s.g.cfg.Fetch.InitialPerTunnel)
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
	c := &w.route.lanes[i]
	return (w.pin < 0 || w.pin == i) && (w.avoid != i || w.pin == i || len(s.g.lanes) == 1) &&
		!(s.disabled[i] && now.Before(s.healthUntil)) && !now.Before(c.until) &&
		c.inflight < int(c.limit) && len(s.g.lanes[i].slots) < cap(s.g.lanes[i].slots) &&
		laneAllows(s.g.cfg.Tunnels[i].Ports, w.port)
}

func (s *fetchScheduler) randomLane() int {
	x := s.random
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	s.random = x
	return int(x % uint64(len(s.g.lanes)))
}

func (s *fetchScheduler) choose(w *fetchWaiter, now time.Time) *fetchPermit {
	if s.active >= s.g.cfg.Fetch.MaxInflight || now.Before(w.route.paused) {
		return nil
	}
	best := -1
	consider := func(i int) {
		if !s.candidate(w, i, now) {
			return
		}
		c := &w.route.lanes[i]
		if best < 0 || float64(c.inflight)/c.limit < float64(w.route.lanes[best].inflight)/w.route.lanes[best].limit {
			best = i
		}
	}
	if w.pin >= 0 {
		consider(w.pin)
	} else {
		// Two choices normally suffice. A fallback scan ensures that scarce
		// available lanes are still used rather than idling behind a full lane.
		consider(s.randomLane())
		consider(s.randomLane())
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
	w.route.lanes[best].inflight++
	recordPeak(&l.peak, l.active.Add(1))
	l.requests.Add(1)
	return &fetchPermit{s: s, route: w.route, lane: best, started: now, epoch: w.route.lanes[best].epoch}
}

func (s *fetchScheduler) acquire(ctx context.Context, key string, port uint16, avoid, pin int) (*fetchPermit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	now := time.Now()
	r := s.route(key, now)
	if r == nil {
		s.mu.Unlock()
		s.rejected.Add(1)
		return nil, errFetchBusy
	}
	w := &fetchWaiter{ctx: ctx, route: r, port: port, avoid: avoid, pin: pin, ready: make(chan *fetchPermit, 1)}
	if s.pending == 0 {
		if p := s.choose(w, now); p != nil {
			s.mu.Unlock()
			return p, nil
		}
	}
	if s.pending >= s.g.cfg.Fetch.MaxPending {
		s.mu.Unlock()
		s.rejected.Add(1)
		return nil, errFetchBusy
	}
	keyQueue := fetchQueueKey{route: r, port: port, avoid: avoid, pin: pin}
	group := s.groups[keyQueue]
	if group == nil {
		group = &fetchQueue{key: keyQueue}
		group.element = s.queue.PushBack(group)
		s.groups[keyQueue] = group
	}
	w.group = group
	w.element = group.waiters.PushBack(w)
	s.pending++
	r.waiting++
	s.mu.Unlock()
	s.signal()
	select {
	case p := <-w.ready:
		return p, nil
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
		return nil, ctx.Err()
	}
}

func (s *fetchScheduler) remove(w *fetchWaiter) {
	w.group.waiters.Remove(w.element)
	w.element = nil
	w.route.waiting--
	s.pending--
	if w.group.waiters.Len() == 0 {
		s.queue.Remove(w.group.element)
		delete(s.groups, w.group.key)
	}
}

func (s *fetchScheduler) dispatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	// Round-robin between destinations/eligibility groups. A saturated origin
	// costs one failed choice, not a scan of every request waiting behind it.
	for s.active < s.g.cfg.Fetch.MaxInflight {
		progress := false
		groups := s.queue.Len()
		for n := 0; n < groups && s.active < s.g.cfg.Fetch.MaxInflight; n++ {
			group := s.queue.Front().Value.(*fetchQueue)
			w := group.waiters.Front().Value.(*fetchWaiter)
			if w.ctx.Err() != nil {
				s.remove(w)
				progress = true
			} else if p := s.choose(w, now); p != nil {
				s.remove(w)
				w.ready <- p
				progress = true
			}
			if group.waiters.Len() > 0 {
				s.queue.MoveToBack(group.element)
			}
		}
		if !progress {
			break
		}
	}
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

func (p *fetchPermit) blockLane() {
	p.s.mu.Lock()
	c := &p.route.lanes[p.lane]
	c.until = time.Now().Add(60 * time.Second)
	c.limit = 1
	c.epoch++
	p.s.mu.Unlock()
}

// outcome: 1 complete success, -1 retryable upstream failure, 0 neutral
// (caller cancellation, terminal HTTP response, etc.). Retry-After applies to
// the destination, because a 429 need not be an IP-specific quota.
func (p *fetchPermit) finish(outcome int, latency time.Duration, pause time.Duration) {
	p.once.Do(func() {
		s := p.s
		now := time.Now()
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
		if p.epoch != c.epoch {
			outcome = 0
		}
		switch outcome {
		case 1:
			if !c.until.IsZero() && !now.Before(c.until) {
				c.baseline = 0
				c.latency = 0
				c.until = time.Time{}
			}
			c.failures = 0
			c.strikes = 0
			ms := max(float64(latency)/float64(time.Millisecond), 0.01)
			if c.baseline == 0 {
				c.baseline = ms
				c.latency = ms
			}
			c.baseline = math.Min(ms, c.baseline*1.0001)
			c.latency = c.latency*0.9 + ms*0.1
			if now.Sub(c.updated) >= 250*time.Millisecond {
				if c.latency > c.baseline*2 {
					c.limit = math.Max(1, c.limit*0.9)
				} else if c.latency < c.baseline*1.5 {
					c.limit = math.Min(float64(s.g.cfg.PerTunnel), c.limit+math.Max(1, math.Sqrt(c.limit)/2))
				}
				c.updated = now
			}
		case -1:
			c.failures++
			if now.Sub(c.updated) >= 500*time.Millisecond {
				c.limit = math.Max(1, c.limit*0.8)
				c.updated = now
			}
			if c.failures >= 3 {
				c.epoch++
				c.strikes = min(c.strikes+1, 6)
				c.until = now.Add(time.Duration(1<<c.strikes) * time.Second)
				c.limit = 1 // one probation request, then ramp up on success
				c.failures = 0
			}
		}
		s.mu.Unlock()
		l := s.g.lanes[p.lane]
		l.active.Add(-1)
		<-l.slots
		s.signal()
	})
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

func (s *fetchScheduler) status() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	blocked := 0
	fresh := time.Now().Before(s.healthUntil)
	if fresh {
		for _, v := range s.disabled {
			if v {
				blocked++
			}
		}
	}
	return map[string]any{"listen": s.g.cfg.Fetch.Listen, "active": s.active, "queued": s.pending, "origins": len(s.routes),
		"unavailable_tunnels": blocked, "kernel_health_fresh": fresh,
		"max_inflight": s.g.cfg.Fetch.MaxInflight, "max_pending": s.g.cfg.Fetch.MaxPending,
		"requests": s.requests.Load(), "successful_attempts": s.completed.Load(), "retries": s.retries.Load(),
		"rejected": s.rejected.Load(), "timeouts": s.timeouts.Load(), "http2": s.g.cfg.Fetch.UseHTTP2(),
		"tls_verification": !s.g.cfg.Fetch.InsecureSkipVerify}
}
