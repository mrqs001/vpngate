package proxy

import (
	"container/heap"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

// The controller tests drive the real scheduler (choose and finish) in
// virtual time: a closed-loop client keeps demand requests outstanding and
// each lane answers after a synthetic time to first byte.

type simLane struct {
	median time.Duration
	sigma  float64 // log-space standard deviation of the time to first byte
	// knee is the tunnel's concurrency capacity: beyond it, latency grows in
	// proportion to the requests it carries, so throughput stays constant.
	knee int
	// fail reports whether a request dispatched at this virtual time fails.
	fail func(at time.Duration) bool
}

type simOrigin struct {
	key    string
	demand int
	scale  float64 // origin-side latency multiplier; zero means 1
	// pause, when it returns a positive duration, answers 429 with that
	// Retry-After for a request dispatched at this virtual time.
	pause func(at time.Duration) time.Duration
	// forbid reports whether lane answers 403 to a request dispatched at
	// this virtual time; the origin is treated as a retry_forbidden origin.
	forbid func(lane int, at time.Duration) bool
}

type simEvent struct {
	at      time.Time
	p       *fetchPermit
	origin  int
	latency time.Duration
	outcome int
	pause   time.Duration
	forbid  bool
}

type simEvents []simEvent

func (h simEvents) Len() int           { return len(h) }
func (h simEvents) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h simEvents) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *simEvents) Push(x any)        { *h = append(*h, x.(simEvent)) }
func (h *simEvents) Pop() any {
	old := *h
	v := old[len(old)-1]
	*h = old[:len(old)-1]
	return v
}

// simSample is the state once per virtual second.
type simSample struct {
	at       time.Duration
	limits   [][]float64 // [origin][lane]
	inflight [][]int
	waiting  []int
}

type simResult struct {
	samples    []simSample
	dispatched [][][]int // [origin][lane][second]
	completed  [][]int   // [origin][second] successful completions
	latencies  []float64 // successful time to first byte, ms, after warm-up
	routes     []*fetchRoute
	s          *fetchScheduler
}

func simGateway(t testing.TB, lanes int, edit func(*config.Runtime)) *fetchScheduler {
	t.Helper()
	c := config.Runtime{MaxConnections: 4096, PerTunnel: 512,
		Fetch: &config.Fetch{MaxInflight: 512, MaxPending: 4096, InitialPerTunnel: 32, MaxAttempts: 3, TimeoutSeconds: 30}}
	for i := range lanes {
		c.Tunnels = append(c.Tunnels, config.Lane{ID: fmt.Sprintf("lane-%d", i), Ports: []uint16{443}})
	}
	if edit != nil {
		edit(&c)
	}
	g := New(c, nil)
	g.fetch = newFetchScheduler(g)
	t.Cleanup(g.Close)
	return g.fetch
}

var simEpoch = time.Unix(1_800_000_000, 0)

func simulate(t testing.TB, s *fetchScheduler, lanes []simLane, origins []simOrigin, duration, warmup time.Duration, seed uint64) simResult {
	t.Helper()
	return simulateFrom(t, simEpoch, s, lanes, origins, duration, warmup, seed)
}

// simulateFrom starts at begin; times in the result are relative to it. At
// the end, requests still outstanding finish neutrally, as if canceled.
func simulateFrom(t testing.TB, begin time.Time, s *fetchScheduler, lanes []simLane, origins []simOrigin, duration, warmup time.Duration, seed uint64) simResult {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed, 0xda942042e4dd58b5))
	res := simResult{s: s, dispatched: make([][][]int, len(origins)), completed: make([][]int, len(origins))}
	seconds := int(duration/time.Second) + 1
	waiting := make([]int, len(origins))
	for o := range origins {
		waiting[o] = origins[o].demand
		res.dispatched[o] = make([][]int, len(lanes))
		for i := range lanes {
			res.dispatched[o][i] = make([]int, seconds)
		}
		res.completed[o] = make([]int, seconds)
		s.mu.Lock()
		res.routes = append(res.routes, s.route(origins[o].key, begin))
		s.mu.Unlock()
	}
	tunnel := make([]int, len(lanes)) // requests on each tunnel, all origins
	events := &simEvents{}
	now := begin
	nextSample := time.Duration(0)
	place := func() {
		for o := range origins {
			for waiting[o] > 0 {
				s.mu.Lock()
				r := s.route(origins[o].key, now)
				p := s.choose(&fetchWaiter{route: r, port: 443, avoid: -1, pin: -1}, now)
				s.mu.Unlock()
				if p == nil {
					break
				}
				waiting[o]--
				at := now.Sub(begin)
				i := p.lane
				res.dispatched[o][i][int(at/time.Second)]++
				tunnel[i]++
				m := lanes[i]
				latency := float64(m.median) * math.Exp(m.sigma*rng.NormFloat64())
				if origins[o].scale > 0 {
					latency *= origins[o].scale
				}
				if m.knee > 0 && tunnel[i] > m.knee {
					latency *= float64(tunnel[i]) / float64(m.knee)
				}
				ev := simEvent{at: now.Add(time.Duration(latency)), p: p, origin: o, latency: time.Duration(latency), outcome: 1}
				pause := time.Duration(0)
				if f := origins[o].pause; f != nil {
					pause = f(at)
				}
				if m.fail != nil && m.fail(at) {
					ev.outcome = -1
				} else if pause > 0 {
					ev.outcome, ev.pause = 0, pause
				} else if f := origins[o].forbid; f != nil && f(i, at) {
					ev.outcome, ev.forbid = -1, true
				}
				heap.Push(events, ev)
			}
		}
	}
	for now.Sub(begin) < duration {
		at := now.Sub(begin)
		if at >= nextSample {
			sample := simSample{at: at, waiting: slices.Clone(waiting)}
			s.mu.Lock()
			for _, r := range res.routes {
				var limits []float64
				var inflight []int
				for i := range r.lanes {
					limits = append(limits, r.lanes[i].limit)
					inflight = append(inflight, r.lanes[i].inflight)
				}
				sample.limits = append(sample.limits, limits)
				sample.inflight = append(sample.inflight, inflight)
			}
			s.mu.Unlock()
			res.samples = append(res.samples, sample)
			nextSample += time.Second
		}
		place()
		// Advance to the next completion, or 10 ms for cooldowns and pauses.
		next := now.Add(10 * time.Millisecond)
		if events.Len() > 0 && (*events)[0].at.Before(next) {
			next = (*events)[0].at
		}
		now = next
		for events.Len() > 0 && !(*events)[0].at.After(now) {
			ev := heap.Pop(events).(simEvent)
			tunnel[ev.p.lane]--
			if ev.forbid {
				ev.p.blockLane(ev.at)
			}
			ev.p.finishAt(ev.at, ev.outcome, ev.latency, ev.pause)
			waiting[ev.origin]++
			if second := int(ev.at.Sub(begin) / time.Second); ev.outcome == 1 && second < seconds {
				res.completed[ev.origin][second]++
				if ev.at.Sub(begin) >= warmup {
					res.latencies = append(res.latencies, float64(ev.latency)/float64(time.Millisecond))
				}
			}
		}
	}
	for events.Len() > 0 {
		heap.Pop(events).(simEvent).p.finishAt(now, 0, 0, 0)
	}
	return res
}

func sumRange(v []int, from, to int) int {
	n := 0
	for _, x := range v[from:min(to, len(v))] {
		n += x
	}
	return n
}

func equalLanes(n int, median time.Duration, sigma float64) []simLane {
	lanes := make([]simLane, n)
	for i := range lanes {
		lanes[i] = simLane{median: median, sigma: sigma}
	}
	return lanes
}

// Image tiles from a large CDN through a VPN vary by more than 3x between the
// median and the 95th percentile with nothing wrong. Noise alone must not shrink a
// lane, and the lanes together must grow to carry the offered load.
func TestFetchControllerKeepsThroughputUnderLognormalNoise(t *testing.T) {
	for _, sigma := range []float64{0.7, 0.9, 1.1} {
		for seed := uint64(1); seed <= 3; seed++ {
			t.Run(fmt.Sprintf("sigma=%v/seed=%d", sigma, seed), func(t *testing.T) {
				t.Parallel()
				if p95 := math.Exp(1.645 * sigma); p95 < 3 {
					t.Fatalf("trace too narrow: p95/p50 %.2f", p95)
				}
				s := simGateway(t, 6, nil)
				lanes := equalLanes(6, 150*time.Millisecond, sigma)
				res := simulate(t, s, lanes, []simOrigin{{key: "https://tiles.test:443", demand: 500}}, 90*time.Second, 15*time.Second, seed)
				queued := 0
				for _, sample := range res.samples[15:] {
					for i, limit := range sample.limits[0] {
						if limit < 32 {
							t.Fatalf("lane %d decayed to %.1f at %v under noise alone", i, limit, sample.at)
						}
					}
					queued += sample.waiting[0]
				}
				// Nearly all of the demand is upstream rather than queued.
				if mean := float64(queued) / float64(len(res.samples[15:])); mean > 25 {
					t.Fatalf("mean %.1f of 500 requests left queued in the gateway", mean)
				}
				total := 0
				for i := range lanes {
					total += sumRange(res.dispatched[0][i], 15, 90)
				}
				for i := range lanes {
					share := float64(sumRange(res.dispatched[0][i], 15, 90)) / float64(total)
					if share < 0.5/6 || share > 1.5/6 {
						t.Fatalf("lane %d share %.3f of equal lanes", i, share)
					}
				}
			})
		}
	}
}

// A tunnel three times slower than its peers, with nothing failing, keeps
// some traffic but receives less of it than the others.
func TestFetchControllerGivesSlowTunnelLessTraffic(t *testing.T) {
	s := simGateway(t, 6, nil)
	lanes := equalLanes(6, 150*time.Millisecond, 0.8)
	lanes[5].median = 450 * time.Millisecond
	res := simulate(t, s, lanes, []simOrigin{{key: "https://tiles.test:443", demand: 300}}, 90*time.Second, 15*time.Second, 7)
	counts := make([]int, len(lanes))
	others := 0
	for i := range lanes {
		counts[i] = sumRange(res.dispatched[0][i], 15, 90)
		if i < 5 {
			others += counts[i]
		}
	}
	if counts[5] == 0 {
		t.Fatal("slow tunnel abandoned without failures")
	}
	// The fast tunnels take up the demand instead.
	queued := 0
	for _, sample := range res.samples[15:] {
		queued += sample.waiting[0]
		for i, limit := range sample.limits[0][:5] {
			if limit < 32 {
				t.Fatalf("fast lane %d at %.1f", i, limit)
			}
		}
	}
	if mean := float64(queued) / float64(len(res.samples[15:])); mean > 15 {
		t.Fatalf("mean %.1f of 300 requests left queued in the gateway", mean)
	}
	if mean := float64(others) / 5; float64(counts[5]) > 0.5*mean {
		t.Fatalf("slow tunnel carried %d requests against a mean of %.0f", counts[5], mean)
	}
	last := res.samples[len(res.samples)-1].limits[0]
	for i := range 5 {
		if last[5] > last[i] {
			t.Fatalf("slow tunnel limit %.1f above peer %d's %.1f", last[5], i, last[i])
		}
	}
}

// Retryable failures cut the lane and cool it down; once the tunnel is
// healthy again, the lane ramps back to at least its initial limit.
func TestFetchControllerBacksOffOnFailuresAndRecovers(t *testing.T) {
	s := simGateway(t, 6, nil)
	lanes := equalLanes(6, 150*time.Millisecond, 0.8)
	lanes[2].fail = func(at time.Duration) bool { return at >= 20*time.Second && at < 30*time.Second }
	res := simulate(t, s, lanes, []simOrigin{{key: "https://tiles.test:443", demand: 400}}, 80*time.Second, 10*time.Second, 3)
	during := sumRange(res.dispatched[0][2], 22, 30)
	if during > 40 {
		t.Fatalf("failing lane received %d requests in 8 s of failures", during)
	}
	for _, sample := range res.samples[22:30] {
		if sample.limits[0][2] > 4 {
			t.Fatalf("failing lane limit %.1f at %v", sample.limits[0][2], sample.at)
		}
	}
	// The healthy lanes absorb the demand meanwhile.
	if done := sumRange(res.completed[0], 22, 30); done < 8*1500 {
		t.Fatalf("throughput fell to %d completions in 8 s", done)
	}
	recovered := -1
	for _, sample := range res.samples[30:] {
		if sample.limits[0][2] >= 32 {
			recovered = int(sample.at / time.Second)
			break
		}
	}
	// The last cooldown is at most 16 s here; the ramp then takes seconds.
	if recovered < 0 || recovered > 30+16+10 {
		t.Fatalf("lane did not ramp back after the failures ended (at %d s)", recovered)
	}
	if late := sumRange(res.dispatched[0][2], 70, 80); late < 2000 {
		t.Fatalf("recovered lane carries only %d requests in 10 s", late)
	}
}

// A 429 with Retry-After pauses the whole origin for that long, without
// treating any tunnel as failed; traffic resumes at the previous limits.
func TestFetchControllerHonoursRetryAfter(t *testing.T) {
	s := simGateway(t, 6, nil)
	lanes := equalLanes(6, 150*time.Millisecond, 0.8)
	paused := false
	origin := simOrigin{key: "https://tiles.test:443", demand: 400, pause: func(at time.Duration) time.Duration {
		if at >= 30*time.Second && !paused {
			paused = true
			return 5 * time.Second
		}
		return 0
	}}
	other := simOrigin{key: "https://other.test:443", demand: 50}
	res := simulate(t, s, lanes, []simOrigin{origin, other}, 60*time.Second, 10*time.Second, 5)
	if !paused {
		t.Fatal("no 429 was answered")
	}
	// The 429 arrives about one latency after 30 s; then nothing for 5 s.
	for second := 32; second < 35; second++ {
		for i := range lanes {
			if n := res.dispatched[0][i][second]; n != 0 {
				t.Fatalf("lane %d dispatched %d requests at %d s during Retry-After", i, n, second)
			}
		}
	}
	if sumRange(res.completed[1], 32, 35) == 0 {
		t.Fatal("unrelated origin paused too")
	}
	for i := range lanes {
		if n := sumRange(res.dispatched[0][i], 37, 40); n == 0 {
			t.Fatalf("lane %d did not resume after Retry-After", i)
		}
		if limit := res.samples[33].limits[0][i]; limit < 32 {
			t.Fatalf("a 429 cut lane %d to %.1f", i, limit)
		}
	}
}

// On a retry_forbidden origin, a 403 withholds that tunnel from that origin
// for 60 s; then it gets one probation request and ramps back.
func TestFetchControllerForbiddenCooldownAndRecovery(t *testing.T) {
	s := simGateway(t, 6, nil)
	lanes := equalLanes(6, 150*time.Millisecond, 0.8)
	forbidden := false
	origin := simOrigin{key: "https://tiles.test:443", demand: 400, forbid: func(lane int, at time.Duration) bool {
		if lane == 4 && at >= 10*time.Second && !forbidden {
			forbidden = true
			return true
		}
		return false
	}}
	other := simOrigin{key: "https://other.test:443", demand: 100}
	res := simulate(t, s, lanes, []simOrigin{origin, other}, 110*time.Second, 5*time.Second, 9)
	if !forbidden {
		t.Fatal("no 403 was answered")
	}
	if n := sumRange(res.dispatched[0][4], 12, 70); n != 0 {
		t.Fatalf("forbidden lane received %d requests during its cooldown", n)
	}
	if sumRange(res.dispatched[1][4], 12, 70) == 0 {
		t.Fatal("cooldown leaked to another origin")
	}
	recovered := false
	for _, sample := range res.samples[71:] {
		if sample.limits[0][4] >= 32 {
			recovered = true
			break
		}
	}
	if !recovered || sumRange(res.dispatched[0][4], 100, 110) < 1000 {
		t.Fatal("forbidden lane did not ramp back after its cooldown")
	}
}

// Each origin has its own controllers: one origin being slow on every
// tunnel neither shrinks the others nor drives its own lanes to one.
func TestFetchControllerManyOriginsAreIndependent(t *testing.T) {
	s := simGateway(t, 6, nil)
	lanes := equalLanes(6, 120*time.Millisecond, 0.8)
	var origins []simOrigin
	for i := range 20 {
		origins = append(origins, simOrigin{key: fmt.Sprintf("https://o%d.test:443", i), demand: 20, scale: 1 + float64(i)/4})
	}
	res := simulate(t, s, lanes, origins, 60*time.Second, 10*time.Second, 11)
	for o := range origins {
		for _, sample := range res.samples[10:] {
			for i, limit := range sample.limits[o] {
				if limit < 32 {
					t.Fatalf("origin %d lane %d decayed to %.1f", o, i, limit)
				}
			}
		}
		if res.completed[o][59] == 0 {
			t.Fatalf("origin %d starved", o)
		}
	}
	s.mu.Lock()
	n := len(s.routes)
	s.mu.Unlock()
	if n != len(origins) {
		t.Fatalf("%d resident origin controllers for %d origins", n, len(origins))
	}
}

// Genuine queueing still counts: beyond a tunnel's capacity, latency grows
// with concurrency, and the controller stops growing near that knee instead
// of filling the tunnel up to per_tunnel_connections.
func TestFetchControllerStopsAtCapacityKnee(t *testing.T) {
	s := simGateway(t, 3, nil)
	lanes := equalLanes(3, 150*time.Millisecond, 0.5)
	for i := range lanes {
		lanes[i].knee = 60
	}
	res := simulate(t, s, lanes, []simOrigin{{key: "https://tiles.test:443", demand: 500}}, 180*time.Second, 30*time.Second, 13)
	for _, sample := range res.samples[30:] {
		for i, limit := range sample.limits[0] {
			if limit > 150 {
				t.Fatalf("lane %d grew to %.1f past a knee of 60 at %v", i, limit, sample.at)
			}
		}
	}
	// Throughput is the capacity: 3 lanes x 60 / (150 ms x exp(0.125)).
	capacity := 3 * 60 / (0.150 * math.Exp(0.125))
	if rate := float64(sumRange(res.completed[0], 30, 180)) / 150; rate < 0.9*capacity {
		t.Fatalf("%.0f completions/s of a %.0f/s capacity", rate, capacity)
	}
	slices.Sort(res.latencies)
	if p50 := res.latencies[len(res.latencies)/2]; p50 > 2.5*150 {
		t.Fatalf("median time to first byte %.0f ms: the tunnels are overfilled", p50)
	}
}

// A path that becomes slower and stays slower is a new normal, not
// congestion: the baseline rises again and the lane is not left shrunken.
func TestFetchControllerBaselineRisesAfterPathChange(t *testing.T) {
	s := simGateway(t, 1, nil)
	lanes := []simLane{{median: 100 * time.Millisecond, sigma: 0.6}}
	origin := simOrigin{key: "https://tiles.test:443", demand: 100}
	simulate(t, s, lanes, []simOrigin{origin}, 30*time.Second, 5*time.Second, 17)
	// Same scheduler state, now three times slower for the rest of the run.
	lanes[0].median = 300 * time.Millisecond
	res := simulateFrom(t, simEpoch.Add(30*time.Second), s, lanes, []simOrigin{origin}, 90*time.Second, 0, 19)
	for _, sample := range res.samples[60:] {
		if limit := sample.limits[0][0]; limit < 32 {
			t.Fatalf("lane still at %.1f after the path settled (%v)", limit, sample.at)
		}
	}
	s.mu.Lock()
	c := s.routes[origin.key].lanes[0]
	s.mu.Unlock()
	if c.base < 200 || c.base > 450 {
		t.Fatalf("baseline %.0f ms did not follow a 300 ms path", c.base)
	}
}

// The controller state is visible: limit, baseline, recent latency, in
// flight and a state for each origin and tunnel.
func TestFetchControllerSnapshot(t *testing.T) {
	s := simGateway(t, 3, nil)
	lanes := equalLanes(3, 150*time.Millisecond, 0.8)
	lanes[1].fail = func(at time.Duration) bool { return at >= 15*time.Second }
	simulate(t, s, lanes, []simOrigin{{key: "https://tiles.test:443", demand: 200}}, 16*time.Second, 0, 23)
	at := simEpoch.Add(16 * time.Second)
	s.mu.Lock()
	r := s.routes["https://tiles.test:443"]
	for range 6 {
		if s.choose(&fetchWaiter{route: r, port: 443, avoid: -1, pin: -1}, at) == nil {
			t.Fatal("no lane available")
		}
	}
	c0 := r.lanes[0].snapshot(at, "lane-0")
	c1 := r.lanes[1].snapshot(at, "lane-1")
	c2 := r.lanes[2].snapshot(at, "lane-2")
	s.mu.Unlock()
	if c0.Limit < 32 || c0.BaselineMS == nil || c0.LatencyMS == nil || *c0.BaselineMS < 50 || *c0.LatencyMS < 50 || c0.Inflight != 3 || c2.Inflight != 3 {
		t.Fatalf("healthy lane snapshots %+v %+v", c0, c2)
	}
	if c0.State != "growing" && c0.State != "steady" {
		t.Fatalf("healthy lane state %q", c0.State)
	}
	if c1.State != "cooldown" || c1.CooldownMS <= 0 || c1.Inflight != 0 {
		t.Fatalf("failing lane snapshot %+v", c1)
	}
}

// The two random choices are two different lanes: an empty fast lane is
// never passed over for a slower one because both picks hit the slow one.
func TestFetchChooseComparesTwoDistinctLanes(t *testing.T) {
	s := simGateway(t, 2, nil)
	at := simEpoch
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.route("https://tiles.test:443", at)
	for i, ms := range []float64{100, 1000} {
		r.lanes[i].latency, r.lanes[i].ratio, r.lanes[i].decided = ms, 1, at
	}
	r.peers = peerView{n: 2, latency: 550, ratio: 1}
	for range 200 {
		p := s.choose(&fetchWaiter{route: r, port: 443, avoid: -1, pin: -1}, at)
		if p == nil || p.lane != 0 {
			t.Fatal("slow lane chosen over an empty fast lane")
		}
		s.mu.Unlock()
		p.finishAt(at, 0, 0, 0)
		s.mu.Lock()
	}
}

// After a minute without traffic a lane starts over: its first window and
// baseline hold only new samples.
func TestFetchControllerIdleLaneStartsOver(t *testing.T) {
	c := newLaneControl(32)
	at := simEpoch
	for i := range 5 {
		c.succeeded(at.Add(time.Duration(i)*time.Millisecond), 100*time.Millisecond, 1, peerView{}, 32, 512)
	}
	at = at.Add(61 * time.Second)
	closed := false
	for i := 0; !closed; i++ {
		closed = c.succeeded(at.Add(time.Duration(i)*300*time.Millisecond), 300*time.Millisecond, 1, peerView{}, 32, 512)
	}
	if c.latency < 290 || c.latency > 310 || c.reference < 290 || c.reference > 310 {
		t.Fatalf("window after idle: latency %.0f ms, reference %.0f ms", c.latency, c.reference)
	}
}
