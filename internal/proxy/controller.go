package proxy

import (
	"math"
	"slices"
	"time"
)

// laneControl is one origin's adaptive concurrency limit on one tunnel.
//
// Latency is each successful attempt's time to first byte. It is handled as
// logarithms, so a decision window's mean is a geometric mean: for the
// lognormal-like spread of real paths it estimates the median, and one slow
// answer moves it far less than it moves an arithmetic mean.
//
// The baseline is the uncongested latency. Each 5 s measurement period with
// a lower geometric mean replaces it. A higher one raises it, half-way in log
// space, only if the tunnel carried no more requests than when the baseline
// was measured. Latency that rose with load is congestion. Latency that rose
// at the same load is a slower path or origin. This lets the baseline rise
// again without drifting up under sustained congestion.
//
// A full lane grows while its latency stays below 1.5x the baseline. Two
// windows in a row at 2x or more shrink it in proportion to the inflation.
// Latency alone never takes a lane below the initial limit, except when the
// inflation lasts 8 windows and 2 s and is specific to this tunnel, judged
// against the other tunnels to the same origin. Retryable failures cut the
// limit at once and lead to the documented cooldowns.
type laneControl struct {
	limit, ssthresh float64
	inflight, peak  int
	epoch           uint64 // bumped by each cooldown; older completions are ignored

	win, period         sampleSum // the decision window and the baseline period
	base, baseLoad      float64   // baseline in ms, and the tunnel load it held at
	reference           float64   // baseline used by the last decision
	latency, ratio      float64   // last window's geometric mean (ms), and latency/reference
	decided, lastSample time.Time
	inflated            int // consecutive inflated windows
	inflatedSince       time.Time

	failures, strikes int
	lastCut, until    time.Time
	state             controlState
	stateAt           time.Time
}

type sampleSum struct {
	start     time.Time
	n         int
	sum, load float64 // sum of log milliseconds, and of tunnel requests in flight
}

type controlState uint8

const (
	stateSteady controlState = iota
	stateGrowing
	stateBackingOff
)

const (
	windowMin      = 250 * time.Millisecond // a decision window lasts at least this long,
	windowSamples  = 8                      // with at least this many successes,
	sparseWindow   = time.Second            // or this long with
	sparseSamples  = 3                      // at least this many
	periodLength   = 5 * time.Second        // baseline measurement period
	learnLength    = time.Second            // the first one, before any growth
	periodSamples  = 16
	growBelow      = 1.5 // latency/baseline under which a full lane grows
	inflatedAbove  = 2.0 // latency/baseline at which a window is inflated
	sustainWindows = 8   // inflated windows in a row, over at least
	sustainFor     = 2 * time.Second
	peerFresh      = 5 * time.Second  // a peer's window is current for this long
	idleReset      = 60 * time.Second // a lane idle this long relearns its baseline
	failureSpacing = 500 * time.Millisecond
	outlierLog     = 2.0794415416798357 // ln 8: samples count as at most 8x off the baseline
)

func newLaneControl(initial float64) laneControl {
	return laneControl{limit: initial, ssthresh: initial}
}

func (c *laneControl) allows(now time.Time) bool {
	return !now.Before(c.until) && c.inflight < int(c.limit)
}

func (c *laneControl) dispatched() {
	c.inflight++
	c.peak = max(c.peak, c.inflight)
}

func (c *laneControl) setState(s controlState, now time.Time) {
	c.state, c.stateAt = s, now
}

// succeeded records a fully read success. load is the tunnel's requests in
// flight across all origins. It reports whether a decision window closed.
func (c *laneControl) succeeded(now time.Time, ttfb time.Duration, load float64, peers peerView, initial, ceiling float64) bool {
	c.failures, c.strikes = 0, 0
	if !c.lastSample.IsZero() && now.Sub(c.lastSample) > idleReset {
		c.base, c.baseLoad, c.period, c.win, c.inflated = 0, 0, sampleSum{}, sampleSum{}, 0
	}
	c.lastSample = now
	x := math.Log(max(float64(ttfb)/float64(time.Millisecond), 0.01))
	if c.base > 0 {
		b := math.Log(c.base)
		x = min(max(x, b-outlierLog), b+outlierLog)
	}
	if c.win.n == 0 {
		c.win.start = now
	}
	c.win.n++
	c.win.sum += x
	if c.period.n == 0 {
		c.period.start = now
	}
	c.period.n++
	c.period.sum += x
	c.period.load += load
	// The first baseline is learned over one second at the initial limit.
	length := periodLength
	if c.base == 0 {
		length = learnLength
	}
	if c.period.n >= periodSamples && now.Sub(c.period.start) >= length {
		c.closePeriod()
	}
	elapsed := now.Sub(c.win.start)
	if !(c.win.n >= windowSamples && elapsed >= windowMin || c.win.n >= sparseSamples && elapsed >= sparseWindow) {
		return false
	}
	c.decide(now, peers, initial, ceiling)
	return true
}

func (c *laneControl) closePeriod() {
	latency := math.Exp(c.period.sum / float64(c.period.n))
	load := c.period.load / float64(c.period.n)
	switch {
	case c.base == 0 || latency <= c.base:
		c.base, c.baseLoad = latency, max(c.baseLoad, load)
	case latency <= c.base*1.1:
		c.baseLoad = max(c.baseLoad, load) // uncongested at this load too
	case load <= c.baseLoad*1.1:
		c.base = math.Sqrt(c.base * latency) // slower at no more load: a new path
	}
	c.period = sampleSum{}
}

func (c *laneControl) decide(now time.Time, peers peerView, initial, ceiling float64) {
	c.latency = math.Exp(c.win.sum / float64(c.win.n))
	c.reference = c.base
	if c.reference == 0 {
		// Until the first period closes, the period so far is the reference.
		c.reference = math.Exp(c.period.sum / float64(c.period.n))
	}
	c.ratio = c.latency / c.reference
	full := c.peak >= int(c.limit)
	// Below the initial limit, a lane returns to it unless inflated.
	grow := growBelow
	if c.limit < initial {
		grow = inflatedAbove
	}
	switch {
	case c.ratio >= inflatedAbove:
		if c.inflated == 0 {
			c.inflatedSince = c.win.start
		}
		c.inflated++
		if c.inflated < 2 {
			break
		}
		floor := min(c.limit, initial)
		if c.inflated >= sustainWindows && now.Sub(c.inflatedSince) >= sustainFor && peers.tunnelSpecific(c.ratio) {
			floor = 1
		}
		if next := max(floor, c.limit*(1-0.5*(1-growBelow/c.ratio))); next < c.limit {
			if c.inflated == 2 {
				c.ssthresh = max(initial, c.limit/2)
			}
			c.limit = next
			c.setState(stateBackingOff, now)
		}
	case c.ratio < grow && full && c.base > 0:
		c.inflated = 0
		if c.limit < c.ssthresh {
			c.limit = min(c.ssthresh, c.limit*2) // recovery: double back up
		} else {
			c.limit += max(1, math.Sqrt(c.limit)) * peers.scale(c.latency)
		}
		c.limit = min(c.limit, ceiling)
		c.setState(stateGrowing, now)
	default:
		c.inflated = 0
		if c.limit >= initial && c.limit < c.ssthresh && c.ratio >= growBelow {
			c.ssthresh = c.limit // recovery ends at the first latency rise
		}
	}
	c.decided = now
	c.win = sampleSum{}
	c.peak = c.inflight
}

// failed records a retryable failure: a transport error or deadline, a
// retryable 5xx, a 403 on a retry_forbidden origin, or an incomplete body.
func (c *laneControl) failed(now time.Time, initial float64) {
	c.failures++
	if now.Sub(c.lastCut) >= failureSpacing {
		c.limit = max(1, c.limit*0.8)
		c.ssthresh = c.limit
		c.lastCut = now
		c.setState(stateBackingOff, now)
	}
	if c.failures >= 3 {
		c.strikes = min(c.strikes+1, 6)
		c.cool(now, time.Duration(1<<c.strikes)*time.Second, initial)
	}
}

// cool withholds the lane for d, then allows one probation request; success
// doubles the limit back to at least the initial limit.
func (c *laneControl) cool(now time.Time, d time.Duration, initial float64) {
	c.ssthresh = max(initial, c.limit/2)
	c.limit = 1
	if until := now.Add(d); until.After(c.until) {
		c.until = until
	}
	c.epoch++
	c.failures, c.inflated = 0, 0
	c.win = sampleSum{}
	c.peak = c.inflight
	c.setState(stateBackingOff, now)
}

// score orders lanes with room for the next request: the fewest requests in
// flight, weighted up for a lane clearly slower than its peers to the origin.
// Equal lanes therefore carry equal load whatever their limits.
func (c *laneControl) score(peers peerView, now time.Time) float64 {
	w := 1.0
	if peers.n >= 2 && c.latency > 0 && now.Sub(c.decided) <= peerFresh {
		w = max(1, c.latency/(peers.latency*slowerThan))
	}
	return float64(c.inflight+1) * w
}

// A lane up to this much slower than the median of its peers counts as equal.
const slowerThan = 1.25

// peerView summarizes one origin's lanes that closed a window recently.
type peerView struct {
	n              int     // such lanes, including the one deciding
	latency, ratio float64 // their median latency (ms) and latency/baseline
}

// scale slows the growth of a lane slower than its peers, so a genuinely
// slower tunnel ends with a lower limit than the others.
func (p peerView) scale(latency float64) float64 {
	if p.n < 2 || latency <= 0 {
		return 1
	}
	return min(1, max(0.25, p.latency/latency))
}

// tunnelSpecific reports whether inflation is this tunnel's own, rather
// than the origin slowing down on every tunnel.
func (p peerView) tunnelSpecific(ratio float64) bool {
	return p.n < 2 || ratio >= 1.5*p.ratio
}

func median(v []float64) float64 {
	slices.Sort(v)
	if n := len(v); n%2 == 1 {
		return v[n/2]
	} else {
		return (v[n/2-1] + v[n/2]) / 2
	}
}

type laneSnapshot struct {
	ID         string   `json:"id"`
	Limit      float64  `json:"limit"`
	Inflight   int      `json:"inflight"`
	LatencyMS  *float64 `json:"latency_ms"`
	BaselineMS *float64 `json:"baseline_ms"`
	State      string   `json:"state"`
	CooldownMS int64    `json:"cooldown_ms"`
	UpdatedMS  int64    `json:"updated_unix_ms"` // when the last window closed; 0 for never
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func (c *laneControl) snapshot(now time.Time, id string) laneSnapshot {
	out := laneSnapshot{ID: id, Limit: round1(c.limit), Inflight: c.inflight, State: "steady"}
	if c.latency > 0 {
		v := round1(c.latency)
		out.LatencyMS = &v
	}
	if c.reference > 0 {
		v := round1(c.reference)
		out.BaselineMS = &v
	}
	if !c.decided.IsZero() {
		out.UpdatedMS = c.decided.UnixMilli()
	}
	switch {
	case now.Before(c.until):
		out.State = "cooldown"
		out.CooldownMS = c.until.Sub(now).Milliseconds()
	case now.Sub(c.stateAt) > peerFresh:
	case c.state == stateGrowing:
		out.State = "growing"
	case c.state == stateBackingOff:
		out.State = "backing_off"
	}
	return out
}
