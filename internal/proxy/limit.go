package proxy

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

// Limiter is an optional aggregate download token bucket. Unlimited mode performs
// one atomic load per chunk, with no mutex, allocation or timer.
type Limiter struct {
	bits    atomic.Uint64
	mu      sync.Mutex
	tokens  float64
	at      time.Time
	changed chan struct{}
}

func NewLimiter(mbps float64) *Limiter {
	l := &Limiter{changed: make(chan struct{})}
	l.Set(mbps)
	return l
}
func (l *Limiter) Rate() float64 { return math.Float64frombits(l.bits.Load()) }
func (l *Limiter) Set(mbps float64) bool {
	if !config.ValidRate(mbps) {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if mbps == 0 {
		mbps = 0
	} // Normalize negative zero for the lock-free unlimited branch.
	l.bits.Store(math.Float64bits(mbps))
	l.tokens = 0
	l.at = time.Now()
	close(l.changed)
	l.changed = make(chan struct{})
	return true
}
func (l *Limiter) Wait(ctx context.Context, n int) error {
	if l.bits.Load() == 0 {
		return nil
	}
	for {
		l.mu.Lock()
		rate := l.Rate() * 1e6
		if rate == 0 {
			l.mu.Unlock()
			return nil
		}
		now := time.Now()
		capacity := math.Max(float64(n), math.Min(rate*0.05, 1<<20))
		l.tokens = math.Min(capacity, l.tokens+now.Sub(l.at).Seconds()*rate)
		l.at = now
		if l.tokens >= float64(n) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((float64(n) - l.tokens) / rate * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		changed := l.changed
		l.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}
