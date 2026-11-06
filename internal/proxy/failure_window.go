package proxy

import "sync"

// Only failed setup/HTTP transport attempts take this lock. The forwarding and
// successful-connect paths are unchanged. One-second buckets bound memory.
type failureWindow struct {
	mu      sync.Mutex
	buckets [60]struct {
		second int64
		count  uint64
	}
}

func (w *failureWindow) add(second int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	b := &w.buckets[second%60]
	if b.second != second {
		b.second = second
		b.count = 0
	}
	b.count++
}
func (w *failureWindow) count(now int64) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var n uint64
	for _, b := range w.buckets {
		if b.second <= now && now-b.second < 60 {
			n += b.count
		}
	}
	return n
}
