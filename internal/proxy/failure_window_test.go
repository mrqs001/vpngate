package proxy

import (
	"sync"
	"testing"
)

func TestRecentFailureWindowExpiresAndHandlesConcurrency(t *testing.T) {
	var w failureWindow
	w.add(100)
	w.add(101)
	var group sync.WaitGroup
	for i := 0; i < 10; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 100; j++ {
				w.add(159)
			}
		}()
	}
	group.Wait()
	if got := w.count(159); got != 1002 {
		t.Fatal(got)
	}
	if got := w.count(160); got != 1001 {
		t.Fatal(got)
	}
	if got := w.count(161); got != 1000 {
		t.Fatal(got)
	}
	if got := w.count(219); got != 0 {
		t.Fatal(got)
	}
	if got := w.count(99); got != 0 {
		t.Fatal("future failures counted after clock change", got)
	}
	w.add(220)
	if got := w.count(220); got != 1 {
		t.Fatal(got)
	}
}
