package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/health"
)

func TestHealthSignalsDoNotTreatIdleHandshakeAsFailure(t *testing.T) {
	now := time.Now()
	up, down := true, false
	base := health.Link{SampledAt: now, NamespaceState: "present", Interface: "wg0", InterfaceUp: &up, WireGuard: &health.WireGuard{Peers: 1}}
	if h := assess(base, now, 0, 0, 0); h.State != "idle" || h.SkipRecommended {
		t.Fatal(h)
	}
	base.WireGuard.LatestHandshakeUnix = now.Unix() - 3600
	if h := assess(base, now, 0, 0, 0); h.State != "idle" || h.SkipRecommended {
		t.Fatal(h)
	}
	if h := assess(base, now, 0, now.UnixMilli()-1000, 0); h.State != "degraded" || h.SkipRecommended {
		t.Fatal(h)
	}
	if h := assess(base, now, 0, now.UnixMilli()-1000, now.UnixMilli()); h.State != "up" {
		t.Fatal(h)
	}
	base.WireGuard.LatestHandshakeUnix = now.Unix() - 50
	if h := assess(base, now, 0, 0, 0); h.State != "up" {
		t.Fatal(h)
	}
	base.InterfaceUp = &down
	if h := assess(base, now, now.UnixMilli(), 0, 0); h.State != "down" || !h.SkipRecommended {
		t.Fatal(h)
	}
	base.SampledAt = now.Add(-31 * time.Second)
	if h := assess(base, now, 0, 0, 0); h.State != "unknown" || h.SkipRecommended {
		t.Fatal("stale down status retained", h)
	}
	base.SampledAt = now
	base.InterfaceUp = &up
	base.NamespaceState = "replaced"
	if h := assess(base, now, 0, 0, 0); h.State != "down" || !h.SkipRecommended {
		t.Fatal(h)
	}
	base.NamespaceState = "present"
	base.WireGuard.Peers = 0
	if h := assess(base, now, 0, 0, 0); h.State != "down" || !h.SkipRecommended {
		t.Fatal(h)
	}
}

func TestPublicSnapshotIsAtomicAndWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	data := Observation{SchemaVersion: 1, Name: "test", Proxy: map[string]any{"large_counter": json.Number("18446744073709551615")}}
	if err := publish(path, data); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatal("snapshot not readable", info.Mode())
	}
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for n := 0; n < 100; n++ {
				bytes, err := os.ReadFile(path)
				if err != nil {
					t.Error(err)
					return
				}
				var snapshot Observation
				if err = json.Unmarshal(bytes, &snapshot); err != nil || snapshot.Name != "test" {
					t.Error("partial snapshot", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		data.WorkerPID = i
		if err := publish(path, data); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	bytes, _ := os.ReadFile(path)
	if !json.Valid(bytes) {
		t.Fatal("invalid published JSON")
	}
}

func TestPublicStatusRejectsStaleOrRecycledProcessIdentity(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "status.json")
	start, err := procStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	data := Observation{Running: true, SupervisorPID: os.Getpid(), SupervisorStartTicks: start, SampledAt: now,
		Proxy: map[string]any{"lanes": []any{map[string]any{"id": "fixture", "health": map[string]any{"state": "down", "skip_recommended": true}}}}}
	if err = publish(path, data); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readPublicStatus(path, now)
	if err != nil || snapshot.Stale || !snapshot.Running {
		t.Fatal(snapshot, err)
	}
	snapshot, err = readPublicStatus(path, now.Add(11*time.Second))
	if err != nil || !snapshot.Stale || snapshot.Running {
		t.Fatal(snapshot, err)
	}
	lane := snapshot.Proxy["lanes"].([]any)[0].(map[string]any)
	health := lane["health"].(map[string]any)
	if health["skip_recommended"] != false || health["state"] != "unknown" {
		t.Fatal(health)
	}
	data.SupervisorStartTicks = "different-generation"
	if err = publish(path, data); err != nil {
		t.Fatal(err)
	}
	snapshot, err = readPublicStatus(path, now)
	if err != nil || !snapshot.Stale || snapshot.Running {
		t.Fatal(snapshot, err)
	}
}

func TestDownloadRateUsesElapsedTimeAndWorkerIdentity(t *testing.T) {
	var s downloadSample
	now := time.Now()
	check := func(bytes uint64, at time.Time, pid int, start string, expected, interval *float64) {
		t.Helper()
		rate, seconds := s.observe(bytes, at, pid, start)
		if expected == nil {
			if rate != nil || seconds != nil {
				t.Fatal("unavailable rate must be null", rate, seconds)
			}
		} else if rate == nil || seconds == nil || *rate != *expected || *seconds != *interval {
			t.Fatalf("rate/interval: %v %v, want %v %v", rate, seconds, *expected, *interval)
		}
	}
	f := func(v float64) *float64 { return &v }
	check(1_000_000, now, 10, "a", nil, nil)
	check(6_000_000, now.Add(2500*time.Millisecond), 10, "a", f(2), f(2.5))
	check(6_000_000, now.Add(4500*time.Millisecond), 10, "a", f(0), f(2))
	check(1, now.Add(5*time.Second), 10, "a", nil, nil)         // Counter reset.
	check(1_000_001, now.Add(6*time.Second), 11, "b", nil, nil) // New worker.
	check(2_000_001, now.Add(7*time.Second), 11, "c", nil, nil) // Reused PID.
	check(3_000_001, now.Add(7*time.Second), 11, "c", nil, nil) // No elapsed interval.
	check(4_000_001, now.Add(6*time.Second), 11, "c", nil, nil) // Non-monotonic test clock.
	check(^uint64(0)-2_000_000, now.Add(8*time.Second), 12, "d", nil, nil)
	check(^uint64(0), now.Add(9*time.Second), 12, "d", f(2), f(1)) // Subtract before float conversion.
}

func TestFutureTimestampToleranceBoundaries(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "status.json")
	start, err := procStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	up := true
	for _, offset := range []time.Duration{time.Second - time.Nanosecond, time.Second, time.Second + time.Nanosecond} {
		timestamp := now.Add(offset)
		data := Observation{Running: true, SupervisorPID: os.Getpid(), SupervisorStartTicks: start, SampledAt: timestamp}
		if err = publish(path, data); err != nil {
			t.Fatal(err)
		}
		snapshot, err := readPublicStatus(path, now)
		stale := offset > time.Second
		if err != nil || snapshot.Stale != stale {
			t.Fatalf("snapshot offset=%v stale=%v error=%v", offset, snapshot.Stale, err)
		}
		h := assess(health.Link{SampledAt: timestamp, NamespaceState: "present", InterfaceUp: &up}, now, 0, 0, 0)
		if (h.Reason == "stale_kernel_sample") != stale {
			t.Fatalf("kernel offset=%v health=%+v", offset, h)
		}
	}
}
