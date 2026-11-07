package proxy

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

// tunnelModel is one lane of the local load model: an origin that waits a
// lognormal time before answering, then sends the body through a FIFO link of
// fixed capacity. Concurrency beyond the link's capacity queues on the link and
// inflates that lane's time to first byte, as a saturated VPN path does.
type tunnelModel struct {
	median time.Duration
	sigma  float64 // log-space standard deviation; 0.7 gives p95/p50 of about 3.2
	mbps   float64 // link capacity, decimal MB/s; 0 is unlimited
	mu     sync.Mutex
	free   time.Time
}

func (m *tunnelModel) handler(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wait := func(d time.Duration) bool {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return true
			case <-r.Context().Done():
				return false
			}
		}
		if !wait(time.Duration(float64(m.median) * math.Exp(m.sigma*rand.NormFloat64()))) {
			return
		}
		if m.mbps > 0 {
			// Reserve the link only once the answer is ready: a FIFO in
			// transmission order, not in arrival order.
			now := time.Now()
			m.mu.Lock()
			start := now
			if m.free.After(start) {
				start = m.free
			}
			m.free = start.Add(time.Duration(float64(len(body)) / (m.mbps * 1e6) * float64(time.Second)))
			done := m.free
			m.mu.Unlock()
			if !wait(done.Sub(now)) {
				return
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
}

type loadScenario struct {
	name     string
	lanes    []*tunnelModel
	inflight int
}

type loadResult struct {
	at      time.Duration // completion time since the measured window started
	latency time.Duration
	lane    string
	bytes   int
	ok      bool
}

func loadSeconds(name string, fallback int) time.Duration {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(fallback) * time.Second
}

func processCPU() time.Duration {
	var u syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &u)
	return time.Duration(u.Utime.Nano() + u.Stime.Nano())
}

// BenchmarkFetchSchedulerLoad is a closed-loop load model of a crawler
// keeping a fixed number of requests in flight through the fetch endpoint,
// with no internet or root. Run with:
//
//	GOMAXPROCS=4 go test ./internal/proxy -run '^$' -bench '^BenchmarkFetchSchedulerLoad$' -benchtime=1x -v
//
// VPNGATE_LOAD_WARMUP_SECONDS (default 10) and VPNGATE_LOAD_SECONDS (default
// 60) set the warm-up and measured durations. The client, gateway and model
// origins share one process; CPU per GB is only for relative comparisons.
func BenchmarkFetchSchedulerLoad(b *testing.B) {
	body := []byte(strings.Repeat("z", 40<<10))
	lognormal := func(ms ...int) []*tunnelModel {
		var out []*tunnelModel
		for _, v := range ms {
			out = append(out, &tunnelModel{median: time.Duration(v) * time.Millisecond, sigma: 0.7, mbps: 40})
		}
		return out
	}
	slow := lognormal(140, 150, 160, 170, 180, 150)
	slow[5].median = 600 * time.Millisecond
	tight := lognormal(150, 150, 150, 150, 150, 150)
	for _, m := range tight {
		m.mbps = 12
	}
	scenarios := []loadScenario{
		{name: "noise", lanes: lognormal(140, 150, 160, 170, 180, 190), inflight: 500},
		{name: "slow-lane", lanes: slow, inflight: 500},
		{name: "capacity", lanes: tight, inflight: 500},
	}
	warmup := loadSeconds("VPNGATE_LOAD_WARMUP_SECONDS", 10)
	measure := loadSeconds("VPNGATE_LOAD_SECONDS", 60)
	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			for range b.N {
				runLoadScenario(b, sc, body, warmup, measure)
			}
		})
	}
}

func runLoadScenario(b *testing.B, sc loadScenario, body []byte, warmup, measure time.Duration) {
	origins := make([]*httptest.Server, len(sc.lanes))
	for i, m := range sc.lanes {
		origins[i] = httptest.NewServer(m.handler(body))
		origins[i].Config.ErrorLog = discardLogger()
		defer origins[i].Close()
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	// The settings of a production deployment with six tunnels.
	c := config.Runtime{MaxConnections: 4096, PerTunnel: 512, ConnectSeconds: 10, IdleSeconds: 600,
		Fetch: &config.Fetch{Listen: l.Addr().String(), MaxInflight: 512, MaxPending: 4096, InitialPerTunnel: 32, MaxAttempts: 3, TimeoutSeconds: 30}}
	sockets := &laneSockets{calls: make([]atomic.Int64, len(origins))}
	for i, o := range origins {
		c.Tunnels = append(c.Tunnels, config.Lane{ID: fmt.Sprintf("lane-%d", i), Ports: []uint16{80, 443}})
		sockets.addresses = append(sockets.addresses, o.Listener.Addr().String())
	}
	g := New(c, sockets)
	ls := make([]net.Listener, len(origins)+1)
	ls[len(origins)] = l
	if err = g.Start(ls); err != nil {
		b.Fatal(err)
	}
	defer g.Close()
	endpoint := "http://" + l.Addr().String() + "/fetch"
	client := &http.Client{Transport: &http.Transport{Proxy: nil, MaxIdleConns: sc.inflight * 2, MaxIdleConnsPerHost: sc.inflight * 2}, Timeout: 40 * time.Second}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), warmup+measure)
	defer cancel()
	begin := time.Now().Add(warmup)
	results := make([][]loadResult, sc.inflight)
	var wg sync.WaitGroup
	var cpuStart time.Duration
	cpuOnce := time.AfterFunc(warmup, func() { cpuStart = processCPU() })
	defer cpuOnce.Stop()
	for worker := range sc.inflight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Port 80 of a fixed literal: the fixture dialer sends lane i to origin i.
			target := "http://192.0.2.10/tile?w=" + strconv.Itoa(worker)
			for ctx.Err() == nil {
				start := time.Now()
				r, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
				r.Header.Set("Vpngate-Target", target)
				resp, err := client.Do(r)
				n := 0
				ok := false
				lane := ""
				if err == nil {
					m, e := io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					n = int(m)
					ok = e == nil && resp.StatusCode == 200 && n == len(body)
					lane = resp.Header.Get("Vpngate-Lane")
				}
				end := time.Now()
				if start.Before(begin) || ctx.Err() != nil {
					continue
				}
				results[worker] = append(results[worker], loadResult{at: end.Sub(begin), latency: end.Sub(start), lane: lane, bytes: n, ok: ok})
			}
		}()
	}
	wg.Wait()
	cpu := processCPU() - cpuStart
	var all []loadResult
	for _, r := range results {
		all = append(all, r...)
	}
	reportLoad(b, sc, all, measure, cpu)
}

func reportLoad(b *testing.B, sc loadScenario, all []loadResult, measure time.Duration, cpu time.Duration) {
	var bytes, failed int
	var latencies []float64
	share := map[string]int{}
	const buckets = 6
	type bucket struct {
		bytes int
		lanes map[string]int
	}
	windows := make([]bucket, buckets)
	for i := range windows {
		windows[i].lanes = map[string]int{}
	}
	for _, r := range all {
		if !r.ok {
			failed++
			continue
		}
		bytes += r.bytes
		latencies = append(latencies, float64(r.latency)/float64(time.Millisecond))
		share[r.lane]++
		w := min(buckets-1, int(r.at*buckets/measure))
		windows[w].bytes += r.bytes
		windows[w].lanes[r.lane]++
	}
	slices.Sort(latencies)
	q := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		return latencies[min(len(latencies)-1, int(p*float64(len(latencies))))]
	}
	seconds := measure.Seconds()
	gb := float64(bytes) / 1e9
	b.ReportMetric(float64(bytes)/seconds/1e6, "MB/s")
	b.ReportMetric(float64(len(latencies))/seconds, "req/s")
	b.ReportMetric(q(0.5), "p50-ms")
	b.ReportMetric(q(0.95), "p95-ms")
	b.ReportMetric(float64(failed), "errors")
	if gb > 0 {
		b.ReportMetric(cpu.Seconds()/gb, "cpu-s/GB")
	}
	ids := make([]string, len(sc.lanes))
	for i := range ids {
		ids[i] = fmt.Sprintf("lane-%d", i)
	}
	line := func(counts map[string]int) string {
		total := 0
		for _, n := range counts {
			total += n
		}
		var parts []string
		for _, id := range ids {
			parts = append(parts, fmt.Sprintf("%s %4.1f%%", id, 100*float64(counts[id])/math.Max(1, float64(total))))
		}
		return strings.Join(parts, "  ")
	}
	b.Logf("%s: %.1f MB/s, %.0f req/s, p50 %.0f ms, p95 %.0f ms, %d errors; shares %s",
		sc.name, float64(bytes)/seconds/1e6, float64(len(latencies))/seconds, q(0.5), q(0.95), failed, line(share))
	for i, w := range windows {
		b.Logf("  window %d: %6.1f MB/s  %s", i, float64(w.bytes)/(seconds/buckets)/1e6, line(w.lanes))
	}
}
