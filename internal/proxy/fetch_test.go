package proxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

type laneSockets struct {
	addresses []string
	calls     []atomic.Int64
}

func (d *laneSockets) Dial(ctx context.Context, lane int, network string, a netip.AddrPort) (net.Conn, error) {
	d.calls[lane].Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, d.addresses[lane])
}

func fetchGateway(t testing.TB, origins []*httptest.Server, edit func(*config.Fetch)) (*Gateway, string, *http.Client) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := config.Runtime{MaxConnections: 1024, PerTunnel: 128, ConnectSeconds: 2, IdleSeconds: 2,
		Fetch: &config.Fetch{Listen: l.Addr().String(), MaxInflight: 256, MaxPending: 512, InitialPerTunnel: 16, MaxAttempts: 3, TimeoutSeconds: 3}}
	sockets := &laneSockets{calls: make([]atomic.Int64, len(origins))}
	for i, o := range origins {
		_, v, _ := net.SplitHostPort(o.Listener.Addr().String())
		p, _ := strconv.Atoi(v)
		c.Tunnels = append(c.Tunnels, config.Lane{ID: fmt.Sprintf("lane-%d", i), Ports: []uint16{uint16(p), 80, 443}})
		sockets.addresses = append(sockets.addresses, o.Listener.Addr().String())
	}
	// All fixture lanes accept each fixture port; the dialer selects the
	// lane's server so tests can inject independent lane behavior.
	for i := range c.Tunnels {
		for _, o := range origins {
			_, v, _ := net.SplitHostPort(o.Listener.Addr().String())
			p, _ := strconv.Atoi(v)
			c.Tunnels[i].Ports = append(c.Tunnels[i].Ports, uint16(p))
		}
	}
	if edit != nil {
		edit(c.Fetch)
	}
	g := New(c, sockets)
	ls := make([]net.Listener, len(origins)+1)
	ls[len(origins)] = l
	if err = g.Start(ls); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, MaxIdleConns: 256, MaxIdleConnsPerHost: 256}, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return g, "http://" + l.Addr().String() + "/fetch", client
}

func fetchCall(c *http.Client, endpoint, target string, headers map[string]string) (*http.Response, []byte, error) {
	r, _ := http.NewRequest("GET", endpoint, nil)
	r.Header.Set("Vpngate-Target", target)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, nil, err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b, err
}

func TestFetchTLSVerificationPoolingAndHTTP2(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			var connections atomic.Int64
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k := range r.Header {
					if strings.HasPrefix(strings.ToLower(k), "vpngate-") {
						t.Error("control header leaked")
					}
				}
				w.Header().Set("X-Protocol", r.Proto)
				io.WriteString(w, strings.Repeat("tls-body", 4096))
			}))
			origin.EnableHTTP2 = true
			origin.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				if s == http.StateNew {
					connections.Add(1)
				}
			}
			origin.StartTLS()
			defer origin.Close()
			g, endpoint, c := fetchGateway(t, []*httptest.Server{origin}, func(f *config.Fetch) { f.HTTP2 = &h2; f.MaxAttempts = 1 })
			resp, _, err := fetchCall(c, endpoint, origin.URL, nil)
			if err != nil || resp.StatusCode != 502 {
				t.Fatal("untrusted TLS accepted", resp, err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(origin.Certificate())
			g.fetchTransports[0].TLSClientConfig.RootCAs = pool
			before := connections.Load()
			for i := 0; i < 8; i++ {
				r, b, e := fetchCall(c, endpoint, origin.URL, map[string]string{"Vpngate-Session": "fixture"})
				if e != nil || r.StatusCode != 200 || len(b) != 32768 || r.Header.Get("Vpngate-Lane") != "lane-0" {
					t.Fatal("fetch mismatch", e)
				}
				if h2 && r.Header.Get("X-Protocol") != "HTTP/2.0" {
					t.Fatal("HTTP2 not used")
				}
			}
			if connections.Load()-before != 1 {
				t.Fatal("upstream pool not reused", connections.Load()-before)
			}
		})
	}
	// The explicit escape hatch is effective; it is not the default.
	o := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer o.Close()
	_, endpoint, c := fetchGateway(t, []*httptest.Server{o}, func(f *config.Fetch) { f.InsecureSkipVerify = true })
	r, _, e := fetchCall(c, endpoint, o.URL, nil)
	if e != nil || r.StatusCode != 200 {
		t.Fatal("explicit TLS option", e)
	}
}

func TestFetchDistributionFailureRecoveryAndHealth(t *testing.T) {
	var bad atomic.Bool
	bad.Store(true)
	origins := make([]*httptest.Server, 6)
	counts := make([]atomic.Int64, 6)
	for i := range origins {
		origins[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counts[i].Add(1)
			if i == 2 && bad.Load() {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, "same-body")
		}))
		defer origins[i].Close()
	}
	g, endpoint, c := fetchGateway(t, origins, nil)
	run := func(n int) {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, b, e := fetchCall(c, endpoint, origins[0].URL, nil)
				if e != nil || r.StatusCode != 200 || string(b) != "same-body" {
					t.Errorf("fetch failed: %v %v", r, e)
				}
			}()
		}
		wg.Wait()
	}
	run(200)
	if g.fetch.retries.Load() == 0 {
		t.Fatal("failure injection was not exercised")
	}
	for i := range counts {
		if i != 2 && counts[i].Load() == 0 {
			t.Fatal("healthy lane unused", i)
		}
	}
	bad.Store(false)
	g.fetch.mu.Lock()
	for _, r := range g.fetch.routes {
		r.lanes[2].until = time.Time{}
	}
	g.fetch.mu.Unlock()
	before := counts[2].Load()
	run(100)
	if counts[2].Load() == before {
		t.Fatal("recovered lane never probed")
	}
	if !g.fetch.setHealth([]bool{false, true, false, false, false, false}) {
		t.Fatal("health rejected")
	}
	before = counts[1].Load()
	run(100)
	if counts[1].Load() != before {
		t.Fatal("known down lane used")
	}
	if g.fetch.active != 0 {
		t.Fatal("active slots leaked")
	}
}

func TestFetchRateLimitScopePostAndStreamingFailure(t *testing.T) {
	var posts atomic.Int64
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rate":
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
		case "/post":
			posts.Add(1)
			b, _ := io.ReadAll(r.Body)
			w.WriteHeader(503)
			w.Write(b)
		case "/broken":
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, "short")
		default:
			io.WriteString(w, "ok")
		}
	}))
	defer o.Close()
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o}, nil)
	r, _, e := fetchCall(c, endpoint, o.URL+"/rate", nil)
	if e != nil || r.StatusCode != 429 {
		t.Fatal("rate response", e)
	}
	// The cooldown applies only to this origin. The fixture dialer maps both
	// loopback names to the same server, while scheduling sees distinct hosts.
	other := strings.Replace(o.URL, "127.0.0.1", "127.0.0.2", 1)
	r, _, e = fetchCall(c, endpoint, other, nil)
	if e != nil || r.StatusCode != 200 {
		t.Fatal("unrelated origin blocked", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("Vpngate-Target", o.URL)
	_, e = c.Do(req)
	if e == nil {
		t.Fatal("rate limit ignored")
	}
	payload := bytes.Repeat([]byte("upload"), 8192)
	req, _ = http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	req.Header.Set("Vpngate-Target", other+"/post")
	r, e = c.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(r.Body)
	r.Body.Close()
	if e != nil || r.StatusCode != 503 || !bytes.Equal(payload, b) || posts.Load() != 1 {
		t.Fatal("POST replayed or corrupted")
	}
	_, _, e = fetchCall(c, endpoint, other+"/broken", nil)
	if e == nil {
		t.Fatal("truncated body accepted")
	}
	if g.lanes[0].upload.Load() != uint64(len(payload)) {
		t.Fatal("upload accounting")
	}
}

func TestFetchQueueCancellationBoundsAndShutdown(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
			io.WriteString(w, "ok")
		case <-r.Context().Done():
		}
	}))
	defer o.Close()
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o}, func(f *config.Fetch) { f.MaxInflight = 1; f.MaxPending = 1 })
	done := make(chan struct{})
	go func() { defer close(done); fetchCall(c, endpoint, o.URL, nil) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	request.Header.Set("Vpngate-Target", o.URL)
	waiting := make(chan struct{})
	go func() { defer close(waiting); c.Do(request) }()
	for deadline := time.Now().Add(time.Second); ; {
		g.fetch.mu.Lock()
		n := g.fetch.queue.Len()
		g.fetch.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not queued")
		}
		time.Sleep(time.Millisecond)
	}
	r, _, e := fetchCall(c, endpoint, o.URL, nil)
	if e != nil || r.StatusCode != 503 || r.Header.Get("Vpngate-Error") != "capacity" {
		t.Fatal("queue unbounded", e)
	}
	cancel()
	<-waiting
	close(release)
	<-done
	g.Close()
	g.fetch.mu.Lock()
	defer g.fetch.mu.Unlock()
	if g.fetch.active != 0 || g.fetch.queue.Len() != 0 {
		t.Fatal("reservations leaked")
	}
}

func TestFetchForbiddenPolicySessionAndRedirect(t *testing.T) {
	var bad atomic.Bool
	bad.Store(true)
	origins := make([]*httptest.Server, 2)
	for i := range origins {
		origins[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				http.Redirect(w, r, "http://127.0.0.2/final", 302)
				return
			}
			if r.URL.Path == "/final" && r.Header.Get("Authorization") != "" {
				t.Error("cross-origin credentials leaked")
			}
			if i == 0 && bad.Load() {
				w.WriteHeader(403)
				return
			}
			io.WriteString(w, "ok")
		}))
		defer origins[i].Close()
	}
	g, endpoint, c := fetchGateway(t, origins, nil)
	key, _ := config.CanonicalOrigin(origins[0].URL)
	g.cfg.Fetch.RetryForbiddenOrigins = []string{key}
	for i := 0; i < 12; i++ {
		r, _, e := fetchCall(c, endpoint, origins[0].URL, nil)
		if e != nil || r.StatusCode != 200 {
			t.Fatal("forbidden route not replaced", e)
		}
	}
	if g.lanes[0].http403.Load() != 1 {
		t.Fatal("blocked lane not cooled down", g.lanes[0].http403.Load())
	}
	bad.Store(false)
	// Reuse a distinct origin to test sticky assignment independently of the
	// deliberately cooled route. Requests with this session keep one exit.
	var selected string
	for i := 0; i < 12; i++ {
		r, _, e := fetchCall(c, endpoint, "http://127.0.0.2/", map[string]string{"Vpngate-Session": "session-a"})
		if e != nil || r.StatusCode != 200 {
			t.Fatal(e)
		}
		if selected != "" && selected != r.Header.Get("Vpngate-Lane") {
			t.Fatal("session changed VPN")
		}
		selected = r.Header.Get("Vpngate-Lane")
	}
	r, b, e := fetchCall(c, endpoint, origins[0].URL+"/redirect", map[string]string{"Authorization": "Bearer fixture"})
	if e != nil || r.StatusCode != 200 || string(b) != "ok" {
		t.Fatal("redirect failed", e)
	}
	if r.Header.Get("Vpngate-Attempts") != "2" {
		t.Fatal("redirect attempt accounting")
	}
}

func TestFetchSchedulerFairnessAndStaleCompletion(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer o.Close()
	g, _, _ := fetchGateway(t, []*httptest.Server{o}, nil)
	s := g.fetch
	p, e := s.acquire(context.Background(), "test", 80, -1, -1)
	if e != nil {
		t.Fatal(e)
	}
	old, e := s.acquire(context.Background(), "test", 80, -1, -1)
	if e != nil {
		t.Fatal(e)
	}
	p.blockLane()
	p.finish(-1, 0, 0)
	old.finish(1, time.Millisecond, 0)
	s.mu.Lock()
	r := s.routes["test"]
	if r.lanes[0].limit != 1 || r.lanes[0].until.IsZero() {
		t.Error("old response undid cooldown")
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	blocked := make(chan error, 1)
	go func() {
		p, e := s.acquire(ctx, "test", 80, -1, -1)
		if p != nil {
			p.finish(0, 0, 0)
		}
		blocked <- e
	}()
	for i := 0; i < 20; i++ {
		p, e := s.acquire(context.Background(), "other", 80, -1, -1)
		if e != nil {
			t.Fatal(e)
		}
		p.finish(1, time.Millisecond, 0)
	}
	cancel()
	if <-blocked == nil {
		t.Fatal("cooled route dispatched")
	}
}

func TestFetchUpstreamDeadlineCountsFailure(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer o.Close()
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o}, func(f *config.Fetch) { f.MaxAttempts = 1 })
	r, _, e := fetchCall(c, endpoint, o.URL, map[string]string{"Vpngate-Timeout-Ms": "30"})
	if e != nil || r.StatusCode != 504 || g.lanes[0].failures.Load() != 1 || g.fetch.timeouts.Load() != 1 {
		t.Fatal("upstream deadline not accounted", e)
	}
}

func TestFetchDownSessionDeadlineDoesNotDispatch(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("known down lane reached") }))
	defer o.Close()
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o}, nil)
	g.fetch.setHealth([]bool{true})
	for i := 0; i < 5; i++ {
		r, _, e := fetchCall(c, endpoint, o.URL, map[string]string{"Vpngate-Session": "pinned", "Vpngate-Timeout-Ms": "20"})
		if e != nil || r.StatusCode != 504 || r.Header.Get("Vpngate-Error") != "deadline" {
			t.Fatal("queued deadline became another error", e)
		}
	}
	if g.lanes[0].requests.Load() != 0 || g.fetch.timeouts.Load() != 5 {
		t.Fatal("down lane dispatched or deadline lost")
	}
}

func TestFetchFiveHundredLanesAndBoundedOrigins(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer o.Close()
	origins := make([]*httptest.Server, 500)
	for i := range origins {
		origins[i] = o
	}
	g, endpoint, c := fetchGateway(t, origins, nil)
	for i := 0; i < maxFetchOrigins+10; i++ {
		u := strings.Replace(o.URL, "127.0.0.1", fmt.Sprintf("127.1.%d.%d", i/250, i%250+1), 1)
		r, _, e := fetchCall(c, endpoint, u, nil)
		if e != nil || r.StatusCode != 200 {
			t.Fatal("500-lane fetch", e)
		}
	}
	if len(g.fetch.routes) != maxFetchOrigins {
		t.Fatal("origin state not bounded")
	}
}

func BenchmarkFetchTLS(b *testing.B) {
	for _, verify := range []bool{true, false} {
		b.Run(fmt.Sprintf("verify=%v", verify), func(b *testing.B) {
			payload := bytes.Repeat([]byte("x"), 40<<10)
			o := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
			defer o.Close()
			g, endpoint, c := fetchGateway(b, []*httptest.Server{o}, func(f *config.Fetch) { f.InsecureSkipVerify = !verify })
			pool := x509.NewCertPool()
			pool.AddCert(o.Certificate())
			g.fetchTransports[0].TLSClientConfig.RootCAs = pool
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r, data, e := fetchCall(c, endpoint, o.URL, nil)
					if e != nil || r.StatusCode != 200 || len(data) != len(payload) {
						b.Fatal("benchmark failure", e)
					}
				}
			})
		})
	}
}
