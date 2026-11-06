package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

// Direct dialing exists only in tests. Production always requires the namespace broker.
type localSockets struct {
	calls atomic.Int64
	fail  bool
}

func (d *localSockets) Dial(ctx context.Context, lane int, network string, a netip.AddrPort) (net.Conn, error) {
	d.calls.Add(1)
	if d.fail {
		return nil, fmt.Errorf("fixture failure")
	}
	if !a.Addr().IsLoopback() {
		return nil, fmt.Errorf("fixture refuses external traffic")
	}
	return (&net.Dialer{}).DialContext(ctx, network, a.String())
}
func port(t *testing.T, address string) uint16 {
	t.Helper()
	_, p, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	n, _ := strconv.Atoi(p)
	return uint16(n)
}
func gateway(t *testing.T, sockets SocketDialer, ports []uint16, edit func(*config.Runtime)) (*Gateway, *url.URL) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	c := config.Runtime{RelayMode: "buffered", MaxConnections: 32, PerTunnel: 16, ConnectSeconds: 2, IdleSeconds: 2,
		Tunnels: []config.Lane{{ID: "fixture", DNS: []string{"192.0.2.53"}, Ports: ports}}}
	if edit != nil {
		edit(&c)
	}
	g := New(c, sockets)
	if e = g.Start([]net.Listener{l}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(g.Close)
	u, _ := url.Parse("http://" + l.Addr().String())
	return g, u
}
func client(u *url.URL) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 3 * time.Second}
}
func closeClient(c *http.Client) { c.CloseIdleConnections() }

func TestListenerFailureIsReportedButShutdownIsQuiet(t *testing.T) {
	g, _ := gateway(t, &localSockets{}, []uint16{80}, nil)
	if err := g.listeners[0].Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-g.Errors():
		if err == nil {
			t.Fatal("listener failure lost its error")
		}
	case <-time.After(time.Second):
		t.Fatal("listener failed silently")
	}
	g.Close()
	clean, _ := gateway(t, &localSockets{}, []uint16{80}, nil)
	clean.Close()
	select {
	case err := <-clean.Errors():
		t.Fatal("ordinary shutdown reported as failure", err)
	default:
	}
}

func TestHTTPStreamingAuthenticationAndConnectionReuse(t *testing.T) {
	var upstreamConns atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Proxy-Connection") != "" {
			t.Error("proxy credentials leaked")
		}
		w.Header().Set("X-Fixture", "ok")
		w.Header().Set("Trailer", "X-Complete")
		io.Copy(w, r.Body)
		w.Header().Set("X-Complete", "yes")
	}))
	origin.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			upstreamConns.Add(1)
		}
	}
	origin.Start()
	defer origin.Close()
	sockets := &localSockets{}
	_, u := gateway(t, sockets, []uint16{port(t, origin.Listener.Addr().String())}, func(c *config.Runtime) { c.Username = "test"; c.Password = "secret" })
	noauth := client(u)
	defer closeClient(noauth)
	r, e := noauth.Get(origin.URL)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 407 || sockets.calls.Load() != 0 {
		t.Fatal("unauthenticated request reached upstream")
	}
	u.User = url.UserPassword("test", "secret")
	c := client(u)
	defer closeClient(c)
	payload := strings.Repeat("abc", 8192)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", origin.URL+"/stream", io.NopCloser(strings.NewReader(payload)))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != payload || resp.Trailer.Get("X-Complete") != "yes" {
			t.Fatalf("stream/trailer mismatch: bytes=%d/%d trailer=%q error=%v", len(body), len(payload), resp.Trailer.Get("X-Complete"), err)
		}
	}
	if upstreamConns.Load() != 1 {
		t.Fatalf("upstream keepalive not reused: %d", upstreamConns.Load())
	}
}

func TestCONNECTPreservesBufferedBytesAndHalfClose(t *testing.T) {
	origin, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	done := make(chan error, 1)
	go func() {
		c, e := origin.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b, e := io.ReadAll(c)
		if e == nil {
			_, e = c.Write(append([]byte("got:"), b...))
		}
		done <- e
	}()
	_, u := gateway(t, &localSockets{}, []uint16{port(t, origin.Addr().String())}, nil)
	conn, e := net.Dial("tcp", u.Host)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nearly-payload", origin.Addr(), origin.Addr())
	r := bufio.NewReader(conn)
	line, e := r.ReadString('\n')
	if e != nil || !strings.Contains(line, "200") {
		t.Fatal(line, e)
	}
	for {
		line, e = r.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	conn.(*net.TCPConn).CloseWrite()
	body, e := io.ReadAll(r)
	if e != nil || string(body) != "got:early-payload" {
		t.Fatalf("buffered bytes/half-close: %q %v", body, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestHTTPSAndHTTP2RemainEndToEnd(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Protocol", r.Proto)
		io.WriteString(w, "encrypted-through-gateway")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	_, u := gateway(t, &localSockets{}, []uint16{port(t, origin.Listener.Addr().String())}, nil)
	pool := origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tr := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	defer closeClient(c)
	for i := 0; i < 3; i++ {
		r, e := c.Get(origin.URL)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(r.Body)
		r.Body.Close()
		if e != nil || string(b) != "encrypted-through-gateway" || r.ProtoMajor != 2 {
			t.Fatalf("TLS/H2 mismatch: %s %v", r.Proto, e)
		}
	}
}

func TestLiveBandwidthChangeReleasesBlockedDownload(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 8192)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer origin.Close()
	g, u := gateway(t, &localSockets{}, []uint16{port(t, origin.Listener.Addr().String())}, func(c *config.Runtime) { c.DownloadMBPS = .001 })
	c := client(u)
	defer closeClient(c)
	done := make(chan error, 1)
	go func() {
		r, e := c.Get(origin.URL)
		if e != nil {
			done <- e
			return
		}
		b, e := io.ReadAll(r.Body)
		r.Body.Close()
		if !bytes.Equal(b, payload) {
			e = fmt.Errorf("payload mismatch")
		}
		done <- e
	}()
	select {
	case e := <-done:
		t.Fatal("download did not wait for budget", e)
	case <-time.After(80 * time.Millisecond):
	}
	g.limiter.Set(0)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("disabling cap did not wake stream")
	}
}

func TestFailedLaneDoesNotUseHostFallback(t *testing.T) {
	var reached atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer origin.Close()
	g, u := gateway(t, &localSockets{fail: true}, []uint16{port(t, origin.Listener.Addr().String())}, nil)
	c := client(u)
	defer closeClient(c)
	r, e := c.Get(origin.URL)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 502 || reached.Load() != 0 || g.lanes[0].failures.Load() != 1 {
		t.Fatal("failed lane escaped to host")
	}
}

func TestShutdownClosesActiveTunnelAndReleasesSlots(t *testing.T) {
	origin, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := origin.Accept(); accepted <- c }()
	g, u := gateway(t, &localSockets{}, []uint16{port(t, origin.Addr().String())}, nil)
	c, e := net.Dial("tcp", u.Host)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Addr(), origin.Addr())
	c.SetDeadline(time.Now().Add(time.Second))
	r := bufio.NewReader(c)
	for {
		line, e := r.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	up := <-accepted
	defer up.Close()
	stopped := make(chan struct{})
	go func() { g.Close(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown hung on CONNECT")
	}
	if len(g.slots) != 0 || g.lanes[0].active.Load() != 0 {
		t.Fatal("slots leaked after shutdown")
	}
}

func TestFiveHundredListenersDoNotReserveActiveSlots(t *testing.T) {
	if testing.Short() {
		t.Skip("500 local listeners")
	}
	c := config.Runtime{RelayMode: "buffered", MaxConnections: 8, PerTunnel: 8, ConnectSeconds: 1, IdleSeconds: 1}
	var listeners []net.Listener
	for i := 0; i < 500; i++ {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			for _, v := range listeners {
				v.Close()
			}
			t.Fatal(e)
		}
		listeners = append(listeners, l)
		c.Tunnels = append(c.Tunnels, config.Lane{ID: fmt.Sprintf("lane-%d", i), Ports: []uint16{443}})
	}
	g := New(c, &localSockets{})
	if e := g.Start(listeners); e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	if len(g.slots) != 0 {
		t.Fatal("idle listeners reserved active connection budget")
	}
	cli := client(&url.URL{Scheme: "http", Host: listeners[499].Addr().String()})
	defer closeClient(cli)
	r, e := cli.Get("http://127.0.0.1:1/")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("last of 500 endpoints is not serving")
	}
}

func TestStatusPreservesConfiguredLaneOrderAndListeners(t *testing.T) {
	cfg := config.Runtime{MaxConnections: 8, PerTunnel: 4, Tunnels: []config.Lane{
		{ID: "z-last", Listen: "127.0.0.1:15423"},
		{ID: "a-first", Listen: "[::1]:15411"},
	}}
	g := New(cfg, &localSockets{})
	defer g.Close()
	status := g.Status().(map[string]any)
	lanes := status["lanes"].([]map[string]any)
	if len(lanes) != len(cfg.Tunnels) {
		t.Fatal("lane count changed")
	}
	for i, lane := range lanes {
		if lane["id"] != cfg.Tunnels[i].ID || lane["listen"] != cfg.Tunnels[i].Listen {
			t.Fatalf("lane %d: %v", i, lane)
		}
	}
}
