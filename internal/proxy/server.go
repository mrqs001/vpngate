package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

type laneState struct {
	ID              string
	active          atomic.Int64
	requests        atomic.Uint64
	failures        atomic.Uint64
	rejected        atomic.Uint64
	dialFailures    atomic.Uint64
	dnsFailures     atomic.Uint64
	connectFailures atomic.Uint64
	relayFailures   atomic.Uint64
	http5xx         atomic.Uint64
	http403         atomic.Uint64
	http429         atomic.Uint64
	peak            atomic.Int64
	download        atomic.Uint64
	upload          atomic.Uint64
	lastSuccess     atomic.Int64
	lastFailure     atomic.Int64
	recentFailures  failureWindow
	slots           chan struct{}
}

type Gateway struct {
	cfg                config.Runtime
	limiter            *Limiter
	resolver           *Resolver
	slots              chan struct{}
	lanes              []*laneState
	servers            []*http.Server
	transports         []*http.Transport
	fetchTransports    []*http.Transport
	fetch              *fetchScheduler
	listeners          []net.Listener
	mu                 sync.Mutex
	connections        map[net.Conn]struct{}
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	handlers           sync.WaitGroup
	closing            bool
	rejected           atomic.Uint64
	peak               atomic.Int64
	spliceDirections   atomic.Uint64
	bufferedDirections atomic.Uint64
	serveErrors        chan error
}

func New(cfg config.Runtime, sockets SocketDialer) *Gateway {
	ctx, cancel := context.WithCancel(context.Background())
	g := &Gateway{cfg: cfg, limiter: NewLimiter(cfg.DownloadMBPS), resolver: NewResolver(sockets),
		slots: make(chan struct{}, cfg.MaxConnections), connections: map[net.Conn]struct{}{}, ctx: ctx, cancel: cancel, serveErrors: make(chan error, 1)}
	for _, c := range cfg.Tunnels {
		g.lanes = append(g.lanes, &laneState{ID: c.ID, slots: make(chan struct{}, cfg.PerTunnel)})
	}
	return g
}

// Start accepts prebound listeners so setup is all-or-nothing, even with 500 lanes.
func (g *Gateway) Start(listeners []net.Listener) error {
	expected := len(g.cfg.Tunnels)
	if g.cfg.Fetch != nil {
		expected++
	}
	if len(listeners) != expected {
		return errors.New("listener/lane count mismatch")
	}
	g.listeners = listeners
	for i, c := range g.cfg.Tunnels {
		if listeners[i] == nil {
			continue
		}
		dial := g.resolver.DialContext(i, c, time.Duration(g.cfg.ConnectSeconds)*time.Second)
		tr := &http.Transport{Proxy: nil, DialContext: dial, DisableCompression: true,
			MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxConnsPerHost: g.cfg.PerTunnel,
			IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: time.Duration(g.cfg.ConnectSeconds) * time.Second,
			ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 64 << 10}
		g.transports = append(g.transports, tr)
		reverse := &httputil.ReverseProxy{
			Transport: tr, FlushInterval: -1, BufferPool: buffers,
			Rewrite: func(p *httputil.ProxyRequest) {
				p.Out.URL.Scheme = "http"
				p.Out.URL.Host = p.In.URL.Host
				p.Out.Host = p.In.URL.Host
				p.Out.Header.Del("Proxy-Authorization")
				p.Out.Header.Del("Proxy-Connection")
			},
			ModifyResponse: func(r *http.Response) error {
				if r.StatusCode >= 500 {
					g.lanes[i].http5xx.Add(1)
				}
				if r.StatusCode == http.StatusSwitchingProtocols {
					// CONNECT carries WebSockets; plaintext HTTP upgrades need a separate accounting path.
					r.Body.Close()
					return errors.New("use CONNECT for protocol upgrades")
				}
				r.Body = &countedBody{ReadCloser: r.Body, ctx: r.Request.Context(), limiter: g.limiter, bytes: &g.lanes[i].download}
				g.lanes[i].lastSuccess.Store(time.Now().UnixNano())
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
				g.lanes[i].dialFailures.Add(1)
				g.failure(i)
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
			},
			ErrorLog: discardLogger(),
		}
		handler := g.handler(i, c, dial, reverse)
		s := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout: time.Duration(g.cfg.IdleSeconds) * time.Second, MaxHeaderBytes: 32 << 10,
			BaseContext: func(net.Listener) context.Context { return g.ctx }, ErrorLog: discardLogger(),
			ConnState: func(conn net.Conn, state http.ConnState) {
				g.mu.Lock()
				defer g.mu.Unlock()
				switch state {
				case http.StateNew:
					g.connections[conn] = struct{}{}
				case http.StateClosed:
					delete(g.connections, conn)
				}
			},
		}
		g.servers = append(g.servers, s)
		g.wg.Add(1)
		go func(s *http.Server, l net.Listener) {
			defer g.wg.Done()
			err := s.Serve(&limitedListener{Listener: l, slots: g.slots, ctx: g.ctx, rejected: &g.rejected, peak: &g.peak})
			if g.ctx.Err() == nil {
				select {
				case g.serveErrors <- err:
				default:
				}
			}
		}(s, listeners[i])
	}
	if g.cfg.Fetch != nil {
		return g.startFetch(listeners[len(g.cfg.Tunnels)])
	}
	return nil
}

// Errors reports a stopped listener so the supervisor can restart the service
// instead of leaving one endpoint silently unavailable. Normal shutdown is quiet.
func (g *Gateway) Errors() <-chan error { return g.serveErrors }

func (g *Gateway) handler(i int, c config.Lane, dial func(context.Context, string, string) (net.Conn, error), reverse http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		if g.closing {
			g.mu.Unlock()
			http.Error(w, "gateway stopping", 503)
			return
		}
		g.handlers.Add(1)
		g.mu.Unlock()
		defer g.handlers.Done()
		if !g.authorized(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="vpngate"`)
			http.Error(w, "proxy authentication required", 407)
			return
		}
		var target string
		if r.Method == http.MethodConnect {
			target = r.Host
			if r.URL.User != nil {
				http.Error(w, "invalid target", 400)
				return
			}
		} else {
			if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil || r.URL.Fragment != "" {
				http.Error(w, "use an absolute http URL or CONNECT", 400)
				return
			}
			target = r.URL.Host
			if r.URL.Port() == "" {
				target = net.JoinHostPort(r.URL.Hostname(), "80")
			}
		}
		_, port, err := net.SplitHostPort(target)
		p, e := strconv.ParseUint(port, 10, 16)
		allowed := false
		for _, v := range c.Ports {
			if uint16(p) == v && p != 0 {
				allowed = true
			}
		}
		if err != nil || e != nil || !allowed {
			http.Error(w, "destination port is not allowed", 403)
			return
		}
		select {
		case g.lanes[i].slots <- struct{}{}:
		default:
			g.lanes[i].rejected.Add(1)
			http.Error(w, "lane connection limit reached", 503)
			return
		}
		defer func() { <-g.lanes[i].slots }()
		recordPeak(&g.lanes[i].peak, g.lanes[i].active.Add(1))
		defer g.lanes[i].active.Add(-1)
		g.lanes[i].requests.Add(1)
		if r.Method == http.MethodConnect {
			g.connect(w, r, i, target, dial)
			return
		}
		r.Header.Del("Proxy-Authorization")
		_ = http.NewResponseController(w).EnableFullDuplex()
		if r.Body != nil {
			r.Body = &countedBody{ReadCloser: r.Body, ctx: r.Context(), bytes: &g.lanes[i].upload}
		}
		reverse.ServeHTTP(w, r)
	})
}

func (g *Gateway) authorized(r *http.Request) bool {
	if g.cfg.Username == "" {
		return true
	}
	scheme, value, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	return ok && subtle.ConstantTimeCompare([]byte(user), []byte(g.cfg.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(g.cfg.Password)) == 1
}

func (g *Gateway) failure(i int) {
	now := time.Now()
	g.lanes[i].failures.Add(1)
	g.lanes[i].lastFailure.Store(now.UnixNano())
	g.lanes[i].recentFailures.add(now.Unix())
}

func (g *Gateway) connect(w http.ResponseWriter, r *http.Request, i int, target string, dial func(context.Context, string, string) (net.Conn, error)) {
	upstream, err := dial(r.Context(), "tcp", target)
	if err != nil {
		g.lanes[i].dialFailures.Add(1)
		if errors.Is(err, errLaneDNS) {
			g.lanes[i].dnsFailures.Add(1)
		} else {
			g.lanes[i].connectFailures.Add(1)
		}
		g.failure(i)
		http.Error(w, "tunnel unavailable", 502)
		return
	}
	defer upstream.Close()
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT requires HTTP/1", 505)
		return
	}
	client, rw, err := h.Hijack()
	if err != nil {
		return
	}
	defer func() { client.Close(); g.mu.Lock(); delete(g.connections, client); g.mu.Unlock() }()
	client.SetWriteDeadline(time.Now().Add(time.Duration(g.cfg.ConnectSeconds) * time.Second))
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if rw.Flush() != nil {
		return
	}
	client.SetWriteDeadline(time.Time{})
	g.lanes[i].lastSuccess.Store(time.Now().UnixNano())
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	idle := time.Duration(g.cfg.IdleSeconds) * time.Second
	var activity relayActivity
	activity.touch()
	done := make(chan error, 2)
	go func() {
		// Hijack can leave bytes read with the CONNECT headers in this reader.
		// Drain exactly those bytes before switching to the underlying socket.
		var err error
		if n := rw.Reader.Buffered(); n > 0 {
			err = g.copy(ctx, upstream, io.LimitReader(rw.Reader, int64(n)), false, &g.lanes[i].upload, &activity)
		}
		if err == nil {
			err = g.relay(ctx, upstream, client, false, &g.lanes[i].upload, &activity)
		}
		closeWrite(upstream)
		done <- err
	}()
	go func() {
		err := g.relay(ctx, client, upstream, true, &g.lanes[i].download, &activity)
		closeWrite(client)
		done <- err
	}()
	tick := time.NewTicker(min(idle, time.Second))
	defer tick.Stop()
	completed := 0
	cancelled := ctx.Done()
	for completed < 2 {
		select {
		case err := <-done:
			completed++
			if err != nil {
				if ctx.Err() == nil {
					g.lanes[i].relayFailures.Add(1)
				}
				cancel()
				client.Close()
				upstream.Close()
			}
		case <-cancelled:
			client.Close()
			upstream.Close()
			cancelled = nil
		case <-tick.C:
			if activity.throttled.Load() == 0 && time.Since(time.Unix(0, activity.last.Load())) >= idle {
				cancel()
				client.Close()
				upstream.Close()
			}
		}
	}
}

type relayActivity struct {
	last      atomic.Int64
	throttled atomic.Int32
}

func (a *relayActivity) touch() { a.last.Store(time.Now().UnixNano()) }

func (g *Gateway) waitDownload(ctx context.Context, n int, activity *relayActivity) error {
	if g.limiter.bits.Load() == 0 {
		return nil
	}
	activity.throttled.Add(1)
	err := g.limiter.Wait(ctx, n)
	activity.touch()
	activity.throttled.Add(-1)
	return err
}

func (g *Gateway) relay(ctx context.Context, dst, src net.Conn, download bool, total *atomic.Uint64, activity *relayActivity) error {
	// Requests are usually small; reserving a second pipe for that direction
	// wastes kernel pipe pages and pushes busy gateways into the per-user pipe
	// soft limit. Downloads use splice, uploads use a small reusable buffer.
	if download && g.cfg.RelayMode != "buffered" {
		if handled, err := g.spliceRelay(ctx, dst, src, download, total, activity); handled {
			return err
		}
	}
	g.bufferedDirections.Add(1)
	return g.copy(ctx, dst, src, download, total, activity)
}

func (g *Gateway) copy(ctx context.Context, dst io.Writer, src io.Reader, download bool, total *atomic.Uint64, activity *relayActivity) error {
	pool := buffers
	if download {
		pool = relayBuffers
	}
	b := pool.Get()
	defer pool.Put(b)
	for {
		n, err := src.Read(b)
		if n > 0 {
			activity.touch()
			if download {
				if err := g.waitDownload(ctx, n, activity); err != nil {
					return err
				}
			}
			m, e := dst.Write(b[:n])
			total.Add(uint64(m))
			activity.touch()
			if e != nil || m != n {
				if e != nil {
					return e
				}
				return io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
func closeWrite(c net.Conn) {
	if t, ok := c.(interface{ CloseWrite() error }); ok {
		_ = t.CloseWrite()
	}
}

func (g *Gateway) Close() {
	g.mu.Lock()
	g.closing = true
	g.mu.Unlock()
	g.cancel()
	g.resolver.Close()
	for _, s := range g.servers {
		_ = s.Close()
	}
	g.mu.Lock()
	for c := range g.connections {
		_ = c.Close()
	}
	g.mu.Unlock()
	for _, t := range g.transports {
		t.CloseIdleConnections()
	}
	for _, t := range g.fetchTransports {
		t.CloseIdleConnections()
	}
	g.wg.Wait()
	g.handlers.Wait()
}

func (g *Gateway) Status() any {
	now := time.Now()
	lanes := make([]map[string]any, 0, len(g.lanes))
	for i, s := range g.lanes {
		state := "idle"
		if s.lastSuccess.Load() > 0 {
			state = "ready"
		}
		if s.lastFailure.Load() > s.lastSuccess.Load() {
			state = "degraded"
		}
		lanes = append(lanes, map[string]any{"id": s.ID, "listen": g.cfg.Tunnels[i].Listen, "state": state, "active": s.active.Load(), "requests": s.requests.Load(),
			"last_success_unix_ms": s.lastSuccess.Load() / int64(time.Millisecond),
			"last_failure_unix_ms": s.lastFailure.Load() / int64(time.Millisecond),
			"recent_failures_60s":  s.recentFailures.count(now.Unix()),
			"failures":             s.failures.Load(), "download_bytes": s.download.Load(), "upload_bytes": s.upload.Load(),
			"rejected_lane": s.rejected.Load(), "dial_or_http_transport_failures": s.dialFailures.Load(),
			"dns_failures": s.dnsFailures.Load(), "connect_failures": s.connectFailures.Load(),
			"relay_errors": s.relayFailures.Load(), "upstream_http_5xx": s.http5xx.Load(), "upstream_http_403": s.http403.Load(), "upstream_http_429": s.http429.Load(), "peak_active": s.peak.Load()})
	}
	out := map[string]any{"download_mbps": g.limiter.Rate(), "connections": len(g.slots), "lanes": lanes,
		"relay_mode":      g.cfg.RelayMode,
		"max_connections": g.cfg.MaxConnections, "per_tunnel_connections": g.cfg.PerTunnel,
		"rejected_global": g.rejected.Load(), "peak_connections": g.peak.Load(),
		"splice_directions": g.spliceDirections.Load(), "buffered_directions": g.bufferedDirections.Load()}
	if g.fetch != nil {
		out["fetch"] = g.fetch.status()
	}
	return out
}

func (g *Gateway) Control(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		// Control operations are tiny and serialized; no unbounded control goroutines.
		c.SetDeadline(time.Now().Add(2 * time.Second))
		var req struct {
			Op       string  `json:"op"`
			MBPS     float64 `json:"mbps"`
			Disabled []bool  `json:"disabled,omitempty"`
		}
		d := json.NewDecoder(io.LimitReader(c, 4096))
		d.DisallowUnknownFields()
		var out any
		if d.Decode(&req) != nil {
			out = map[string]string{"error": "invalid control request"}
		} else {
			switch req.Op {
			case "health":
				if g.fetch != nil && g.fetch.setHealth(req.Disabled) {
					out = map[string]bool{"ok": true}
				} else {
					out = map[string]string{"error": "invalid health update"}
				}
			case "status":
				out = g.Status()
			case "limit":
				if g.limiter.Set(req.MBPS) {
					out = g.Status()
				} else {
					out = map[string]string{"error": "invalid rate"}
				}
			default:
				out = map[string]string{"error": "unknown operation"}
			}
		}
		_ = json.NewEncoder(c).Encode(out)
		c.Close()
	}
}

type bytePool struct {
	p    sync.Pool
	size int
}

func (p *bytePool) Get() []byte {
	if b := p.p.Get(); b != nil {
		return b.([]byte)
	}
	return make([]byte, p.size)
}
func (p *bytePool) Put(b []byte) {
	if cap(b) == p.size {
		p.p.Put(b[:p.size])
	}
}

var buffers = &bytePool{size: 16 << 10}
var relayBuffers = &bytePool{size: 64 << 10}

type countedBody struct {
	io.ReadCloser
	ctx     context.Context
	limiter *Limiter
	bytes   *atomic.Uint64
}

func (b *countedBody) Read(p []byte) (int, error) {
	if len(p) > 16<<10 {
		p = p[:16<<10]
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		if b.limiter != nil {
			if e := b.limiter.Wait(b.ctx, n); e != nil {
				return 0, e
			}
		}
		b.bytes.Add(uint64(n))
	}
	return n, err
}

type limitedListener struct {
	net.Listener
	slots    chan struct{}
	ctx      context.Context
	rejected *atomic.Uint64
	peak     *atomic.Int64
}

func (l *limitedListener) Accept() (net.Conn, error) {
	// Acquire after accept: 500 idle listeners must not reserve 500 connection slots.
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			recordPeak(l.peak, int64(len(l.slots)))
			return &slotConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			l.rejected.Add(1)
			c.Close()
			// Overload is not a listener failure. Returning a temporary error to
			// net/http would trigger exponential accept backoff after capacity frees.
		}
	}
}

func recordPeak(peak *atomic.Int64, current int64) {
	for old := peak.Load(); current > old; old = peak.Load() {
		if peak.CompareAndSwap(old, current) {
			return
		}
	}
}

type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *slotConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
