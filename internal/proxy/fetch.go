package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type fetchContextKey struct{}
type fetchRequest struct {
	target   *url.URL
	session  string
	class    fetchClass
	attempts int
	lane     int
	queued   time.Duration // waiting for dispatch, over all attempts
}

// fetchRefuse answers a request vpngate will not forward. reason is its
// Vpngate-Error value: invalid_request (400), proxy_auth (407) or stopping (503).
func fetchRefuse(w http.ResponseWriter, code int, reason, text string) {
	w.Header().Set("Vpngate-Error", reason)
	http.Error(w, text, code)
}

func fetchPriority(values []string) (fetchClass, bool) {
	switch {
	case len(values) == 0:
		return classInteractive, true
	case len(values) > 1:
		return 0, false
	case strings.EqualFold(values[0], "interactive"):
		return classInteractive, true
	case strings.EqualFold(values[0], "bulk"):
		return classBulk, true
	}
	return 0, false
}

func (g *Gateway) startFetch(l net.Listener) error {
	g.fetch = newFetchScheduler(g)
	for i, c := range g.cfg.Tunnels {
		// Reuse the namespace dialer. TLS is performed by the unprivileged
		// worker, with one bounded session cache per lane and no local TLS leg.
		tr := &http.Transport{Proxy: nil, DialContext: g.resolver.DialContext(i, c, time.Duration(g.cfg.ConnectSeconds)*time.Second),
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: g.cfg.Fetch.InsecureSkipVerify,
				ClientSessionCache: tls.NewLRUClientSessionCache(128)},
			ForceAttemptHTTP2: g.cfg.Fetch.UseHTTP2(), DisableCompression: true,
			MaxIdleConns: max(1, min(256, g.cfg.MaxConnections/len(g.lanes))), MaxIdleConnsPerHost: min(128, g.cfg.PerTunnel), MaxConnsPerHost: g.cfg.PerTunnel,
			IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: time.Duration(g.cfg.ConnectSeconds) * time.Second,
			ResponseHeaderTimeout: time.Duration(g.cfg.Fetch.TimeoutSeconds) * time.Second,
			ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 64 << 10}
		g.fetchTransports = append(g.fetchTransports, tr)
	}
	reverse := &httputil.ReverseProxy{Transport: fetchTransport{g}, BufferPool: relayBuffers,
		Rewrite: func(p *httputil.ProxyRequest) {
			meta := p.In.Context().Value(fetchContextKey{}).(*fetchRequest)
			u := *meta.target
			p.Out.URL = &u
			p.Out.Host = u.Host
			p.Out.RequestURI = ""
			stripFetchHeaders(p.Out.Header)
			p.Out.Header.Del("Proxy-Authorization")
			p.Out.Header.Del("Proxy-Connection")
		},
		ModifyResponse: func(r *http.Response) error {
			if r.StatusCode == http.StatusSwitchingProtocols {
				r.Body.Close()
				return errors.New("fetch does not support protocol upgrades")
			}
			meta := r.Request.Context().Value(fetchContextKey{}).(*fetchRequest)
			stripFetchHeaders(r.Header)
			r.Header.Set("Vpngate-Lane", g.cfg.Tunnels[meta.lane].ID)
			r.Header.Set("Vpngate-Attempts", strconv.Itoa(meta.attempts))
			r.Header.Set("Vpngate-Queue-Ms", strconv.FormatInt(meta.queued.Milliseconds(), 10))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			code := http.StatusBadGateway
			reason := "upstream_unavailable"
			if errors.Is(err, errFetchBusy) {
				code = http.StatusServiceUnavailable
				reason = "capacity"
			}
			if errors.Is(err, context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
				reason = "deadline"
				g.fetch.timeouts.Add(1)
			}
			if meta, ok := r.Context().Value(fetchContextKey{}).(*fetchRequest); ok {
				w.Header().Set("Vpngate-Queue-Ms", strconv.FormatInt(meta.queued.Milliseconds(), 10))
			}
			fetchRefuse(w, code, reason, http.StatusText(code))
		}, ErrorLog: discardLogger(),
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		if g.closing {
			g.mu.Unlock()
			fetchRefuse(w, 503, "stopping", "gateway stopping")
			return
		}
		g.handlers.Add(1)
		g.mu.Unlock()
		defer g.handlers.Done()
		if r.URL.Path != "/fetch" || r.URL.RawQuery != "" || r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
			fetchRefuse(w, 400, "invalid_request", "use /fetch with Vpngate-Target")
			return
		}
		if !g.authorized(r) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="vpngate"`)
			fetchRefuse(w, 407, "proxy_auth", "proxy authentication required")
			return
		}
		u, _, err := fetchTarget(r.Header.Get("Vpngate-Target"))
		if err != nil || len(r.Header.Values("Vpngate-Target")) != 1 {
			fetchRefuse(w, 400, "invalid_request", "invalid Vpngate-Target")
			return
		}
		session := r.Header.Get("Vpngate-Session")
		if len(session) > 128 {
			fetchRefuse(w, 400, "invalid_request", "session identifier too long")
			return
		}
		class, ok := fetchPriority(r.Header.Values("Vpngate-Priority"))
		if !ok {
			fetchRefuse(w, 400, "invalid_request", "Vpngate-Priority must be interactive or bulk")
			return
		}
		timeout := time.Duration(g.cfg.Fetch.TimeoutSeconds) * time.Second
		if v := r.Header.Get("Vpngate-Timeout-Ms"); v != "" {
			ms, e := strconv.Atoi(v)
			if e != nil || ms < 1 || ms > g.cfg.Fetch.TimeoutSeconds*1000 {
				fetchRefuse(w, 400, "invalid_request", "invalid request timeout")
				return
			}
			timeout = time.Duration(ms) * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		deadline := time.Now().Add(timeout)
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(deadline.Add(time.Second))
		defer rc.SetWriteDeadline(time.Time{})
		if r.Body != nil && r.Body != http.NoBody {
			// An ordinary read deadline also expires net/http's background
			// disconnect read on a GET, racing our request deadline into a
			// cancellation. Only interrupt an upload after its context ends.
			done := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { _ = rc.SetReadDeadline(time.Now()); close(done) })
			defer func() {
				if !stop() {
					<-done
				}
				_ = rc.SetReadDeadline(time.Time{})
			}()
		}
		meta := &fetchRequest{target: u, session: session, class: class}
		r = r.WithContext(context.WithValue(ctx, fetchContextKey{}, meta))
		g.fetch.requests.Add(1)
		reverse.ServeHTTP(w, r)
	})
	s := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10,
		BaseContext: func(net.Listener) context.Context { return g.ctx }, ErrorLog: discardLogger()}
	g.servers = append(g.servers, s)
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		err := s.Serve(&limitedListener{Listener: l, slots: g.slots, ctx: g.ctx, rejected: &g.rejected, peak: &g.peak})
		if g.ctx.Err() == nil {
			select {
			case g.serveErrors <- err:
			default:
			}
		}
	}()
	return nil
}

func stripFetchHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "vpngate-") {
			delete(h, k)
		}
	}
}

func fetchTarget(raw string) (*url.URL, uint16, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, 0, errors.New("invalid fetch target")
	}
	p := uint64(80)
	if u.Scheme == "https" {
		p = 443
	}
	if u.Port() != "" {
		p, err = strconv.ParseUint(u.Port(), 10, 16)
	}
	if err != nil || p == 0 {
		return nil, 0, errors.New("invalid target port")
	}
	return u, uint16(p), nil
}

// Let the standard client handle redirects and cross-origin credential
// stripping; every redirected request still goes through the lane scheduler.
type fetchTransport struct{ g *Gateway }

func (t fetchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c := http.Client{Transport: fetchAttemptTransport{t.g}, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("redirect limit")
		}
		if via[len(via)-1].URL.Scheme == "https" && next.URL.Scheme != "https" {
			return errors.New("HTTPS downgrade refused")
		}
		return nil
	}}
	return c.Do(r)
}

type fetchAttemptTransport struct{ g *Gateway }

func (t fetchAttemptTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	g := t.g
	meta := r.Context().Value(fetchContextKey{}).(*fetchRequest)
	u, port, err := fetchTarget(r.URL.String())
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, c := range g.cfg.Tunnels {
		if laneAllows(c.Ports, port) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, errors.New("destination port not allowed")
	}
	key := u.Scheme + "://" + strings.ToLower(net.JoinHostPort(u.Hostname(), strconv.Itoa(int(port))))
	pin := -1
	if meta.session != "" {
		h := fnv.New64a()
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(meta.session))
		pin = int(h.Sum64() % uint64(len(g.lanes)))
	}
	retryForbidden := false
	for _, origin := range g.cfg.Fetch.RetryForbiddenOrigins {
		if origin == key {
			retryForbidden = true
			break
		}
	}
	retryable := (r.Method == http.MethodGet || r.Method == http.MethodHead) && (r.Body == nil || r.Body == http.NoBody)
	avoid := -1
	for attempt := 0; ; attempt++ {
		p, waited, e := g.fetch.acquire(r.Context(), key, port, avoid, pin, meta.class)
		meta.queued += waited
		if e != nil {
			return nil, e
		}
		meta.lane = p.lane
		meta.attempts++
		out := r.Clone(r.Context())
		if r.Body != nil && r.Body != http.NoBody {
			out.Body = &countedBody{ReadCloser: r.Body, ctx: r.Context(), bytes: &g.lanes[p.lane].upload}
		}
		p.started = time.Now()
		resp, e := g.fetchTransports[p.lane].RoundTrip(out)
		ttfb := time.Since(p.started)
		lane := g.lanes[p.lane]
		blocked := e == nil && resp.StatusCode == 403 && retryForbidden
		bad := blocked || e != nil || resp.StatusCode == 500 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504
		if e != nil {
			var certErr *tls.CertificateVerificationError
			var hostErr x509.HostnameError
			if errors.As(e, &certErr) || errors.As(e, &hostErr) {
				p.finish(0, 0, 0)
				return nil, e
			}
			if !errors.Is(r.Context().Err(), context.Canceled) {
				lane.dialFailures.Add(1)
				g.failure(p.lane)
				if errors.Is(e, errLaneDNS) {
					lane.dnsFailures.Add(1)
				}
				p.finish(-1, ttfb, 0)
			} else {
				p.finish(0, 0, 0)
			}
		} else {
			if resp.StatusCode == 403 {
				lane.http403.Add(1)
			}
			if resp.StatusCode == 429 {
				lane.http429.Add(1)
			}
			if blocked {
				p.blockLane(time.Now())
			}
			if resp.StatusCode >= 500 {
				lane.http5xx.Add(1)
			}
			pause := time.Duration(0)
			if resp.StatusCode == 429 || resp.StatusCode == 503 {
				pause = retryAfter(resp.Header.Get("Retry-After"), time.Now())
				if resp.StatusCode == 429 && pause == 0 {
					pause = time.Second
				}
			}
			p.pauseOrigin(pause)
			if bad && retryable && !(blocked && pin >= 0) && attempt+1 < g.cfg.Fetch.MaxAttempts && pause == 0 {
				resp.Body.Close()
				g.failure(p.lane)
				p.finish(-1, ttfb, 0)
			} else {
				outcome := 0
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					outcome = 1
				}
				if bad {
					outcome = -1
				}
				resp.Body = &fetchBody{ReadCloser: resp.Body, p: p, ctx: r.Context(), ttfb: ttfb, outcome: outcome, pause: pause}
				return resp, nil
			}
		}
		if !retryable || attempt+1 >= g.cfg.Fetch.MaxAttempts || r.Context().Err() != nil {
			return nil, e
		}
		g.fetch.retries.Add(1)
		avoid = p.lane
		// Bounded backoff prevents a shared outage becoming a retry storm.
		timer := time.NewTimer(time.Duration(25<<attempt) * time.Millisecond)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return nil, r.Context().Err()
		case <-timer.C:
		}
	}
}

func retryAfter(v string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(v, 10, 32); err == nil {
		return time.Duration(min(seconds, 3600)) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		return min(max(at.Sub(now), 0), time.Hour)
	}
	return 0
}

type fetchBody struct {
	io.ReadCloser
	p        *fetchPermit
	ctx      context.Context
	ttfb     time.Duration
	outcome  int
	pause    time.Duration
	finished atomic.Bool
}

func (b *fetchBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.p.s.g.lanes[b.p.lane].download.Add(uint64(n))
		if e := b.p.s.g.limiter.Wait(b.ctx, n); e != nil {
			b.end(0)
			return 0, e
		}
	}
	if err == io.EOF {
		b.end(b.outcome)
	} else if err != nil {
		outcome := -1
		if errors.Is(b.ctx.Err(), context.Canceled) {
			outcome = 0
		}
		if errors.Is(b.ctx.Err(), context.DeadlineExceeded) {
			b.p.s.timeouts.Add(1)
		}
		b.end(outcome)
	}
	return n, err
}
func (b *fetchBody) end(outcome int) {
	if b.finished.Swap(true) {
		return
	}
	l := b.p.s.g.lanes[b.p.lane]
	if outcome == 1 {
		l.lastSuccess.Store(time.Now().UnixNano())
		b.p.s.completed.Add(1)
	}
	if outcome == -1 {
		b.p.s.g.failure(b.p.lane)
	}
	b.p.finish(outcome, b.ttfb, b.pause)
}
func (b *fetchBody) Close() error { err := b.ReadCloser.Close(); b.end(0); return err }
