package signed

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	utls "github.com/mrqs001/vpngate/internal/third_party/utls"
)

// Options mirror the http.Transport settings vpngate uses for /fetch.
type Options struct {
	RootCAs                *x509.CertPool // nil: system roots
	InsecureSkipVerify     bool
	HTTP2                  bool // offer h2; false offers only http/1.1 (no longer Chrome's ALPN)
	ResponseHeaderTimeout  time.Duration
	IdleConnTimeout        time.Duration
	MaxIdleConnsPerHost    int // idle HTTP/1.1 connections kept per origin
	MaxResponseHeaderBytes uint32
}

// Transport is an http.RoundTripper that sends requests with the profile's
// TLS, HTTP/2 and header fingerprint. HTTP/2 connections are shared per
// origin; HTTP/1.1 connections carry one request at a time.
type Transport struct {
	dial DialFunc
	p    *Profile
	o    Options
	tls  *tlsConfig

	mu        sync.Mutex
	pools     map[string]*originPool
	lastSweep time.Time
}

type originPool struct {
	h2      []*h2Conn
	h1      []*h1Conn // idle
	dialing *dialCall
	h1Only  bool // http:// or ALPN chose http/1.1: dials need not wait for each other
}

type dialCall struct {
	done chan struct{}
	err  error
}

func NewTransport(dial DialFunc, p *Profile, o Options) *Transport {
	if o.MaxResponseHeaderBytes == 0 {
		o.MaxResponseHeaderBytes = 64 << 10
	}
	return &Transport{dial: dial, p: p, o: o, pools: map[string]*originPool{},
		tls: &tlsConfig{roots: o.RootCAs, insecure: o.InsecureSkipVerify, h2: o.HTTP2, cache: utls.NewLRUClientSessionCache(128)}}
}

type omitKey struct{}

// WithOmit attaches the names of default headers to leave out of a request.
func WithOmit(ctx context.Context, names []string) context.Context {
	return context.WithValue(ctx, omitKey{}, names)
}

// OmitFrom returns the names attached by WithOmit.
func OmitFrom(ctx context.Context) []string {
	v, _ := ctx.Value(omitKey{}).([]string)
	return v
}

func originKey(u *urlParts) string { return u.scheme + "://" + u.addr }

type urlParts struct{ scheme, addr, host string }

func parts(r *http.Request) (*urlParts, error) {
	u := r.URL
	if u.Scheme != "https" && u.Scheme != "http" || u.Hostname() == "" {
		return nil, errors.New("signed: unsupported URL " + u.Redacted())
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return &urlParts{scheme: u.Scheme, addr: net.JoinHostPort(u.Hostname(), port), host: u.Hostname()}, nil
}

func replayable(r *http.Request) bool {
	return r.Body == nil || r.Body == http.NoBody || r.GetBody != nil
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	up, err := parts(r)
	if err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	hasBody := r.Body != nil && r.Body != http.NoBody
	client := r.Header
	if _, set := client["Content-Length"]; !set && (r.ContentLength > 0 || (!hasBody && !navigation(r.Method))) {
		client = r.Header.Clone()
		client.Set("Content-Length", strconv.FormatInt(max(r.ContentLength, 0), 10))
	}
	fields := t.p.Headers(r.Method, r.URL, client, OmitFrom(r.Context()))
	key := originKey(up)
	for attempt := 0; ; attempt++ {
		cc, hc, reused, err := t.conn(r.Context(), key, up)
		if err != nil {
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, err
		}
		var resp *http.Response
		if cc != nil {
			resp, err = cc.roundTrip(r, fields)
		} else {
			resp, err = hc.roundTrip(r, fields, t.p)
		}
		if err == nil {
			return resp, nil
		}
		if attempt > 0 || !replayable(r) || r.Context().Err() != nil || !retryableConnError(err, reused, cc != nil) {
			return nil, err
		}
		if r.GetBody != nil && hasBody {
			body, e := r.GetBody()
			if e != nil {
				return nil, err
			}
			r = r.Clone(r.Context())
			r.Body = body
		}
	}
}

// retryableConnError reports whether a failure happened before the server
// could have acted on the request, on a connection that was already open.
func retryableConnError(err error, reused, h2 bool) bool {
	if errors.Is(err, errH2Unprocessed) {
		return true
	}
	if !reused {
		return false
	}
	if h2 {
		return errors.Is(err, errH2ConnLost)
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// conn returns a connection with room for one request: a reserved stream
// on a pooled HTTP/2 connection, an idle HTTP/1.1 connection, or a new one.
// Only one dial per origin runs at a time; other callers wait for it, so a
// burst to a new HTTP/2 origin shares one connection as Chrome does.
func (t *Transport) conn(ctx context.Context, key string, up *urlParts) (*h2Conn, *h1Conn, bool, error) {
	for {
		t.mu.Lock()
		t.sweepLocked(time.Now())
		p := t.pools[key]
		if p == nil {
			p = &originPool{}
			t.pools[key] = p
		}
		for _, cc := range p.h2 {
			if cc.reserve() {
				t.mu.Unlock()
				return cc, nil, true, nil
			}
		}
		if n := len(p.h1); n > 0 {
			hc := p.h1[n-1]
			p.h1 = p.h1[:n-1]
			t.mu.Unlock()
			return nil, hc, true, nil
		}
		if d := p.dialing; d != nil && !p.h1Only && up.scheme == "https" {
			t.mu.Unlock()
			select {
			case <-d.done:
			case <-ctx.Done():
				return nil, nil, false, ctx.Err()
			}
			if d.err != nil && !errors.Is(d.err, context.Canceled) && !errors.Is(d.err, context.DeadlineExceeded) {
				return nil, nil, false, d.err
			}
			continue // the new HTTP/2 connection may have room; an HTTP/1.1 one does not
		}
		d := &dialCall{done: make(chan struct{})}
		p.dialing = d
		t.mu.Unlock()

		cc, hc, err := t.dialConn(ctx, key, up)
		t.mu.Lock()
		if p.dialing == d {
			p.dialing = nil
		}
		p.h1Only = p.h1Only || hc != nil
		d.err = err
		if cc != nil {
			cc.reserve()
			p.h2 = append(p.h2, cc)
		}
		t.mu.Unlock()
		close(d.done)
		return cc, hc, false, err
	}
}

func (t *Transport) dialConn(ctx context.Context, key string, up *urlParts) (*h2Conn, *h1Conn, error) {
	var c net.Conn
	h2 := false
	if up.scheme == "https" {
		tc, err := dialTLS(ctx, t.dial, up.addr, up.host, t.p, t.tls)
		if err != nil {
			return nil, nil, err
		}
		c, h2 = tc, tc.ConnectionState().NegotiatedProtocol == "h2"
	} else {
		raw, err := t.dial(ctx, "tcp", up.addr)
		if err != nil {
			return nil, nil, err
		}
		c = raw
	}
	if h2 {
		cc, err := newH2Conn(c, t.p, t.o.MaxResponseHeaderBytes)
		if err != nil {
			return nil, nil, err
		}
		cc.respHeaderTimeout = t.o.ResponseHeaderTimeout
		return cc, nil, nil
	}
	hc := newH1Conn(c)
	hc.respHeaderTimeout = t.o.ResponseHeaderTimeout
	hc.onIdle = func(hc *h1Conn) { t.putIdle(key, hc) }
	return nil, hc, nil
}

func (t *Transport) putIdle(key string, hc *h1Conn) {
	t.mu.Lock()
	p := t.pools[key]
	if p != nil && len(p.h1) < max(1, t.o.MaxIdleConnsPerHost) {
		p.h1 = append(p.h1, hc)
		hc = nil
	}
	t.mu.Unlock()
	if hc != nil {
		hc.close()
	}
}

// sweepLocked drops dead connections and closes ones idle past
// IdleConnTimeout, at most once per second, without a timer goroutine.
func (t *Transport) sweepLocked(now time.Time) {
	if now.Sub(t.lastSweep) < time.Second {
		return
	}
	t.lastSweep = now
	t.pruneLocked(func(since time.Time) bool { return t.o.IdleConnTimeout > 0 && now.Sub(since) > t.o.IdleConnTimeout })
}

// pruneLocked removes dead connections and closes idle ones for which
// expired returns true. Caller holds t.mu.
func (t *Transport) pruneLocked(expired func(idleSince time.Time) bool) {
	for key, p := range t.pools {
		live := p.h2[:0]
		for _, cc := range p.h2 {
			idle, since := cc.idle()
			switch {
			case !cc.usable() && idle:
				cc.close()
			case !cc.usable():
				live = append(live, cc) // finishing streams; drop once idle
			case idle && expired(since):
				cc.close()
			default:
				live = append(live, cc)
			}
		}
		clear(p.h2[len(live):])
		p.h2 = live
		idle := p.h1[:0]
		for _, hc := range p.h1 {
			hc.mu.Lock()
			since := hc.idleSince
			hc.mu.Unlock()
			if expired(since) {
				hc.close()
			} else {
				idle = append(idle, hc)
			}
		}
		clear(p.h1[len(idle):])
		p.h1 = idle
		if len(p.h2) == 0 && len(p.h1) == 0 && p.dialing == nil {
			delete(t.pools, key)
		}
	}
}

// CloseIdleConnections closes every connection with no request in flight.
func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(func(time.Time) bool { return true })
}
