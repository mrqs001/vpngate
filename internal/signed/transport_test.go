package signed

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type origin struct {
	*httptest.Server
	conns atomic.Int64
	roots *x509.CertPool
}

func newOrigin(t *testing.T, tls, h2 bool, h http.HandlerFunc) *origin {
	t.Helper()
	o := &origin{}
	o.Server = httptest.NewUnstartedServer(h)
	o.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			o.conns.Add(1)
		}
	}
	if tls {
		o.EnableHTTP2 = h2
		o.StartTLS()
		o.roots = x509.NewCertPool()
		o.roots.AddCert(o.Certificate())
	} else {
		o.Start()
	}
	t.Cleanup(o.Close)
	return o
}

func newTestTransport(o *origin) *Transport {
	return NewTransport(plainDial, Chrome, Options{RootCAs: o.roots, HTTP2: true, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second, MaxIdleConnsPerHost: 8, MaxResponseHeaderBytes: 64 << 10})
}

func get(t *testing.T, tr *Transport, ctx context.Context, url string) (*http.Response, string) {
	t.Helper()
	r, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := tr.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

func TestTransportReusesOneH2Conn(t *testing.T) {
	o := newOrigin(t, true, true, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Sec-Ch-Ua-Platform")+r.URL.Path)
	})
	tr := newTestTransport(o)
	defer tr.CloseIdleConnections()
	for i := 0; i < 8; i++ {
		resp, body := get(t, tr, context.Background(), o.URL+"/x")
		if resp.Proto != "HTTP/2.0" || body != `"Windows"/x` {
			t.Fatal(resp.Proto, body)
		}
	}
	if o.conns.Load() != 1 {
		t.Fatal("connections", o.conns.Load())
	}
}

func TestTransportALPNHTTP1Origin(t *testing.T) {
	o := newOrigin(t, true, false, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto+" "+r.Header.Get("User-Agent"))
	})
	tr := newTestTransport(o)
	defer tr.CloseIdleConnections()
	for i := 0; i < 3; i++ {
		resp, body := get(t, tr, context.Background(), o.URL+"/")
		if resp.Proto != "HTTP/1.1" || body != "HTTP/1.1 "+Chrome.UserAgent {
			t.Fatal(resp.Proto, body)
		}
	}
	if o.conns.Load() != 1 {
		t.Fatal("HTTP/1.1 keep-alive not reused", o.conns.Load())
	}
}

func TestTransportPlainHTTP(t *testing.T) {
	o := newOrigin(t, false, false, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Sec-Ch-Ua")+"|"+r.Header.Get("Accept-Encoding"))
	})
	tr := newTestTransport(o)
	defer tr.CloseIdleConnections()
	if _, body := get(t, tr, context.Background(), o.URL+"/"); body != "|gzip, deflate" {
		t.Fatal(body)
	}
}

func TestTransportIdleConnClosedByServer(t *testing.T) {
	for _, mode := range []string{"close", "goaway"} {
		t.Run(mode, func(t *testing.T) {
			o := newOrigin(t, true, true, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
			tr := newTestTransport(o)
			defer tr.CloseIdleConnections()
			get(t, tr, context.Background(), o.URL+"/")
			if mode == "close" {
				o.CloseClientConnections()
			} else {
				o.Config.SetKeepAlivesEnabled(false) // net/http sends GOAWAY to idle HTTP/2 conns
			}
			time.Sleep(50 * time.Millisecond)
			for i := 0; i < 3; i++ {
				if _, body := get(t, tr, context.Background(), o.URL+"/"); body != "ok" {
					t.Fatal(body)
				}
			}
			if o.conns.Load() < 2 {
				t.Fatal("expected a new connection", o.conns.Load())
			}
		})
	}
}

func TestTransportOmitFromContext(t *testing.T) {
	o := newOrigin(t, true, true, func(w http.ResponseWriter, r *http.Request) {
		_, user := r.Header["Sec-Fetch-User"]
		_, site := r.Header["Sec-Fetch-Site"]
		io.WriteString(w, strings.Join([]string{boolString(user), boolString(site)}, ","))
	})
	tr := newTestTransport(o)
	defer tr.CloseIdleConnections()
	ctx := WithOmit(context.Background(), []string{"sec-fetch-user"})
	if _, body := get(t, tr, ctx, o.URL+"/"); body != "false,true" {
		t.Fatal(body)
	}
	if OmitFrom(context.Background()) != nil {
		t.Fatal("omit without context value")
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestTransportPostBodyAndLength(t *testing.T) {
	o := newOrigin(t, true, true, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		io.WriteString(w, r.Header.Get("Content-Length")+"|"+r.Header.Get("Origin")+"|"+string(b))
	})
	tr := newTestTransport(o)
	defer tr.CloseIdleConnections()
	r, _ := http.NewRequest("POST", o.URL+"/p", strings.NewReader("hello"))
	resp, err := tr.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "5|"+o.URL+"|hello" {
		t.Fatal(string(b))
	}
}

func TestTransportNoGoroutinesWhenIdle(t *testing.T) {
	o := newOrigin(t, true, true, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	before := runtime.NumGoroutine()
	tr := newTestTransport(o)
	get(t, tr, context.Background(), o.URL+"/")
	tr.CloseIdleConnections()
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) { // the origin's own conn goroutines wind down too
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Fatal("goroutines", before, n)
	}
}

func TestTransportHTTP1OriginDialsInParallel(t *testing.T) {
	release := make(chan struct{})
	var inflight, peak atomic.Int64
	o := newOrigin(t, true, false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			return
		}
		n := inflight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		inflight.Add(-1)
	})
	slow := func(ctx context.Context, network, addr string) (net.Conn, error) {
		time.Sleep(100 * time.Millisecond)
		return plainDial(ctx, network, addr)
	}
	tr := NewTransport(slow, Chrome, Options{RootCAs: o.roots, HTTP2: true, IdleConnTimeout: time.Minute, MaxIdleConnsPerHost: 8})
	defer tr.CloseIdleConnections()
	get(t, tr, context.Background(), o.URL+"/warm") // learns the origin is HTTP/1.1
	done := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func() {
			r, _ := http.NewRequest("GET", o.URL+"/", nil)
			if resp, err := tr.RoundTrip(r); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			done <- struct{}{}
		}()
	}
	deadline := time.Now().Add(250 * time.Millisecond) // four serial dials take 400 ms
	for peak.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	for i := 0; i < 4; i++ {
		<-done
	}
	if peak.Load() < 4 {
		t.Fatal("HTTP/1.1 requests were serialised", peak.Load())
	}
}
