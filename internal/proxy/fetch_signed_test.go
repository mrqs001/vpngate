package proxy

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/mrqs001/vpngate/internal/config"
	"github.com/mrqs001/vpngate/internal/signed"
	"github.com/mrqs001/vpngate/internal/signed/signedtest"
)

func signedEndpoint(e string) string { return strings.TrimSuffix(e, "/fetch") + "/fetch_signed" }

func trust(g *Gateway, origins ...*httptest.Server) {
	pool := x509.NewCertPool()
	for _, o := range origins {
		pool.AddCert(o.Certificate())
	}
	g.signedRoots = pool
}

func TestFetchRequestSizeClass(t *testing.T) {
	// The /fetch hot path allocates one fetchRequest per request; it must stay
	// in the 64-byte size class it had before /fetch_signed.
	if n := unsafe.Sizeof(fetchRequest{}); n > 64 {
		t.Fatal("fetchRequest is", n, "bytes")
	}
}

func signedRequests(t *testing.T, g *Gateway) uint64 {
	raw, err := json.Marshal(g.Status())
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Fetch struct {
			SignedRequests *uint64 `json:"signed_requests"`
		} `json:"fetch"`
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.Fetch.SignedRequests == nil {
		t.Fatal("status has no fetch.signed_requests", err)
	}
	return *s.Fetch.SignedRequests
}

func TestFetchOnlyCreatesNoSignedTransport(t *testing.T) {
	o := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer o.Close()
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o, o}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(o.Certificate())
	for _, tr := range g.fetchTransports {
		tr.TLSClientConfig.RootCAs = pool
	}
	for range 20 {
		if r, _, e := fetchCall(c, endpoint, o.URL, nil); e != nil || r.StatusCode != 200 {
			t.Fatal(e, r)
		}
	}
	if len(g.signed) != 2 {
		t.Fatal("signed lanes", len(g.signed))
	}
	for i := range g.signed {
		if g.signed[i].t.Load() != nil {
			t.Fatal("signed transport created by /fetch traffic on lane", i)
		}
	}
	if n := signedRequests(t, g); n != 0 {
		t.Fatal("signed_requests", n)
	}
}

func TestFetchSignedContract(t *testing.T) {
	seen := make(chan http.Header, 64)
	handler := func(lane int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/headers":
				seen <- r.Header.Clone()
				io.WriteString(w, r.Proto)
			case "/big":
				w.Write(bytes.Repeat([]byte("b"), 1<<20))
			case "/redir":
				http.Redirect(w, r, "/final", http.StatusFound)
			case "/final":
				io.WriteString(w, "final")
			case "/down":
				http.Redirect(w, r, "http://"+r.Host+"/final", http.StatusFound)
			case "/flaky":
				if lane == 0 {
					w.WriteHeader(503)
					return
				}
				io.WriteString(w, "recovered")
			case "/slow":
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
	origins := []*httptest.Server{httptest.NewUnstartedServer(handler(0)), httptest.NewUnstartedServer(handler(1))}
	for _, o := range origins {
		o.EnableHTTP2 = true
		o.StartTLS()
		defer o.Close()
	}
	g, endpoint, c := fetchGateway(t, origins, nil)
	trust(g, origins...)
	signedURL := signedEndpoint(endpoint)
	target := origins[0].URL

	r, body, err := fetchCall(c, signedURL, target+"/headers", map[string]string{"Vpngate-Omit": "sec-fetch-user", "Vpngate-Session": "s1"})
	if err != nil || r.StatusCode != 200 || string(body) != "HTTP/2.0" {
		t.Fatal("basic", err, r, string(body))
	}
	if r.Header.Get("Vpngate-Lane") == "" || r.Header.Get("Vpngate-Attempts") != "1" || r.Header.Get("Vpngate-Queue-Ms") == "" {
		t.Fatal("gateway headers", r.Header)
	}
	h := <-seen
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "vpngate-") {
			t.Fatal("control header reached the origin", k)
		}
	}
	if h.Get("Sec-Ch-Ua") == "" || h.Get("User-Agent") != signed.Chrome.UserAgent {
		t.Fatal("Chrome headers missing", h)
	}
	if _, ok := h["Sec-Fetch-User"]; ok {
		t.Fatal("Vpngate-Omit ignored")
	}

	if r, body, err = fetchCall(c, signedURL, target+"/big", nil); err != nil || r.StatusCode != 200 || len(body) != 1<<20 {
		t.Fatal("streaming", err, len(body))
	}
	if r, body, err = fetchCall(c, signedURL, target+"/redir", nil); err != nil || r.StatusCode != 200 || string(body) != "final" {
		t.Fatal("redirect", err, string(body))
	}
	if r, _, err = fetchCall(c, signedURL, target+"/down", nil); err != nil || r.StatusCode != 502 {
		t.Fatal("HTTPS downgrade not refused", err, r.StatusCode)
	}
	for range 4 {
		r, body, err = fetchCall(c, signedURL, target+"/flaky", nil)
		if err != nil || r.StatusCode != 200 || string(body) != "recovered" || r.Header.Get("Vpngate-Lane") != "lane-1" {
			t.Fatal("retry across lanes", err, r.StatusCode, string(body))
		}
	}
	if r, _, err = fetchCall(c, signedURL, target+"/slow", map[string]string{"Vpngate-Timeout-Ms": "50"}); err != nil || r.StatusCode != 504 || r.Header.Get("Vpngate-Error") != "deadline" {
		t.Fatal("deadline", err, r.StatusCode, r.Header.Get("Vpngate-Error"))
	}
	if n := signedRequests(t, g); n < 8 {
		t.Fatal("signed_requests", n)
	}

	// An untrusted certificate is final: no retry on the other lane.
	g2, endpoint2, c2 := fetchGateway(t, origins, nil)
	r, _, err = fetchCall(c2, signedEndpoint(endpoint2), target+"/headers", nil)
	if err != nil || r.StatusCode != 502 {
		t.Fatal("untrusted certificate accepted", err, r.StatusCode)
	}
	dials := int64(0)
	for i := range origins {
		dials += g2.resolver.sockets.(*laneSockets).calls[i].Load()
	}
	if dials != 1 {
		t.Fatal("certificate failure retried", dials)
	}
}

func TestFetchSignedSeparateOriginState(t *testing.T) {
	o := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Ch-Ua") != "" {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		io.WriteString(w, "ok")
	}))
	o.EnableHTTP2 = true
	o.StartTLS()
	defer o.Close()
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o}, func(f *config.Fetch) { f.MaxAttempts = 1 })
	trust(g, o)
	pool := x509.NewCertPool()
	pool.AddCert(o.Certificate())
	g.fetchTransports[0].TLSClientConfig.RootCAs = pool
	for range 3 {
		if r, _, e := fetchCall(c, signedEndpoint(endpoint), o.URL, nil); e != nil || r.StatusCode != 429 {
			t.Fatal("signed 429", e, r)
		}
	}
	r, _, e := fetchCall(c, endpoint, o.URL, nil)
	if e != nil || r.StatusCode != 200 {
		t.Fatal("/fetch", e, r)
	}
	if ms, _ := strconv.Atoi(r.Header.Get("Vpngate-Queue-Ms")); ms >= 100 {
		t.Fatal("signed 429 paused /fetch for", ms, "ms")
	}
	raw, _ := json.Marshal(g.Status())
	var s struct {
		Fetch struct {
			Controllers []struct {
				Origin string `json:"origin"`
			} `json:"controllers"`
		} `json:"fetch"`
	}
	json.Unmarshal(raw, &s)
	want := map[string]bool{"https://" + o.Listener.Addr().String(): false, "signed:https://" + o.Listener.Addr().String(): false}
	for _, ctl := range s.Fetch.Controllers {
		if _, ok := want[ctl.Origin]; ok {
			want[ctl.Origin] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Fatal("controller missing", k, string(raw))
		}
	}
}

func TestFetchSignedHTTP2Disabled(t *testing.T) {
	o := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Proto) }))
	o.EnableHTTP2 = true
	o.StartTLS()
	defer o.Close()
	off := false
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o}, func(f *config.Fetch) { f.HTTP2 = &off })
	trust(g, o)
	if r, body, e := fetchCall(c, signedEndpoint(endpoint), o.URL, nil); e != nil || r.StatusCode != 200 || string(body) != "HTTP/1.1" {
		t.Fatal(e, string(body))
	}
}

func TestFetchSignedFingerprintEndToEnd(t *testing.T) {
	// The lane's origin is a bare listener that records the ClientHello.
	o := httptest.NewUnstartedServer(nil)
	defer o.Listener.Close()
	hello := make(chan []byte, 1)
	go func() {
		conn, err := o.Listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rec := signedtest.NewRecorder(conn)
		buf := make([]byte, 4096)
		go func() {
			for {
				if _, err := rec.Read(buf); err != nil {
					return
				}
			}
		}()
		hello <- rec.First(t)
	}()
	g, endpoint, c := fetchGateway(t, []*httptest.Server{o}, func(f *config.Fetch) { f.MaxAttempts = 1 })
	_ = g
	go fetchCall(c, signedEndpoint(endpoint), "https://"+o.Listener.Addr().String()+"/", nil)
	var got []byte
	select {
	case got = <-hello:
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello")
	}
	// An IP-literal target has no SNI. JA4's cipher and extension hashes
	// exclude SNI, so they must equal Chrome's; the prefix differs only in
	// the SNI marker and the extension count.
	ja4, capture := strings.Split(signedtest.JA4(t, got), "_"), strings.Split(signedtest.JA4(t, signedtest.Chrome155Capture(t)), "_")
	wantPrefix := strings.Replace(capture[0], "d", "i", 1)
	n, _ := strconv.Atoi(capture[0][6:8])
	wantPrefix = wantPrefix[:6] + fmt.Sprintf("%02d", n-1) + wantPrefix[8:]
	if ja4[0] != wantPrefix || ja4[1] != capture[1] || ja4[2] != capture[2] {
		t.Fatalf("JA4 %v, Chrome capture %v", ja4, capture)
	}
}

func TestFetchBadPathKeepsOriginalMessage(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer o.Close()
	_, endpoint, c := fetchGateway(t, []*httptest.Server{o}, nil)
	for _, path := range []string{"/other", "/fetch?x=1"} {
		r, body, err := fetchCall(c, strings.TrimSuffix(endpoint, "/fetch")+path, o.URL, nil)
		if err != nil || r.StatusCode != 400 || string(body) != "use /fetch with Vpngate-Target\n" {
			t.Fatalf("%s: %v %q", path, err, body)
		}
	}
}
