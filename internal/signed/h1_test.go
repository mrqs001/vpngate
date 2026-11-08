package signed

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rawRequest reads one HTTP/1.1 request head from c and returns its lines.
func rawRequest(t *testing.T, br *bufio.Reader) []string {
	t.Helper()
	var lines []string
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			return lines
		}
		lines = append(lines, l)
	}
}

func TestH1WritesChromeOrder(t *testing.T) {
	c, sc := tcpPair(t)
	h1 := newH1Conn(c)
	type res struct {
		r   *http.Response
		err error
	}
	got := make(chan res, 1)
	r, _ := http.NewRequest("GET", "https://a.example/p", nil)
	fields := Chrome.Headers("GET", r.URL, http.Header{"X-Extra": {"1"}, "Cookie": {"c=1"}}, nil)
	go func() { resp, err := h1.roundTrip(r, fields, Chrome); got <- res{resp, err} }()
	br := bufio.NewReader(sc)
	lines := rawRequest(t, br)
	want := []string{"GET /p HTTP/1.1", "Host: a.example", "Connection: keep-alive",
		"sec-ch-ua: " + Chrome.Navigate["sec-ch-ua"], "sec-ch-ua-mobile: ?0", `sec-ch-ua-platform: "Windows"`,
		"Upgrade-Insecure-Requests: 1", "User-Agent: " + Chrome.UserAgent, "Accept: " + Chrome.Navigate["accept"],
		"Sec-Fetch-Site: none", "Sec-Fetch-Mode: navigate", "Sec-Fetch-User: ?1", "Sec-Fetch-Dest: document",
		"Accept-Encoding: gzip, deflate, br, zstd", "Accept-Language: en-US,en;q=0.9", "Cookie: c=1", "X-Extra: 1"}
	if !equal(lines, want) {
		t.Fatalf("request head\n got %q\nwant %q", lines, want)
	}
	io.WriteString(sc, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	rr := <-got
	if rr.err != nil {
		t.Fatal(rr.err)
	}
	if b, _ := io.ReadAll(rr.r.Body); string(b) != "ok" {
		t.Fatal(string(b))
	}

	for _, length := range []int64{5, -1} {
		body := "hello"
		r, _ = http.NewRequest("POST", "https://a.example/up", io.NopCloser(strings.NewReader(body)))
		r.ContentLength = length
		fields = Chrome.Headers("POST", r.URL, http.Header{"Content-Type": {"text/plain"}}, nil)
		go func() { resp, err := h1.roundTrip(r, fields, Chrome); got <- res{resp, err} }()
		lines = rawRequest(t, br)
		if lines[2] != "Connection: keep-alive" {
			t.Fatal("connection position", lines)
		}
		var req bytes.Buffer
		req.WriteString(strings.Join(lines, "\r\n") + "\r\n\r\n")
		parsed, err := http.ReadRequest(bufio.NewReader(io.MultiReader(&req, br)))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(parsed.Body)
		if string(b) != body || parsed.Header.Get("Origin") != "https://a.example" {
			t.Fatal("body", length, string(b), lines)
		}
		if length < 0 && parsed.TransferEncoding[0] != "chunked" {
			t.Fatal("unknown length must be chunked", lines)
		}
		if length >= 0 && lines[3] != "Content-Length: 5" {
			t.Fatal("content-length position", lines)
		}
		io.WriteString(sc, "HTTP/1.1 204 No Content\r\n\r\n")
		if rr := <-got; rr.err != nil || rr.r.StatusCode != 204 {
			t.Fatal(rr.err)
		}
	}
}

func TestH1KeepAliveReuse(t *testing.T) {
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.URL.Path)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h1 := newH1Conn(c)
	defer h1.close()
	for i := 0; i < 5; i++ {
		r, _ := http.NewRequest("GET", srv.URL+"/n"+string(rune('0'+i)), nil)
		resp, err := h1.roundTrip(r, Chrome.Headers("GET", r.URL, nil, nil), Chrome)
		if err != nil {
			t.Fatal(i, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != r.URL.Path || !h1.reusable() {
			t.Fatal("response", i, string(b))
		}
	}
	if conns.Load() != 1 {
		t.Fatal("connections", conns.Load())
	}
	// A body closed early makes the connection unusable.
	r, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	resp, err := h1.roundTrip(r, nil, Chrome)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(10 * time.Millisecond)
	if h1.reusable() {
		t.Fatal("conn reusable after early close")
	}
}
