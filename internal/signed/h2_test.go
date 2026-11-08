package signed

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// tcpPair returns two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		done <- c
	}()
	client, err = net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-done
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// framerServer drives the server side of a connection frame by frame.
type framerServer struct {
	t    *testing.T
	conn net.Conn
	fr   *http2.Framer
	enc  *hpack.Encoder
	buf  bytes.Buffer
	mu   sync.Mutex
}

func newFramerServer(t *testing.T, c net.Conn) *framerServer {
	s := &framerServer{t: t, conn: c}
	preface := make([]byte, len(http2.ClientPreface))
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		t.Fatal("no client preface", err)
	}
	s.fr = http2.NewFramer(c, bufio.NewReader(c))
	s.fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	s.fr.MaxHeaderListSize = 1 << 20
	s.enc = hpack.NewEncoder(&s.buf)
	return s
}

func (s *framerServer) read() http2.Frame {
	s.t.Helper()
	f, err := s.fr.ReadFrame()
	if err != nil {
		s.t.Fatal("server read:", err)
	}
	return f
}

// next reads frames until one of type T arrives, skipping SETTINGS acks,
// WINDOW_UPDATEs and PINGs unless they are the wanted type.
func next[T http2.Frame](s *framerServer) T {
	s.t.Helper()
	for {
		f := s.read()
		if v, ok := f.(T); ok {
			return v
		}
	}
}

func (s *framerServer) settings() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fr.WriteSettings()
}

func (s *framerServer) block(fields ...string) []byte {
	s.buf.Reset()
	for i := 0; i < len(fields); i += 2 {
		s.enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	return append([]byte(nil), s.buf.Bytes()...)
}

func (s *framerServer) respond(id uint32, end bool, fields ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: s.block(fields...), EndHeaders: true, EndStream: end})
}

func (s *framerServer) data(id uint32, end bool, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fr.WriteData(id, end, b)
}

func newGET(t *testing.T, url string) *http.Request {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestH2PrefaceMatchesChrome(t *testing.T) {
	c, sc := tcpPair(t)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	s := newFramerServer(t, sc)
	set := s.read().(*http2.SettingsFrame)
	var ids []http2.SettingID
	var vals []uint32
	set.ForeachSetting(func(st http2.Setting) error { ids = append(ids, st.ID); vals = append(vals, st.Val); return nil })
	if !equal(ids, []http2.SettingID{1, 2, 4, 6}) || !equal(vals, []uint32{65536, 0, 6291456, 262144}) {
		t.Fatal("settings", ids, vals)
	}
	wu := s.read().(*http2.WindowUpdateFrame)
	if wu.StreamID != 0 || wu.Increment != 15663105 {
		t.Fatal("window update", wu.StreamID, wu.Increment)
	}
	fields := []Field{{"user-agent", "x"}, {"accept", "y"}, {"priority", "u=0, i"}}
	go cc.roundTrip(newGET(t, "https://a.example/p?q=1"), fields)
	h := next[*http2.MetaHeadersFrame](s)
	if !h.HasPriority() || !h.Priority.Exclusive || h.Priority.StreamDep != 0 || h.Priority.Weight != 255 {
		t.Fatal("priority", h.Priority)
	}
	var got []string
	for _, f := range h.Fields {
		got = append(got, f.Name+"="+f.Value)
	}
	want := []string{":method=GET", ":authority=a.example", ":scheme=https", ":path=/p?q=1", "user-agent=x", "accept=y", "priority=u=0, i"}
	if !equal(got, want) {
		t.Fatal("fields", got)
	}
	if !h.StreamEnded() {
		t.Fatal("GET without body must end the stream in HEADERS")
	}
}

func equal[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestH2PriorityWeightFollowsHeader(t *testing.T) {
	c, sc := tcpPair(t)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	s := newFramerServer(t, sc)
	go cc.roundTrip(newGET(t, "https://a.example:8443/"), []Field{{"priority", "u=1, i"}})
	h := next[*http2.MetaHeadersFrame](s)
	if h.Priority.Weight != 219 {
		t.Fatal("weight", h.Priority.Weight)
	}
	if v := h.PseudoValue("authority"); v != "a.example:8443" {
		t.Fatal("authority keeps a non-default port", v)
	}
}

// goServer serves h2c with prior knowledge on the server end of a pair.
func goServer(t *testing.T, sc net.Conn, s *http2.Server, h http.Handler) {
	go s.ServeConn(sc, &http2.ServeConnOpts{Handler: h})
}

func dialGo(t *testing.T, s *http2.Server, h http.Handler) *h2Conn {
	c, sc := tcpPair(t)
	goServer(t, sc, s, h)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.close() })
	return cc
}

func TestH2ConcurrentStreamsShareConnection(t *testing.T) {
	var inflight, peak atomic.Int64
	cc := dialGo(t, &http2.Server{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(20 * time.Millisecond)
		inflight.Add(-1)
		io.WriteString(w, r.URL.Path)
	}))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/" + strings.Repeat("x", i+1)
			resp, err := cc.roundTrip(newGET(t, "http://a.example"+path), nil)
			if err != nil {
				t.Error(err)
				return
			}
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(b) != path || resp.StatusCode != 200 || resp.ProtoMajor != 2 {
				t.Error("stream", i, err, string(b))
			}
		}(i)
	}
	wg.Wait()
	if peak.Load() < 2 {
		t.Fatal("streams were not concurrent", peak.Load())
	}
}

func TestH2LargeDownloadFlowControl(t *testing.T) {
	const size = 20 << 20
	cc := dialGo(t, &http2.Server{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "20971520")
		chunk := bytes.Repeat([]byte("d"), 64<<10)
		for n := 0; n < size; n += len(chunk) {
			w.Write(chunk)
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := cc.roundTrip(newGET(t, "http://a.example/").WithContext(ctx), nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != size || resp.ContentLength != size {
		t.Fatal(n, err, resp.ContentLength)
	}
}

func TestH2LargeUploadSmallServerWindow(t *testing.T) {
	cc := dialGo(t, &http2.Server{MaxUploadBufferPerStream: 65535, MaxUploadBufferPerConnection: 65535},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := sha256.New()
			io.Copy(h, r.Body)
			io.WriteString(w, hex.EncodeToString(h.Sum(nil)))
		}))
	body := bytes.Repeat([]byte("u"), 5<<20)
	sum := sha256.Sum256(body)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", "http://a.example/up", bytes.NewReader(body))
	resp, err := cc.roundTrip(r, []Field{{"content-length", "5242880"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != hex.EncodeToString(sum[:]) {
		t.Fatal("upload digest", err, string(b))
	}
}

func TestH2CancelSendsRSTAndConnSurvives(t *testing.T) {
	c, sc := tcpPair(t)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	s := newFramerServer(t, sc)
	s.settings()
	type result struct {
		resp *http.Response
		err  error
	}
	got := make(chan result, 1)
	go func() { r, e := cc.roundTrip(newGET(t, "https://a.example/a"), nil); got <- result{r, e} }()
	a := next[*http2.MetaHeadersFrame](s)
	s.respond(a.StreamID, false, ":status", "200")
	s.data(a.StreamID, false, []byte("partial"))
	ra := <-got
	if ra.err != nil {
		t.Fatal(ra.err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(ra.resp.Body, buf); err != nil {
		t.Fatal(err)
	}
	ra.resp.Body.Close()
	rst := next[*http2.RSTStreamFrame](s)
	if rst.StreamID != a.StreamID || rst.ErrCode != http2.ErrCodeCancel {
		t.Fatal("rst", rst.StreamID, rst.ErrCode)
	}
	go func() { r, e := cc.roundTrip(newGET(t, "https://a.example/b"), nil); got <- result{r, e} }()
	b := next[*http2.MetaHeadersFrame](s)
	s.respond(b.StreamID, false, ":status", "200")
	s.data(b.StreamID, true, []byte("whole"))
	rb := <-got
	if rb.err != nil {
		t.Fatal(rb.err)
	}
	body, err := io.ReadAll(rb.resp.Body)
	if err != nil || string(body) != "whole" {
		t.Fatal("second stream", err, string(body))
	}

	// Cancelling the request context mid-body also resets the stream.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		r, e := cc.roundTrip(newGET(t, "https://a.example/c").WithContext(ctx), nil)
		got <- result{r, e}
	}()
	h := next[*http2.MetaHeadersFrame](s)
	s.respond(h.StreamID, false, ":status", "200")
	rc := <-got
	cancel()
	if _, err := io.ReadAll(rc.resp.Body); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled body", err)
	}
	if rst := next[*http2.RSTStreamFrame](s); rst.StreamID != h.StreamID {
		t.Fatal("no reset for cancelled context")
	}
}

func TestH2ContinuationAndHeaderLimit(t *testing.T) {
	c, sc := tcpPair(t)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	s := newFramerServer(t, sc)
	s.settings()
	type result struct {
		resp *http.Response
		err  error
	}
	got := make(chan result, 1)
	go func() { r, e := cc.roundTrip(newGET(t, "https://a.example/"), nil); got <- result{r, e} }()
	h := next[*http2.MetaHeadersFrame](s)
	blk := s.block(":status", "200", "x-one", strings.Repeat("a", 100), "x-two", "b")
	third := len(blk) / 3
	s.mu.Lock()
	s.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: h.StreamID, BlockFragment: blk[:third], EndStream: true})
	s.fr.WriteContinuation(h.StreamID, false, blk[third:2*third])
	s.fr.WriteContinuation(h.StreamID, true, blk[2*third:])
	s.mu.Unlock()
	r := <-got
	if r.err != nil || r.resp.Header.Get("X-Two") != "b" || len(r.resp.Header.Get("X-One")) != 100 {
		t.Fatal("continuation", r.err)
	}

	go func() { r, e := cc.roundTrip(newGET(t, "https://a.example/big"), nil); got <- result{r, e} }()
	h = next[*http2.MetaHeadersFrame](s)
	big := s.block(":status", "200", "x-big", strings.Repeat("z", 70<<10))
	s.mu.Lock()
	s.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: h.StreamID, BlockFragment: big[:16000]})
	for off := 16000; off < len(big); off += 16000 {
		end := min(off+16000, len(big))
		s.fr.WriteContinuation(h.StreamID, end == len(big), big[off:end])
	}
	s.mu.Unlock()
	select {
	case r := <-got:
		if r.err == nil {
			t.Fatal("oversized response headers accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("oversized response headers hang")
	}
}

func TestH2GoAwayFailsUnprocessedRetryably(t *testing.T) {
	c, sc := tcpPair(t)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	s := newFramerServer(t, sc)
	s.settings()
	errs := make(chan error, 2)
	go func() { _, e := cc.roundTrip(newGET(t, "https://a.example/1"), nil); errs <- e }()
	first := next[*http2.MetaHeadersFrame](s)
	go func() { _, e := cc.roundTrip(newGET(t, "https://a.example/3"), nil); errs <- e }()
	second := next[*http2.MetaHeadersFrame](s)
	if first.StreamID != 1 || second.StreamID != 3 {
		t.Fatal("stream ids", first.StreamID, second.StreamID)
	}
	s.mu.Lock()
	s.fr.WriteGoAway(1, http2.ErrCodeNo, nil)
	s.mu.Unlock()
	if e := <-errs; !errors.Is(e, errH2Unprocessed) {
		t.Fatal("stream 3 after GOAWAY", e)
	}
	if cc.reserve() {
		t.Fatal("reserve after GOAWAY")
	}
	s.respond(1, true, ":status", "204")
	if e := <-errs; e != nil {
		t.Fatal("stream 1 must finish", e)
	}
}

func TestH2CancelledBeforeStartReleasesReservation(t *testing.T) {
	cc := dialGo(t, &http2.Server{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 200; i++ { // the leak depended on goroutine timing
		if !cc.reserve() {
			t.Fatal("reserve", i)
		}
		cc.roundTrip(newGET(t, "http://a.example/").WithContext(ctx), nil)
	}
	deadline := time.Now().Add(time.Second)
	for idle, _ := cc.idle(); !idle; idle, _ = cc.idle() {
		if time.Now().After(deadline) {
			cc.mu.Lock()
			t.Fatal("reservation leaked: pending", cc.pending, "streams", len(cc.streams))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestH2StalledWriteFailsConnection(t *testing.T) {
	old := h2WriteTimeout
	h2WriteTimeout = 200 * time.Millisecond
	defer func() { h2WriteTimeout = old }()
	c, sc := tcpPair(t)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	s := newFramerServer(t, sc)
	s.mu.Lock()
	s.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1<<31 - 1})
	s.fr.WriteWindowUpdate(0, 1<<31-1-65535)
	s.mu.Unlock()
	time.Sleep(50 * time.Millisecond) // the client applies the window; the server now stops reading
	body := io.LimitReader(zeros{}, 1<<30)
	r, _ := http.NewRequest("POST", "https://a.example/up", body)
	done := make(chan error, 1)
	go func() { _, e := cc.roundTrip(r, nil); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("stalled upload succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled write blocked the connection")
	}
	if cc.usable() {
		t.Fatal("stalled connection still usable")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestH2EarlyResponseResetsUnfinishedUpload(t *testing.T) {
	c, sc := tcpPair(t)
	cc, err := newH2Conn(c, Chrome, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.close()
	s := newFramerServer(t, sc)
	s.settings()
	r, _ := http.NewRequest("POST", "https://a.example/up", io.LimitReader(zeros{}, 1<<30))
	type result struct {
		resp *http.Response
		err  error
	}
	got := make(chan result, 1)
	go func() { resp, e := cc.roundTrip(r, nil); got <- result{resp, e} }()
	h := next[*http2.MetaHeadersFrame](s)
	s.respond(h.StreamID, true, ":status", "413")
	res := <-got
	if res.err != nil || res.resp.StatusCode != 413 {
		t.Fatal(res.err)
	}
	for {
		f := s.read()
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			if rst.StreamID != h.StreamID || rst.ErrCode != http2.ErrCodeNo {
				t.Fatal("rst", rst.StreamID, rst.ErrCode)
			}
			return
		}
		if d, ok := f.(*http2.DataFrame); ok && d.StreamEnded() {
			t.Fatal("upload completed instead of stopping")
		}
	}
}
