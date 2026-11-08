package signed

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	// errH2Unprocessed means the server did not process the stream (GOAWAY
	// above it, REFUSED_STREAM, or no capacity); it is safe to retry.
	errH2Unprocessed = errors.New("signed: HTTP/2 stream not processed by server")
	// errH2ConnLost means the connection failed before the response headers.
	errH2ConnLost        = errors.New("signed: HTTP/2 connection lost")
	errH2HeadersTooLarge = errors.New("signed: response headers too large")
	errH2HeaderTimeout   = errors.New("signed: timeout awaiting response headers")
	errH2BodyClosed      = errors.New("signed: response body closed")
)

// h2WriteTimeout bounds one socket write. A write that makes no progress
// for this long means a dead path; the connection fails so a black-holed
// tunnel cannot hold the write lock (and every stream on it) for minutes.
var h2WriteTimeout = 10 * time.Second

type deadlineWriter struct{ c net.Conn }

func (w deadlineWriter) Write(p []byte) (int, error) {
	w.c.SetWriteDeadline(time.Now().Add(h2WriteTimeout))
	return w.c.Write(p)
}

const (
	h2PeerInitialWindow = 65535 // RFC 9113 defaults until the peer's SETTINGS
	h2PeerMaxFrame      = 16384
	h2InitialMaxStreams = 100
	h2MaxStreamID       = 1<<31 - 1
)

// h2Conn is one client HTTP/2 connection that writes the profile's preface,
// SETTINGS, WINDOW_UPDATE, pseudo-header order and HEADERS priority.
type h2Conn struct {
	conn              net.Conn
	p                 *Profile
	bw                *bufio.Writer
	fr                *http2.Framer
	recvWindow        int64 // our per-stream receive window (SETTINGS_INITIAL_WINDOW_SIZE)
	connWindow        int64 // our connection receive window after the preface update
	respHeaderTimeout time.Duration

	wmu  sync.Mutex // frame writes and the hpack encoder
	henc *hpack.Encoder
	hbuf bytes.Buffer

	mu          sync.Mutex
	cond        *sync.Cond // send-window and stream-state changes, for body writers
	streams     map[uint32]*h2Stream
	nextID      uint32
	pending     int // reserved by the pool, not yet started
	started     int // streams ever started
	maxStreams  uint32
	peerWindow  int64
	peerMax     uint32
	sendWindow  int64
	recvUnacked int64
	goAway      bool
	err         error
	idleSince   time.Time
}

type h2Stream struct {
	cc        *h2Conn
	id        uint32
	req       *http.Request
	cond      *sync.Cond // data, end or error for the body reader
	ready     chan struct{}
	resp      *http.Response
	headerErr error
	buf       bytes.Buffer
	unacked   int64
	sendWin   int64
	remoteEnd bool
	localEnd  bool
	closed    bool  // removed from the connection
	err       error // terminal error for the body reader
	stop      func() bool
}

func newH2Conn(c net.Conn, p *Profile, maxHeaderBytes uint32) (*h2Conn, error) {
	cc := &h2Conn{conn: c, p: p, bw: bufio.NewWriterSize(deadlineWriter{c}, 16<<10), streams: map[uint32]*h2Stream{}, nextID: 1,
		maxStreams: h2InitialMaxStreams, peerWindow: h2PeerInitialWindow, peerMax: h2PeerMaxFrame,
		sendWindow: h2PeerInitialWindow, recvWindow: h2PeerInitialWindow, idleSince: time.Now()}
	cc.cond = sync.NewCond(&cc.mu)
	table := uint32(4096)
	for _, s := range p.Settings {
		switch s.ID {
		case http2.SettingInitialWindowSize:
			cc.recvWindow = int64(s.Val)
		case http2.SettingHeaderTableSize:
			table = s.Val
		}
	}
	cc.connWindow = h2PeerInitialWindow + int64(p.ConnectionFlow)
	cc.fr = http2.NewFramer(cc.bw, bufio.NewReaderSize(c, 16<<10))
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(table, nil)
	cc.fr.MaxHeaderListSize = maxHeaderBytes
	cc.henc = hpack.NewEncoder(&cc.hbuf)
	settings := make([]http2.Setting, len(p.Settings))
	for i, s := range p.Settings {
		settings[i] = http2.Setting{ID: s.ID, Val: s.Val}
	}
	cc.bw.WriteString(http2.ClientPreface)
	cc.fr.WriteSettings(settings...)
	if p.ConnectionFlow > 0 {
		cc.fr.WriteWindowUpdate(0, p.ConnectionFlow)
	}
	if err := cc.bw.Flush(); err != nil {
		c.Close()
		return nil, err
	}
	go cc.readLoop()
	return cc, nil
}

func (cc *h2Conn) canTakeLocked() bool {
	return cc.err == nil && !cc.goAway && uint32(len(cc.streams)+cc.pending) < cc.maxStreams &&
		uint64(cc.nextID)+2*uint64(cc.pending) < h2MaxStreamID
}

// reserve reports whether a new stream fits and, if so, holds a slot for it.
func (cc *h2Conn) reserve() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if !cc.canTakeLocked() {
		return false
	}
	cc.pending++
	return true
}

// unreserve returns a slot taken by reserve that will not be used.
func (cc *h2Conn) unreserve() {
	cc.mu.Lock()
	if cc.pending > 0 {
		cc.pending--
	}
	cc.mu.Unlock()
}

// idle reports whether the connection is alive with no streams, and since when.
func (cc *h2Conn) idle() (bool, time.Time) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.err == nil && !cc.goAway && len(cc.streams) == 0 && cc.pending == 0, cc.idleSince
}

// usable reports whether the connection may take streams in future.
func (cc *h2Conn) usable() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.err == nil && !cc.goAway
}

func (cc *h2Conn) close() error {
	err := cc.conn.Close()
	cc.fail(net.ErrClosed)
	return err
}

func authority(r *http.Request) string {
	h := r.Host
	if h == "" {
		h = r.URL.Host
	}
	if r.URL.Scheme == "https" {
		h = strings.TrimSuffix(h, ":443")
	} else {
		h = strings.TrimSuffix(h, ":80")
	}
	return h
}

func (cc *h2Conn) roundTrip(req *http.Request, fields []Field) (*http.Response, error) {
	ctx := req.Context()
	hasBody := req.Body != nil && req.Body != http.NoBody
	prio := ""
	for _, f := range fields {
		if f.Name == "priority" {
			prio = f.Value
		}
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	cs := &h2Stream{cc: cc, req: req, ready: make(chan struct{})}
	cs.cond = sync.NewCond(&cc.mu)
	if err := ctx.Err(); err != nil {
		cc.unreserve() // the pool's reservation, if any, is not used
		return nil, err
	}

	cc.wmu.Lock()
	cc.mu.Lock()
	if cc.pending > 0 {
		cc.pending--
	} else if !cc.canTakeLocked() {
		err := cc.err
		cc.mu.Unlock()
		cc.wmu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errH2Unprocessed, err)
		}
		return nil, errH2Unprocessed
	}
	if cc.err != nil || cc.goAway {
		cc.mu.Unlock()
		cc.wmu.Unlock()
		return nil, errH2Unprocessed
	}
	cs.id = cc.nextID
	cc.nextID += 2
	cs.sendWin = cc.peerWindow
	cs.localEnd = !hasBody
	cc.streams[cs.id] = cs
	cc.started++
	maxFrame := int(cc.peerMax)
	cc.mu.Unlock()

	cc.hbuf.Reset()
	for _, ph := range cc.p.Pseudo {
		v := ""
		switch ph {
		case ":method":
			v = method
		case ":authority":
			v = authority(req)
		case ":scheme":
			v = req.URL.Scheme
		case ":path":
			v = req.URL.RequestURI()
		}
		cc.henc.WriteField(hpack.HeaderField{Name: ph, Value: v})
	}
	for _, f := range fields {
		cc.henc.WriteField(hpack.HeaderField{Name: f.Name, Value: f.Value})
	}
	block := cc.hbuf.Bytes()
	first := min(len(block), maxFrame-5) // 5 bytes of priority fields
	err := cc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: cs.id, BlockFragment: block[:first],
		EndStream: !hasBody, EndHeaders: first == len(block),
		Priority: http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: Weight(prio)}})
	for off := first; err == nil && off < len(block); off += maxFrame {
		end := min(off+maxFrame, len(block))
		err = cc.fr.WriteContinuation(cs.id, end == len(block), block[off:end])
	}
	if err == nil {
		err = cc.bw.Flush()
	}
	cc.wmu.Unlock()
	if err != nil {
		cc.fail(err)
		return nil, fmt.Errorf("%w: %v", errH2ConnLost, err)
	}

	// Registered under cc.mu once the stream exists; every reader of cs.stop
	// holds cc.mu. A context already done fires abort at once, which resets
	// the stream.
	cc.mu.Lock()
	cs.stop = context.AfterFunc(ctx, func() { cs.abort(ctx.Err(), true) })
	cc.mu.Unlock()

	if hasBody {
		go cs.writeBody(req.Body)
	}
	var timeout <-chan time.Time
	if cc.respHeaderTimeout > 0 {
		t := time.NewTimer(cc.respHeaderTimeout)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case <-cs.ready:
	case <-timeout:
		cs.abort(errH2HeaderTimeout, true)
	}
	cc.mu.Lock()
	resp, herr := cs.resp, cs.headerErr
	cc.mu.Unlock()
	if resp == nil {
		return nil, herr
	}
	return resp, nil
}

// writeBody sends the request body as DATA frames under flow control.
func (cs *h2Stream) writeBody(body io.ReadCloser) {
	defer body.Close()
	cc := cs.cc
	buf := make([]byte, h2PeerMaxFrame)
	for {
		n, rerr := body.Read(buf)
		end := rerr == io.EOF
		data := buf[:n]
		for len(data) > 0 || (end && n == 0) {
			cc.mu.Lock()
			for !cs.closed && !cs.remoteEnd && cc.err == nil && len(data) > 0 && (cs.sendWin <= 0 || cc.sendWindow <= 0) {
				cc.cond.Wait()
			}
			if cs.closed || cs.remoteEnd || cc.err != nil {
				remote := cs.remoteEnd && !cs.closed
				cc.mu.Unlock()
				if remote {
					cc.writeRST(cs.id, http2.ErrCodeNo) // the response is complete; stop the upload
				}
				return
			}
			k := min(int64(len(data)), cs.sendWin, cc.sendWindow, int64(cc.peerMax))
			cs.sendWin -= k
			cc.sendWindow -= k
			last := end && k == int64(len(data))
			if last {
				cs.localEnd = true
			}
			cc.mu.Unlock()
			cc.wmu.Lock()
			err := cc.fr.WriteData(cs.id, last, data[:k])
			if err == nil {
				err = cc.bw.Flush()
			}
			cc.wmu.Unlock()
			if err != nil {
				cc.fail(err)
				return
			}
			data = data[k:]
			if last {
				return
			}
		}
		if rerr != nil && !end {
			cs.abort(fmt.Errorf("signed: request body: %w", rerr), true)
			return
		}
	}
}

func (cc *h2Conn) writeRST(id uint32, code http2.ErrCode) {
	cc.wmu.Lock()
	err := cc.fr.WriteRSTStream(id, code)
	if err == nil {
		err = cc.bw.Flush()
	}
	cc.wmu.Unlock()
	if err != nil {
		cc.fail(err)
	}
}

func (cc *h2Conn) writeWindowUpdates(stream uint32, streamInc, connInc int64) {
	if streamInc == 0 && connInc == 0 {
		return
	}
	cc.wmu.Lock()
	if streamInc > 0 {
		cc.fr.WriteWindowUpdate(stream, uint32(streamInc))
	}
	if connInc > 0 {
		cc.fr.WriteWindowUpdate(0, uint32(connInc))
	}
	err := cc.bw.Flush()
	cc.wmu.Unlock()
	if err != nil {
		cc.fail(err)
	}
}

// removeLocked takes a stream off the connection. Caller holds cc.mu.
func (cc *h2Conn) removeLocked(cs *h2Stream) {
	if cs.closed {
		return
	}
	cs.closed = true
	delete(cc.streams, cs.id)
	if len(cc.streams) == 0 {
		cc.idleSince = time.Now()
	}
	cc.cond.Broadcast()
}

// creditLocked returns consumed bytes to the connection window and reports
// the connection WINDOW_UPDATE to send, if any. Caller holds cc.mu.
func (cc *h2Conn) creditLocked(n int64) int64 {
	cc.recvUnacked += n
	if cc.recvUnacked >= cc.connWindow/2 {
		inc := cc.recvUnacked
		cc.recvUnacked = 0
		return inc
	}
	return 0
}

// abort ends a stream with err, optionally resetting it on the wire.
func (cs *h2Stream) abort(err error, rst bool) {
	cc := cs.cc
	cc.mu.Lock()
	if cs.err != nil || (cs.remoteEnd && cs.buf.Len() == 0 && cs.resp != nil) {
		cc.mu.Unlock()
		return
	}
	wasOpen := !cs.closed
	cs.err = err
	if cs.resp == nil && cs.headerErr == nil {
		cs.headerErr = err
		close(cs.ready)
	}
	connInc := cc.creditLocked(int64(cs.buf.Len()))
	cs.buf.Reset()
	cc.removeLocked(cs)
	cs.cond.Broadcast()
	stop := cs.stop
	cc.mu.Unlock()
	if stop != nil {
		stop()
	}
	if rst && wasOpen && cs.id != 0 && !cs.remoteEnd {
		cc.writeRST(cs.id, http2.ErrCodeCancel)
	}
	cc.writeWindowUpdates(0, 0, connInc)
}

func (cc *h2Conn) fail(err error) {
	cc.mu.Lock()
	if cc.err == nil {
		cc.err = err
	}
	for _, cs := range cc.streams {
		if cs.resp == nil {
			cs.headerErr = fmt.Errorf("%w: %v", errH2ConnLost, err)
			close(cs.ready)
		}
		if cs.err == nil {
			cs.err = fmt.Errorf("signed: connection lost: %w", io.ErrUnexpectedEOF)
		}
		cs.closed = true
		cs.cond.Broadcast()
		if cs.stop != nil {
			go cs.stop()
		}
	}
	clear(cc.streams)
	cc.cond.Broadcast()
	cc.mu.Unlock()
	cc.conn.Close()
}

func (cc *h2Conn) readLoop() {
	for {
		f, err := cc.fr.ReadFrame()
		if err != nil {
			var se http2.StreamError
			if errors.As(err, &se) {
				cc.mu.Lock()
				cs := cc.streams[se.StreamID]
				cc.mu.Unlock()
				if cs != nil {
					cs.abort(fmt.Errorf("signed: stream error: %v", se), true)
				} else {
					cc.writeRST(se.StreamID, se.Code)
				}
				continue
			}
			cc.fail(err)
			return
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			cc.onHeaders(f)
		case *http2.DataFrame:
			cc.onData(f)
		case *http2.SettingsFrame:
			if !f.IsAck() {
				cc.onSettings(f)
			}
		case *http2.WindowUpdateFrame:
			cc.mu.Lock()
			if f.StreamID == 0 {
				cc.sendWindow += int64(f.Increment)
			} else if cs := cc.streams[f.StreamID]; cs != nil {
				cs.sendWin += int64(f.Increment)
			}
			cc.cond.Broadcast()
			cc.mu.Unlock()
		case *http2.PingFrame:
			if !f.IsAck() {
				cc.wmu.Lock()
				if cc.fr.WritePing(true, f.Data) == nil {
					cc.bw.Flush()
				}
				cc.wmu.Unlock()
			}
		case *http2.GoAwayFrame:
			cc.mu.Lock()
			cc.goAway = true
			var refused []*h2Stream
			for id, cs := range cc.streams {
				if id > f.LastStreamID {
					refused = append(refused, cs)
				}
			}
			cc.cond.Broadcast()
			cc.mu.Unlock()
			for _, cs := range refused {
				cs.abort(errH2Unprocessed, false)
			}
		case *http2.RSTStreamFrame:
			cc.mu.Lock()
			cs := cc.streams[f.StreamID]
			cc.mu.Unlock()
			if cs != nil {
				if f.ErrCode == http2.ErrCodeRefusedStream {
					cs.abort(errH2Unprocessed, false)
				} else {
					cs.abort(fmt.Errorf("signed: stream reset by server: %v", f.ErrCode), false)
				}
			}
		case *http2.PushPromiseFrame:
			cc.fail(errors.New("signed: server push after ENABLE_PUSH=0"))
			return
		}
	}
}

func (cc *h2Conn) onSettings(f *http2.SettingsFrame) {
	table, hasTable := uint32(0), false
	cc.mu.Lock()
	f.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingMaxConcurrentStreams:
			cc.maxStreams = s.Val
		case http2.SettingInitialWindowSize:
			delta := int64(s.Val) - cc.peerWindow
			for _, cs := range cc.streams {
				cs.sendWin += delta
			}
			cc.peerWindow = int64(s.Val)
		case http2.SettingMaxFrameSize:
			cc.peerMax = s.Val
		case http2.SettingHeaderTableSize:
			table, hasTable = s.Val, true
		}
		return nil
	})
	cc.cond.Broadcast()
	cc.mu.Unlock()
	cc.wmu.Lock()
	if hasTable {
		cc.henc.SetMaxDynamicTableSizeLimit(table)
	}
	if cc.fr.WriteSettingsAck() == nil {
		cc.bw.Flush()
	}
	cc.wmu.Unlock()
}

func (cc *h2Conn) onHeaders(f *http2.MetaHeadersFrame) {
	cc.mu.Lock()
	cs := cc.streams[f.StreamID]
	cc.mu.Unlock()
	if cs == nil {
		return
	}
	if f.Truncated {
		cs.abort(errH2HeadersTooLarge, true)
		return
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cs.closed {
		return
	}
	if cs.resp != nil { // trailers
		if !f.StreamEnded() {
			go cs.abort(errors.New("signed: trailers without END_STREAM"), true)
			return
		}
		if cs.resp.Trailer == nil {
			cs.resp.Trailer = http.Header{}
		}
		for _, hf := range f.RegularFields() {
			cs.resp.Trailer.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
		}
		cs.remoteEnd = true
		cc.removeLocked(cs)
		cs.cond.Broadcast()
		return
	}
	code, err := strconv.Atoi(f.PseudoValue("status"))
	if err != nil || code < 100 || code > 999 {
		go cs.abort(errors.New("signed: malformed response status"), true)
		return
	}
	if code < 200 {
		return // 1xx informational; the final response follows
	}
	h := make(http.Header, len(f.Fields))
	for _, hf := range f.RegularFields() {
		h.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
	}
	resp := &http.Response{Status: strconv.Itoa(code) + " " + http.StatusText(code), StatusCode: code,
		Proto: "HTTP/2.0", ProtoMajor: 2, Header: h, Request: cs.req, ContentLength: -1}
	for _, v := range h.Values("Trailer") {
		for _, k := range strings.Split(v, ",") {
			if k = http.CanonicalHeaderKey(strings.TrimSpace(k)); k != "" {
				if resp.Trailer == nil {
					resp.Trailer = http.Header{}
				}
				resp.Trailer[k] = nil
			}
		}
	}
	if cl := h.Get("Content-Length"); cl != "" {
		if n, e := strconv.ParseInt(cl, 10, 64); e == nil && n >= 0 {
			resp.ContentLength = n
		}
	}
	if f.StreamEnded() {
		cs.remoteEnd = true
		resp.Body = http.NoBody
		if resp.ContentLength < 0 {
			resp.ContentLength = 0
		}
		cc.removeLocked(cs)
		if cs.stop != nil {
			go cs.stop()
		}
	} else {
		resp.Body = &h2Body{cs: cs}
	}
	if cs.req.Method == http.MethodHead {
		resp.Body = &h2Body{cs: cs, head: true}
	}
	cs.resp = resp
	close(cs.ready)
}

func (cc *h2Conn) onData(f *http2.DataFrame) {
	data := f.Data()
	n := int64(f.Length)
	cc.mu.Lock()
	cs := cc.streams[f.StreamID]
	if cs == nil || cs.resp == nil {
		inc := cc.creditLocked(n)
		cc.mu.Unlock()
		cc.writeWindowUpdates(0, 0, inc)
		return
	}
	cs.buf.Write(data)
	pad := n - int64(len(data))
	connInc := cc.creditLocked(pad)
	cs.unacked += pad
	if f.StreamEnded() {
		cs.remoteEnd = true
		cc.removeLocked(cs)
	}
	cs.cond.Broadcast()
	cc.mu.Unlock()
	cc.writeWindowUpdates(0, 0, connInc)
}

// h2Body streams one response body and returns flow-control credit as the
// caller consumes it.
type h2Body struct {
	cs   *h2Stream
	head bool
	done bool
}

func (b *h2Body) Read(p []byte) (int, error) {
	cs := b.cs
	cc := cs.cc
	cc.mu.Lock()
	if b.head {
		cc.mu.Unlock()
		return 0, io.EOF
	}
	for cs.buf.Len() == 0 && !cs.remoteEnd && cs.err == nil {
		cs.cond.Wait()
	}
	if cs.buf.Len() > 0 {
		n, _ := cs.buf.Read(p)
		connInc := cc.creditLocked(int64(n))
		var streamInc int64
		if !cs.remoteEnd {
			cs.unacked += int64(n)
			if cs.unacked >= cc.recvWindow/2 {
				streamInc, cs.unacked = cs.unacked, 0
			}
		}
		cc.mu.Unlock()
		cc.writeWindowUpdates(cs.id, streamInc, connInc)
		return n, nil
	}
	err := cs.err
	cc.mu.Unlock()
	if err != nil {
		return 0, err
	}
	b.finish()
	return 0, io.EOF
}

func (b *h2Body) finish() {
	if !b.done {
		b.done = true
		b.cs.cc.mu.Lock()
		stop := b.cs.stop
		b.cs.cc.mu.Unlock()
		if stop != nil {
			stop()
		}
	}
}

func (b *h2Body) Close() error {
	cs := b.cs
	cc := cs.cc
	cc.mu.Lock()
	complete := cs.remoteEnd && cs.buf.Len() == 0
	cc.mu.Unlock()
	if !complete {
		cs.abort(errH2BodyClosed, true)
	}
	b.finish()
	return nil
}
