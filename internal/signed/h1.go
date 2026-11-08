package signed

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"
)

// h1Conn sends HTTP/1.1 requests with the profile's header order and case,
// one at a time, and keeps the connection alive between them.
type h1Conn struct {
	conn              net.Conn
	br                *bufio.Reader
	bw                *bufio.Writer
	respHeaderTimeout time.Duration

	mu        sync.Mutex
	ok        bool // no request in flight and the last response allows reuse
	idleSince time.Time
	onIdle    func(*h1Conn) // called when a response body ends cleanly
}

func newH1Conn(c net.Conn) *h1Conn {
	return &h1Conn{conn: c, br: bufio.NewReaderSize(c, 16<<10), bw: bufio.NewWriterSize(c, 16<<10), ok: true, idleSince: time.Now()}
}

func (c *h1Conn) reusable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ok
}

func (c *h1Conn) close() error {
	c.mu.Lock()
	c.ok = false
	c.mu.Unlock()
	return c.conn.Close()
}

func (c *h1Conn) writeHead(req *http.Request, fields []Field, p *Profile) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	bw := c.bw
	bw.WriteString(method + " " + req.URL.RequestURI() + " HTTP/1.1\r\nHost: " + authority(req) + "\r\n")
	byName := make(map[string]string, len(fields))
	for _, f := range fields {
		byName[f.Name] = f.Value
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	if _, ok := byName["content-length"]; !ok {
		switch {
		case hasBody && req.ContentLength > 0:
			byName["content-length"] = strconv.FormatInt(req.ContentLength, 10)
		case !hasBody && !navigation(method):
			byName["content-length"] = "0"
		}
	}
	chunked := hasBody && req.ContentLength <= 0 && byName["content-length"] == ""
	for _, name := range p.H1Order {
		lower := strings.ToLower(name)
		switch {
		case lower == "connection":
			bw.WriteString("Connection: keep-alive\r\n")
			if chunked {
				bw.WriteString("Transfer-Encoding: chunked\r\n")
			}
		default:
			if v, ok := byName[lower]; ok {
				bw.WriteString(name + ": " + v + "\r\n")
			}
		}
		delete(byName, lower)
	}
	delete(byName, "priority") // Chrome sends no priority header over HTTP/1.1
	for _, f := range fields {
		if v, ok := byName[f.Name]; ok {
			bw.WriteString(http.CanonicalHeaderKey(f.Name) + ": " + v + "\r\n")
		}
	}
	bw.WriteString("\r\n")
}

func (c *h1Conn) roundTrip(req *http.Request, fields []Field, p *Profile) (*http.Response, error) {
	c.mu.Lock()
	if !c.ok {
		c.mu.Unlock()
		return nil, errors.New("signed: HTTP/1.1 connection busy or closed")
	}
	c.ok = false
	c.mu.Unlock()
	ctx := req.Context()
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Unix(1, 0)) })
	fail := func(err error) (*http.Response, error) {
		stop()
		c.conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	c.writeHead(req, fields, p)
	if hasBody {
		var err error
		if req.ContentLength > 0 {
			_, err = io.Copy(c.bw, io.LimitReader(req.Body, req.ContentLength))
		} else {
			cw := httputil.NewChunkedWriter(c.bw)
			if _, err = io.Copy(cw, req.Body); err == nil {
				err = cw.Close()
				c.bw.WriteString("\r\n")
			}
		}
		req.Body.Close()
		if err != nil {
			return fail(err)
		}
	}
	if err := c.bw.Flush(); err != nil {
		return fail(err)
	}
	if c.respHeaderTimeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.respHeaderTimeout))
	}
	var resp *http.Response
	for {
		r, err := http.ReadResponse(c.br, req)
		if err != nil {
			return fail(err)
		}
		if r.StatusCode >= 200 || r.StatusCode == http.StatusSwitchingProtocols {
			resp = r
			break
		}
	}
	if c.respHeaderTimeout > 0 {
		c.conn.SetReadDeadline(time.Time{})
	}
	keep := !resp.Close && !req.Close
	body := &h1Body{ReadCloser: resp.Body, c: c, ctx: ctx, stop: stop, keep: keep}
	if resp.Body == http.NoBody { // 204, 304, HEAD: the connection is free now
		body.end(keep)
		return resp, nil
	}
	resp.Body = body
	return resp, nil
}

type h1Body struct {
	io.ReadCloser
	c    *h1Conn
	ctx  context.Context
	stop func() bool
	keep bool
	once sync.Once
}

func (b *h1Body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.end(b.keep)
	} else if err != nil {
		b.end(false)
		if b.ctx.Err() != nil {
			return n, b.ctx.Err()
		}
	}
	return n, err
}

func (b *h1Body) Close() error {
	b.end(false) // a no-op after a clean EOF
	return b.ReadCloser.Close()
}

func (b *h1Body) end(reuse bool) {
	b.once.Do(func() {
		reuse = b.stop() && reuse // a fired deadline poisons the connection
		c := b.c
		if !reuse {
			c.conn.Close()
			return
		}
		c.mu.Lock()
		c.ok = true
		c.idleSince = time.Now()
		onIdle := c.onIdle
		c.mu.Unlock()
		if onIdle != nil {
			onIdle(c)
		}
	})
}
