// Package signedtest holds test helpers for fingerprint checks: a TLS
// ClientHello parser, JA4, and a connection wrapper that records the first
// TLS record a client sends. It is imported only by tests.
package signedtest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Hello is the parsed content of one ClientHello.
type Hello struct {
	Ciphers    []uint16 // non-GREASE, in order
	Extensions []uint16 // non-GREASE, in order
	Groups     []uint16 // non-GREASE
	SigAlgs    []uint16
	ALPN       []string
	ALPS       []string
	Versions   []uint16 // non-GREASE supported_versions
	SNI        string
}

func grease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// HelloSummary is the order-independent part of a ClientHello that a
// fingerprint compares: Chrome permutes extension order per connection.
type HelloSummary struct {
	Ciphers, Extensions, Groups, SigAlgs string
	ALPN, ALPS                           string
}

func list(v []uint16, sorted bool) string {
	if sorted {
		v = slices.Clone(v)
		slices.Sort(v)
	}
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(s, ",")
}

// Summary returns the comparable fields of a ClientHello (record or handshake bytes).
func Summary(t testing.TB, record []byte) HelloSummary {
	h := Parse(t, record)
	return HelloSummary{Ciphers: list(h.Ciphers, false), Extensions: list(h.Extensions, true), Groups: list(h.Groups, false),
		SigAlgs: list(h.SigAlgs, false), ALPN: strings.Join(h.ALPN, ","), ALPS: strings.Join(h.ALPS, ",")}
}

// JA4 computes the FoxIO JA4 fingerprint of a ClientHello over TCP.
func JA4(t testing.TB, record []byte) string {
	h := Parse(t, record)
	version := "00"
	if len(h.Versions) > 0 {
		switch slices.Max(h.Versions) {
		case 0x0304:
			version = "13"
		case 0x0303:
			version = "12"
		}
	}
	sni := "i"
	if h.SNI != "" {
		sni = "d"
	}
	alpn := "00"
	if len(h.ALPN) > 0 && h.ALPN[0] != "" {
		a := h.ALPN[0]
		alpn = string(a[0]) + string(a[len(a)-1])
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", version, sni, min(len(h.Ciphers), 99), min(len(h.Extensions), 99), alpn)
	var exts []uint16
	for _, e := range h.Extensions {
		if e != 0 && e != 16 {
			exts = append(exts, e)
		}
	}
	c := list(exts, true)
	if len(h.SigAlgs) > 0 {
		c += "_" + list(h.SigAlgs, false)
	}
	return a + "_" + hash12(list(h.Ciphers, true)) + "_" + hash12(c)
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

type reader struct {
	t testing.TB
	b []byte
}

func (r *reader) n(k int) []byte {
	if len(r.b) < k {
		r.t.Fatalf("ClientHello truncated: need %d, have %d", k, len(r.b))
	}
	v := r.b[:k]
	r.b = r.b[k:]
	return v
}
func (r *reader) u8() int  { return int(r.n(1)[0]) }
func (r *reader) u16() int { return int(binary.BigEndian.Uint16(r.n(2))) }
func (r *reader) vec16() *reader {
	return &reader{r.t, r.n(r.u16())}
}
func (r *reader) u16s() []uint16 {
	var out []uint16
	for len(r.b) > 0 {
		if v := uint16(r.u16()); !grease(v) {
			out = append(out, v)
		}
	}
	return out
}
func (r *reader) strings8() []string {
	var out []string
	for len(r.b) > 0 {
		out = append(out, string(r.n(r.u8())))
	}
	return out
}

// Parse parses a TLS record holding a ClientHello, or the bare handshake message.
func Parse(t testing.TB, b []byte) Hello {
	t.Helper()
	r := &reader{t, b}
	if len(b) > 5 && b[0] == 22 {
		r.n(5)
	}
	if r.u8() != 1 {
		t.Fatal("not a ClientHello")
	}
	r.n(3)
	r.n(2 + 32)
	r.n(r.u8())
	var h Hello
	h.Ciphers = r.vec16().u16s()
	r.n(r.u8())
	ext := r.vec16()
	for len(ext.b) > 0 {
		typ := uint16(ext.u16())
		body := ext.vec16()
		if grease(typ) {
			continue
		}
		h.Extensions = append(h.Extensions, typ)
		switch typ {
		case 0:
			names := body.vec16()
			names.u8()
			h.SNI = string(names.vec16().b)
		case 10:
			h.Groups = body.vec16().u16s()
		case 13:
			h.SigAlgs = body.vec16().u16s()
		case 16:
			h.ALPN = body.vec16().strings8()
		case 17513, 17613:
			h.ALPS = body.vec16().strings8()
		case 43:
			v := &reader{t, body.n(body.u8())}
			h.Versions = v.u16s()
		}
	}
	return h
}

// Chrome155Capture returns the real Chrome 155 ClientHello record vendored with uTLS.
func Chrome155Capture(t testing.TB) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "third_party", "utls", "testdata", "chrome155_clienthello.hex"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Recorder wraps a server-side connection and keeps the first TLS record
// the client sends.
type Recorder struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	done chan struct{}
}

func NewRecorder(c net.Conn) *Recorder { return &Recorder{Conn: c, done: make(chan struct{})} }

func (r *Recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	select {
	case <-r.done:
	default:
		r.buf = append(r.buf, p[:n]...)
		if len(r.buf) >= 5 && len(r.buf) >= 5+int(binary.BigEndian.Uint16(r.buf[3:5])) {
			r.buf = r.buf[:5+int(binary.BigEndian.Uint16(r.buf[3:5]))]
			close(r.done)
		}
	}
	r.mu.Unlock()
	return n, err
}

// First returns the first record once it has been read completely.
func (r *Recorder) First(t testing.TB) []byte {
	t.Helper()
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.buf)
}
