package signed

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/signed/signedtest"
	utls "github.com/mrqs001/vpngate/internal/third_party/utls"
)

func plainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// tlsFixture is a TLS 1.3 server with tickets that records each client's
// first record and reports whether the handshake resumed.
type tlsFixture struct {
	addr    string
	roots   *x509.CertPool
	hellos  chan []byte
	resumed chan bool
}

func newTLSFixture(t *testing.T, protos ...string) *tlsFixture {
	t.Helper()
	cert := httptest.NewUnstartedServer(http.NotFoundHandler())
	cert.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(cert.Certificate())
	cfg := cert.TLS.Clone()
	cert.Close()
	cfg.NextProtos = protos
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &tlsFixture{addr: l.Addr().String(), roots: pool, hellos: make(chan []byte, 8), resumed: make(chan bool, 8)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rec := signedtest.NewRecorder(c)
				s := tls.Server(rec, cfg)
				s.SetDeadline(time.Now().Add(5 * time.Second))
				err := s.Handshake()
				f.hellos <- rec.First(t)
				if err != nil {
					f.resumed <- false
					return
				}
				f.resumed <- s.ConnectionState().DidResume
				s.Write([]byte("x")) // after the session tickets
				io.Copy(io.Discard, s)
			}()
		}
	}()
	return f
}

func (f *tlsFixture) dial(t *testing.T, c *tlsConfig) (*utls.UConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialTLS(ctx, plainDial, f.addr, "example.com", Chrome, c)
	if err == nil {
		b := make([]byte, 1)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e := io.ReadFull(conn, b); e != nil { // processes NewSessionTicket
			t.Fatal(e)
		}
	}
	return conn, err
}

func TestDialTLSMatchesChrome155Capture(t *testing.T) {
	f := newTLSFixture(t, "h2", "http/1.1")
	c, err := f.dial(t, &tlsConfig{roots: f.roots, h2: true, cache: utls.NewLRUClientSessionCache(8)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := <-f.hellos
	capture := signedtest.Chrome155Capture(t)
	if a, b := signedtest.JA4(t, got), signedtest.JA4(t, capture); a != b {
		t.Fatalf("JA4 %s, Chrome capture %s", a, b)
	}
	if a, b := signedtest.Summary(t, got), signedtest.Summary(t, capture); a != b {
		t.Fatalf("ClientHello differs from Chrome capture\n got %+v\nwant %+v", a, b)
	}
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("ALPN", c.ConnectionState().NegotiatedProtocol)
	}
}

func TestDialTLSResumptionAddsOnlyPSK(t *testing.T) {
	f := newTLSFixture(t, "h2")
	cfg := &tlsConfig{roots: f.roots, h2: true, cache: utls.NewLRUClientSessionCache(8)}
	c1, err := f.dial(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()
	first := signedtest.Parse(t, <-f.hellos)
	if <-f.resumed {
		t.Fatal("first handshake resumed")
	}
	c2, err := f.dial(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	second := signedtest.Parse(t, <-f.hellos)
	if !<-f.resumed {
		t.Fatal("second handshake did not resume")
	}
	a, b := slices.Sorted(slices.Values(first.Extensions)), slices.Sorted(slices.Values(second.Extensions))
	want := slices.Sorted(slices.Values(append(slices.Clone(first.Extensions), 41)))
	if !slices.Equal(b, want) || slices.Contains(a, 41) {
		t.Fatalf("fresh %v, resumed %v", a, b)
	}
	if second.Extensions[len(second.Extensions)-1] != 41 {
		t.Fatal("pre_shared_key must be the last extension")
	}
}

func TestDialTLSHTTP1OnlyALPN(t *testing.T) {
	f := newTLSFixture(t, "h2", "http/1.1")
	c, err := f.dial(t, &tlsConfig{roots: f.roots, h2: false, cache: utls.NewLRUClientSessionCache(8)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if h := signedtest.Parse(t, <-f.hellos); !slices.Equal(h.ALPN, []string{"http/1.1"}) {
		t.Fatal("ALPN", h.ALPN)
	}
	if c.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatal("negotiated", c.ConnectionState().NegotiatedProtocol)
	}
}

func TestDialTLSCertificateError(t *testing.T) {
	f := newTLSFixture(t, "h2")
	_, err := f.dial(t, &tlsConfig{h2: true}) // system roots do not trust the fixture
	if err == nil || !IsCertificateError(err) {
		t.Fatal("untrusted certificate", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialTLS(ctx, plainDial, f.addr, "wrong.example", Chrome, &tlsConfig{roots: f.roots, h2: true}); err == nil || !IsCertificateError(err) {
		t.Fatal("wrong host name", err)
	}
	if IsCertificateError(io.EOF) {
		t.Fatal("EOF is not a certificate error")
	}
}
