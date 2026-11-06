package embedded

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mrqs001/vpngate/internal/config"
	"github.com/mrqs001/vpngate/internal/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A real encrypted WireGuard peer, using only unprivileged UDP sockets. No host
// routes or provider credentials participate in this test.
func peer(t *testing.T) (*netstack.Net, config.Tunnel) {
	t.Helper()
	serverKey, clientKey := newKey(t), newKey(t)
	tun, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("fd77::1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	if err = dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=10.77.0.2/32\nallowed_ip=fd77::2/128\n", hex.EncodeToString(serverKey.Bytes()), hex.EncodeToString(clientKey.PublicKey().Bytes()))); err != nil {
		t.Fatal("peer configuration")
	}
	if err = dev.Up(); err != nil {
		t.Fatal(err)
	}
	// Never log IpcGet: it contains private keys.
	snapshot, err := dev.IpcGet()
	if err != nil {
		t.Fatal("peer port lookup")
	}
	port := ""
	for _, line := range strings.Split(snapshot, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatal("peer has no UDP port")
	}
	return stack, config.Tunnel{ID: "a", DNS: []string{"10.77.0.1"}, Ports: []uint16{18443, 18080}, Embedded: &config.EmbeddedWireGuard{
		PrivateKey: base64.StdEncoding.EncodeToString(clientKey.Bytes()), PublicKey: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		Endpoint: net.JoinHostPort("127.0.0.1", port), Addresses: []string{"10.77.0.2/32", "fd77::2/128"},
	}}
}

func TestEncryptedFetchDNSHTTP2AndFailClosed(t *testing.T) {
	stack, tunnel := peer(t)
	// Generate a short-lived trust root for this test process only.
	key, err := tls.X509KeyPair(testCertificate(t))
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: key.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certFile)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	var dnsQueries atomic.Int64
	dnsHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		dnsQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.77.0.1")})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("fd77::1")})
			}
		}
		_ = w.WriteMsg(m)
	})
	udp, err := stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{PacketConn: udp, Handler: dnsHandler}
	go dnsServer.ActivateAndServe()
	t.Cleanup(func() { dnsServer.Shutdown() })
	listener, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:18443"))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("encrypted-payload"), 4096)
	var connections atomic.Int64
	server := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{key}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Protocol", r.Proto)
		w.Write(body)
	}), ConnState: func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			connections.Add(1)
		}
	}}
	go server.ServeTLS(listener, "", "")
	t.Cleanup(func() { server.Close() })
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Name: "test", Fetch: &config.Fetch{Listen: l.Addr().String(), MaxAttempts: 1, TimeoutSeconds: 3}, Tunnels: []config.Tunnel{tunnel}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	r, _ := cfg.Runtime()
	g := proxy.New(r, d)
	t.Cleanup(g.Close)
	if err := g.Start([]net.Listener{nil, l}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	fetch := func(target string) (*http.Response, []byte, error) {
		req, _ := http.NewRequest("GET", "http://"+l.Addr().String()+"/fetch", nil)
		req.Header.Set("Vpngate-Target", target)
		res, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		b, e := io.ReadAll(res.Body)
		res.Body.Close()
		return res, b, e
	}
	for i := 0; i < 8; i++ {
		res, b, err := fetch("https://fixture.test:18443/data")
		if err != nil || res.StatusCode != 200 || !bytes.Equal(body, b) || res.Header.Get("X-Upstream-Protocol") != "HTTP/2.0" {
			t.Fatalf("encrypted fetch failed: response=%v error=%v", res, err)
		}
	}
	if connections.Load() != 1 || dnsQueries.Load() != 2 {
		t.Fatal("connections or DNS not pooled", connections.Load(), dnsQueries.Load())
	}
	res, _, err := fetch("https://wrong-host.test:18443/data")
	if err != nil || res.StatusCode != 502 {
		t.Fatal("invalid TLS hostname accepted")
	}
	// The host has this listener, but it must be unreachable through an embedded
	// socket. A fallback to net.Dial would accidentally reach it.
	trap, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer trap.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	x, err := d.Dial(ctx, 0, "tcp", netip.MustParseAddrPort(trap.Addr().String()))
	if err == nil {
		x.Close()
		t.Fatal("escaped embedded tunnel to host listener")
	}
	trap.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if escaped, e := trap.Accept(); e == nil {
		escaped.Close()
		t.Fatal("host fallback")
	}
	// A pending dial must cancel promptly, including before its first handshake.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, e := d.Dial(ctx2, 0, "tcp", netip.MustParseAddrPort("10.77.0.99:443")); e != context.Canceled {
		t.Fatal("cancellation not propagated", e)
	}
	// Active requests and device teardown must not race or hang.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); fetch("https://fixture.test:18443/data") }()
	}
	g.Close()
	wg.Wait()
	d.Close()
	d.Close()
}

func TestIPv6AndIndependentLanes(t *testing.T) {
	cfg := config.Config{Name: "test", Fetch: &config.Fetch{Listen: "127.0.0.1:15400"}}
	for i := 0; i < 2; i++ {
		stack, tunnel := peer(t)
		tunnel.ID = "lane-" + strconv.Itoa(i)
		cfg.Tunnels = append(cfg.Tunnels, tunnel)
		l, e := stack.ListenTCPAddrPort(netip.MustParseAddrPort("[fd77::1]:18080"))
		if e != nil {
			t.Fatal(e)
		}
		s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tunnel.ID) })}
		go s.Serve(l)
		t.Cleanup(func() { s.Close() })
	}
	d, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(d.Close)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, e := d.Dial(ctx, i, "tcp", netip.MustParseAddrPort("[fd77::1]:18080"))
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(c, "GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n")
		b, e := io.ReadAll(c)
		c.Close()
		if e != nil || !strings.HasSuffix(string(b), cfg.Tunnels[i].ID) {
			t.Fatal("lane identity or IPv6 failed", e)
		}
	}
}

func testCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	// Ed25519 keeps fixture generation cheap and independent of system tooling.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"fixture.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
}
