package proxy

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mrqs001/vpngate/internal/config"
)

type dnsSockets struct {
	mu       sync.Mutex
	udp, tcp string
	seen     []string
	lanes    []int
}

func (d *dnsSockets) Dial(ctx context.Context, lane int, network string, a netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.seen = append(d.seen, network+" "+a.String())
	d.lanes = append(d.lanes, lane)
	d.mu.Unlock()
	target := d.udp
	if network == "tcp" {
		target = d.tcp
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}
func TestLaneDNSCacheAndTCPFallback(t *testing.T) {
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	tcp, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		u.Close()
		t.Fatal(e)
	}
	udpServer := &dns.Server{PacketConn: u, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Truncated = true
		w.WriteMsg(r)
	})}
	tcpServer := &dns.Server{Listener: tcp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "canonical.test."},
			&dns.A{Hdr: dns.RR_Header{Name: "canonical.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.42")},
			&dns.A{Hdr: dns.RR_Header{Name: "unrelated.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.99")},
		}
		w.WriteMsg(r)
	})}
	go udpServer.ActivateAndServe()
	go tcpServer.ActivateAndServe()
	defer udpServer.Shutdown()
	defer tcpServer.Shutdown()
	s := &dnsSockets{udp: u.LocalAddr().String(), tcp: tcp.Addr().String()}
	r := NewResolver(s)
	c := config.Lane{DNS: []string{"192.0.2.53"}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, lane := range []int{0, 0, 1} {
		ips, e := r.Resolve(ctx, lane, c, "example.test")
		if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.42" {
			t.Fatalf("DNS result: %v %v", ips, e)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.seen) != 4 {
		t.Fatalf("cache or TCP fallback failed: %v", s.seen)
	}
	for i, v := range s.seen {
		if v != "udp 192.0.2.53:53" && v != "tcp 192.0.2.53:53" {
			t.Fatal("used host DNS", v)
		}
		if s.lanes[i] != i/2 {
			t.Fatal("cross-lane DNS cache/lookup")
		}
	}
}

func TestLimiterCancellation(t *testing.T) {
	l := NewLimiter(.000001)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if l.Wait(ctx, 100) == nil {
		t.Fatal("canceled limiter wait succeeded")
	}
	if !l.Set(0) || l.Wait(context.Background(), 1<<20) != nil {
		t.Fatal("unlimited mode failed")
	}
}

func TestDNSCoalescesWithoutSharingCallerCancellation(t *testing.T) {
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	started, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	server := &dns.Server{PacketConn: u, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.42")}}
		w.WriteMsg(r)
	})}
	go server.ActivateAndServe()
	defer func() { unblock(); server.Shutdown() }()
	s := &dnsSockets{udp: u.LocalAddr().String()}
	r := NewResolver(s)
	defer r.Close()
	c := config.Lane{DNS: []string{"192.0.2.53"}}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, e := r.Resolve(ctx, 0, c, "shared.test"); first <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS exchange did not start")
	}
	second := make(chan error, 1)
	go func() { _, e := r.Resolve(context.Background(), 0, c, "shared.test"); second <- e }()
	cancel()
	if e := <-first; e == nil {
		t.Fatal("canceled caller returned a result")
	}
	unblock()
	select {
	case e := <-second:
		if e != nil {
			t.Fatal("one caller canceled the shared lookup", e)
		}
	case <-time.After(time.Second):
		t.Fatal("shared lookup did not complete")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.seen) != 1 {
		t.Fatalf("duplicate DNS queries: %d", len(s.seen))
	}
}

func TestDNSRetriesLostUDPReplyWithinLane(t *testing.T) {
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	queries := 0
	server := &dns.Server{PacketConn: u, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		mu.Lock()
		queries++
		n := queries
		mu.Unlock()
		if n == 1 {
			return
		}
		response := new(dns.Msg)
		response.SetReply(q)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.42")}}
		w.WriteMsg(response)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	sockets := &dnsSockets{udp: u.LocalAddr().String()}
	resolver := NewResolver(sockets)
	defer resolver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, e := resolver.Resolve(ctx, 4, config.Lane{DNS: []string{"192.0.2.53"}}, "retry.test")
	if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.42" {
		t.Fatal("lost DNS packet failed lookup", ips, e)
	}
	sockets.mu.Lock()
	defer sockets.mu.Unlock()
	if len(sockets.lanes) != 2 || sockets.lanes[0] != 4 || sockets.lanes[1] != 4 {
		t.Fatal("retry left lane or did not happen", sockets.lanes)
	}
}
