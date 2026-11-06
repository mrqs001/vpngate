package netns

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testBroker(t *testing.T) (*Broker, func()) {
	t.Helper()
	parent, child, err := SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- ServeBroker(parent, func(lane, family, kind int) (int, error) {
			if lane != 0 {
				return -1, unix.ENOENT
			}
			return NewSocket(family, kind)
		})
	}()
	b, err := NewBroker(child)
	child.Close()
	if err != nil {
		t.Fatal(err)
	}
	return b, func() {
		b.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("broker did not exit")
		}
	}
}

func TestBrokerTCPAndUDP(t *testing.T) {
	b, close := testBroker(t)
	defer close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		c, e := tcp.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := b.Dial(ctx, 0, "tcp", netip.MustParseAddrPort(tcp.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("TCP round trip: %q %v", buf, err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 32)
		n, a, e := udp.ReadFrom(buf)
		if e == nil {
			udp.WriteTo(buf[:n], a)
		}
	}()
	u, err := b.Dial(ctx, 0, "udp", netip.MustParseAddrPort(udp.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(time.Second))
	u.Write([]byte("dns"))
	n, err := u.Read(buf)
	if err != nil || string(buf[:n]) != "dns" {
		t.Fatalf("UDP round trip: %q %v", buf[:n], err)
	}
}

func TestBrokerErrorsDoNotLeakOrDesynchronize(t *testing.T) {
	b, close := testBroker(t)
	defer close()
	before, _ := os.ReadDir("/proc/self/fd")
	for i := 0; i < 30; i++ {
		if f, e := b.Socket(context.Background(), 99, unix.AF_INET, unix.SOCK_STREAM); e == nil {
			f.Close()
			t.Fatal("unknown lane accepted")
		}
		f, e := b.Socket(context.Background(), 0, unix.AF_INET, unix.SOCK_STREAM)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if f, e := b.Socket(ctx, 0, unix.AF_INET, unix.SOCK_STREAM); e == nil {
			f.Close()
			t.Fatal("canceled request accepted")
		}
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(before)+1 {
		t.Fatalf("descriptor leak: %d -> %d", len(before), len(after))
	}
}

func TestRefusedConnectAndCancellation(t *testing.T) {
	b, close := testBroker(t)
	defer close()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddrPort(l.Addr().String())
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := b.Dial(ctx, 0, "tcp", addr); err == nil {
		c.Close()
		t.Fatal("refused connection succeeded")
	}
}
