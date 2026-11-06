package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

func tunnel(t *testing.T, proxy, target string) (*net.TCPConn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", response, err)
	}
	return c.(*net.TCPConn), r
}

func TestRelayLiveCapAndIdleTimeout(t *testing.T) {
	for _, mode := range []string{"buffered", "splice"} {
		t.Run(mode, func(t *testing.T) {
			origin, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			payload := bytes.Repeat([]byte("splice-integrity"), 8192)
			done := make(chan error, 1)
			go func() {
				c, e := origin.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(8 * time.Second))
				for n := 0; n < 2; n++ {
					var command [1]byte
					if _, e = io.ReadFull(c, command[:]); e != nil {
						done <- e
						return
					}
					if _, e = c.Write(payload); e != nil {
						done <- e
						return
					}
				}
				done <- nil
			}()
			g, u := gateway(t, &localSockets{}, []uint16{port(t, origin.Addr().String())}, func(c *config.Runtime) { c.IdleSeconds = 1; c.RelayMode = mode })
			c, r := tunnel(t, u.Host, origin.Addr().String())
			buf := make([]byte, len(payload))
			c.Write([]byte{1})
			if _, err = io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, payload) {
				t.Fatal("unlimited transfer", err)
			}
			g.limiter.Set(.001)
			c.Write([]byte{2})
			c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			var one [1]byte
			if n, e := r.Read(one[:]); n != 0 || e == nil {
				t.Fatal("enabling cap did not affect established splice stream")
			}
			// A deliberate bandwidth wait must not trigger the one-second network idle timeout.
			time.Sleep(1200 * time.Millisecond)
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			g.limiter.Set(0)
			if _, err = io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, payload) {
				t.Fatal("cap release lost data", err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			c.Close()
			g.Close()
			if g.lanes[0].download.Load() != uint64(2*len(payload)) || g.lanes[0].upload.Load() != 2 {
				t.Fatal("inexact byte counters", g.Status())
			}
			wantSplice, wantBuffered := uint64(0), uint64(2)
			if mode == "splice" {
				wantSplice, wantBuffered = 1, 1
			}
			if g.spliceDirections.Load() != wantSplice || g.bufferedDirections.Load() != wantBuffered {
				t.Fatal("TCP relay missed splice", g.Status())
			}

		})
	}
}

func TestSpliceBackpressureHalfCloseAndDescriptorCleanup(t *testing.T) {
	before, _ := os.ReadDir("/proc/self/fd")
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("backpressure-and-half-close"), 1<<18)
	done := make(chan error, 1)
	go func() {
		c, e := origin.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(8 * time.Second))
		b, e := io.ReadAll(c)
		if e != nil || !bytes.Equal(b, payload) {
			done <- fmt.Errorf("upload mismatch: %v", e)
			return
		}
		_, e = c.Write(b)
		done <- e
	}()
	g, u := gateway(t, &localSockets{}, []uint16{port(t, origin.Addr().String())}, func(c *config.Runtime) { c.RelayMode = "splice" })
	c, r := tunnel(t, u.Host, origin.Addr().String())
	c.SetReadBuffer(32 << 10)
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.CloseWrite()
	time.Sleep(100 * time.Millisecond)
	b, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(b, payload) {
		t.Fatal("download mismatch", len(b), err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	c.Close()
	g.Close()
	origin.Close()
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(before) {
		t.Fatalf("descriptor leak %d -> %d", len(before), len(after))
	}
	if g.lanes[0].upload.Load() != uint64(len(payload)) || g.lanes[0].download.Load() != uint64(len(payload)) {
		t.Fatal("partial writes miscounted", g.Status())
	}
}

func TestAdmissionAndUpstreamCounters(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer origin.Close()
	g, u := gateway(t, &localSockets{}, []uint16{port(t, origin.Listener.Addr().String())}, func(c *config.Runtime) { c.MaxConnections = 2; c.PerTunnel = 1 })
	c, _ := tunnel(t, u.Host, origin.Listener.Addr().String())
	cli := client(u)
	defer closeClient(cli)
	resp, err := cli.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || !strings.Contains(string(body), "lane connection limit") || g.lanes[0].rejected.Load() != 1 || g.lanes[0].http5xx.Load() != 0 {
		t.Fatal("local refusal misattributed", g.Status())
	}
	// Keep both accepted client sockets open, then attempt a third.
	extra, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	extra.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err = extra.Read(b[:])
	extra.Close()
	if err == nil || g.rejected.Load() != 1 {
		t.Fatal("global refusal not recorded", g.Status())
	}
	c.Close()
	cli.CloseIdleConnections()
	for deadline := time.Now().Add(time.Second); g.lanes[0].active.Load() != 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	resp, err = cli.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 || g.lanes[0].http5xx.Load() != 1 || g.lanes[0].dialFailures.Load() != 0 {
		t.Fatal("origin 503 misattributed", g.Status())
	}
}
