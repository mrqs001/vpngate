package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
	"github.com/mrqs001/vpngate/internal/netns"
)

func TestWorkerEntrypoint(t *testing.T) {
	if os.Getenv("VPNGATE_TEST_WORKER") != "1" {
		t.Skip("subprocess entrypoint")
	}
	if e := ServeChild(); e != nil {
		t.Fatal(e)
	}
}

func TestUnprivilegedWorkerProcessWithInheritedDescriptors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test verifies an unprivileged worker; run the test suite as a normal user")
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "worker-fixture") }))
	defer origin.Close()
	parent, child, e := netns.SocketPair()
	if e != nil {
		t.Fatal(e)
	}
	defer child.Close()
	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- netns.ServeBroker(parent, func(lane, family, kind int) (int, error) { return netns.NewSocket(family, kind) })
	}()
	defer func() {
		parent.Close()
		select {
		case <-brokerDone:
		case <-time.After(time.Second):
			t.Error("socket helper did not stop")
		}
	}()
	path := filepath.Join(t.TempDir(), "control")
	control, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	cf, e := control.File()
	if e != nil {
		t.Fatal(e)
	}
	defer cf.Close()
	listener, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	lf, e := listener.File()
	if e != nil {
		t.Fatal(e)
	}
	defer lf.Close()
	binary, e := os.Open(os.Args[0])
	if e != nil {
		t.Fatal(e)
	}
	defer binary.Close()
	cmd := exec.Command("/proc/self/fd/5", "-test.run=^TestWorkerEntrypoint$")
	cmd.Env = []string{"VPNGATE_TEST_WORKER=1", "GOMAXPROCS=2"}
	cmd.ExtraFiles = []*os.File{child, cf, binary, lf}
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	child.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case e := <-done:
			if e != nil {
				t.Errorf("worker process failed: %v %s", e, logs.String())
			}
		case <-time.After(4 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("worker shutdown timed out")
		}
	}()
	_, p, _ := net.SplitHostPort(origin.Listener.Addr().String())
	n, _ := strconv.Atoi(p)
	c := config.Runtime{MaxConnections: 8, PerTunnel: 8, ConnectSeconds: 2, IdleSeconds: 2,
		Tunnels: []config.Lane{{ID: "fixture", Ports: []uint16{uint16(n)}}}}
	if e = json.NewEncoder(stdin).Encode(c); e != nil {
		t.Fatal(e)
	}
	stdin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var controlConn net.Conn
	for ctx.Err() == nil {
		controlConn, e = net.DialTimeout("unix", path, 100*time.Millisecond)
		if e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer controlConn.Close()
	controlConn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(controlConn, "{\"op\":\"status\"}\n")
	var status map[string]any
	if e = json.NewDecoder(controlConn).Decode(&status); e != nil {
		t.Fatal("worker readiness", e)
	}
	u, _ := url.Parse("http://" + listener.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	resp, e := client.Get(origin.URL)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || string(b) != "worker-fixture" {
		t.Fatalf("child proxy request: %q %v", b, e)
	}
}
