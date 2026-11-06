package daemon

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestReadinessNotification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	c, e := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if e = notifyReady(); e != nil {
		t.Fatal(e)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	n, _, e := c.ReadFromUnix(b)
	if e != nil || string(b[:n]) != "READY=1" {
		t.Fatal("incorrect readiness notification", string(b[:n]), e)
	}
	t.Setenv("NOTIFY_SOCKET", path+"-missing")
	if notifyReady() == nil {
		t.Fatal("missing manager socket accepted")
	}
}
