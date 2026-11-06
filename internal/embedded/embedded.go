// Package embedded runs WireGuard and TCP/IP inside the gateway process. Only
// encrypted UDP and the local HTTP listener use host sockets; no TUN, namespace,
// external command, route modification or privileged helper is needed.
package embedded

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"github.com/mrqs001/vpngate/internal/config"
	"github.com/mrqs001/vpngate/internal/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

type lane struct {
	device *device.Device
	net    *packetStack
}

// Dialer owns all embedded devices. Close is called after gateway handlers stop.
type Dialer struct {
	lanes []lane
	close sync.Once
}

func New(c config.Config) (*Dialer, error) {
	if !c.Embedded() {
		return nil, errors.New("embedded configuration required")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	d := new(Dialer)
	for _, t := range c.Tunnels {
		addresses := make([]netip.Addr, 0, len(t.Embedded.Addresses))
		for _, a := range t.Embedded.Addresses {
			addresses = append(addresses, netip.MustParsePrefix(a).Addr())
		}
		stack, err := newPacketStack(addresses, t.Embedded.MTU)
		if err != nil {
			d.Close()
			return nil, fmt.Errorf("tunnel %s: cannot create embedded TCP/IP stack", t.ID)
		}
		dev := device.NewDevice(stack, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		d.lanes = append(d.lanes, lane{device: dev, net: stack})
		if err := dev.IpcSet(ipcConfig(*t.Embedded)); err != nil {
			d.Close()
			return nil, fmt.Errorf("tunnel %s: cannot configure embedded WireGuard", t.ID)
		}
		if err := dev.Up(); err != nil {
			d.Close()
			return nil, fmt.Errorf("tunnel %s: cannot open WireGuard UDP transport", t.ID)
		}
	}
	return d, nil
}

// ipcConfig is never logged, written to disk, or exposed through status.
func ipcConfig(w config.EmbeddedWireGuard) string {
	keyHex := func(key string) string {
		b, _ := base64.StdEncoding.DecodeString(key) // already validated
		return hex.EncodeToString(b)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\n", keyHex(w.PrivateKey), keyHex(w.PublicKey), w.Endpoint, w.Keepalive)
	if w.PresharedKey != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", keyHex(w.PresharedKey))
	}
	for _, a := range w.Addresses {
		if netip.MustParsePrefix(a).Addr().Is4() {
			b.WriteString("allowed_ip=0.0.0.0/0\n")
		} else {
			b.WriteString("allowed_ip=::/0\n")
		}
	}
	return b.String()
}

func (d *Dialer) Dial(ctx context.Context, index int, network string, address netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if index < 0 || index >= len(d.lanes) {
		return nil, errors.New("unknown embedded lane")
	}
	return d.lanes[index].net.dial(ctx, network, address)
}

func (d *Dialer) Close() {
	d.close.Do(func() {
		for _, l := range d.lanes {
			l.device.Close()
		}
	})
}

// Run is a foreground, unprivileged, single-process alternative to daemon.Run.
func Run(ctx context.Context, c config.Config) error {
	if !c.Embedded() {
		return errors.New("embedded configuration required")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	r, err := c.Runtime()
	if err != nil {
		return err
	}
	listener, err := net.Listen(config.ListenNetwork(c.Fetch.Listen), c.Fetch.Listen)
	if err != nil {
		return errors.New("cannot bind embedded fetch listener")
	}
	defer listener.Close()
	previous := runtime.GOMAXPROCS(c.WorkerThreads)
	defer runtime.GOMAXPROCS(previous)
	d, err := New(c)
	if err != nil {
		return err
	}
	defer d.Close()
	g := proxy.New(r, d)
	defer g.Close()
	listeners := make([]net.Listener, len(c.Tunnels)+1)
	listeners[len(c.Tunnels)] = listener
	if err := g.Start(listeners); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case <-g.Errors():
		return errors.New("embedded fetch listener stopped")
	}
}
