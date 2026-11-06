//go:build linux

// Package health reads kernel state without sending VPN traffic or changing routes.
package health

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

type WireGuard struct {
	Peers               int   `json:"peers"`
	LatestHandshakeUnix int64 `json:"latest_handshake_unix"`
}

type Link struct {
	SampledAt      time.Time  `json:"sampled_at"`
	NamespaceState string     `json:"namespace_state"`
	Interface      string     `json:"interface,omitempty"`
	InterfaceUp    *bool      `json:"interface_up"`
	WireGuard      *WireGuard `json:"wireguard,omitempty"`
	Error          string     `json:"error,omitempty"`
}

type Probe struct {
	names, interfaces []string
	identities        []os.FileInfo
	buffer            []byte
}

func openNamespace(name string) (*os.File, error) {
	fd, err := unix.Open("/var/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "health-namespace"), nil
}

func New(names, interfaces []string) (*Probe, error) {
	if len(names) != len(interfaces) {
		return nil, errors.New("health lane count mismatch")
	}
	host, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	p := &Probe{names: append([]string(nil), names...), interfaces: append([]string(nil), interfaces...), buffer: make([]byte, 64<<10)}
	for _, name := range names {
		f, e := openNamespace(name)
		if e != nil {
			return nil, errors.New("cannot observe lane namespace")
		}
		st, e := f.Stat()
		f.Close()
		if e != nil || os.SameFile(host, st) {
			return nil, errors.New("invalid health namespace")
		}
		p.identities = append(p.identities, st)
	}
	return p, nil
}

// Sample has its own pinned thread, separate from socket creation. Only local
// kernel reads happen here. Missing/replaced namespaces are never followed.
func (p *Probe) Sample(ctx context.Context) []Link {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	home, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
	if err == nil {
		defer home.Close()
	}
	out := make([]Link, len(p.names))
	for i, name := range p.names {
		r := Link{SampledAt: time.Now().UTC(), NamespaceState: "unknown", Interface: p.interfaces[i]}
		out[i] = r
		if err != nil || ctx.Err() != nil {
			out[i].Error = "probe_unavailable"
			continue
		}
		target, e := openNamespace(name)
		if e != nil {
			if os.IsNotExist(e) {
				out[i].NamespaceState = "missing"
			} else {
				out[i].Error = "namespace_unreadable"
			}
			continue
		}
		generation, e := target.Stat()
		if e != nil {
			target.Close()
			out[i].Error = "namespace_unreadable"
			continue
		}
		if !os.SameFile(p.identities[i], generation) {
			target.Close()
			out[i].NamespaceState = "replaced"
			continue
		}
		if e = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); e != nil {
			target.Close()
			out[i].Error = "namespace_unavailable"
			continue
		}
		out[i] = inspectLink(p.interfaces[i], p.buffer)
		if unix.Setns(int(home.Fd()), unix.CLONE_NEWNET) != nil {
			// Never release a thread whose namespace could not be restored.
			panic("cannot restore health-worker namespace")
		}
		target.Close()
	}
	return out
}

func inspectLink(name string, buffer []byte) Link {
	r := Link{SampledAt: time.Now().UTC(), NamespaceState: "present", Interface: name}
	if name == "" {
		r.Error = "interface_not_configured"
		return r
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		r.Error = "interface_unreadable"
		return r
	}
	defer unix.Close(fd)
	request, err := unix.NewIfreq(name)
	if err == nil {
		err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request)
	}
	if err != nil {
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO) {
			r.Error = "interface_missing"
		} else {
			r.Error = "interface_unreadable"
		}
		return r
	}
	up := request.Uint16()&unix.IFF_UP != 0
	r.InterfaceUp = &up
	wg, err := readWireGuard(name, buffer)
	if err == nil {
		r.WireGuard = &wg
	} else if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
		r.Error = "handshake_unreadable"
	}
	return r
}
