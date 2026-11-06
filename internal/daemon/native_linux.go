//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NativeNetwork only runs at setup/cleanup. Kernel TCP, WireGuard, namespace
// socket creation and the frontend's data path are unchanged.
type NativeNetwork struct{}

const namespaceRoot = "/run/netns"

var namespaceName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var errOwnership = errors.New("network resource identity changed; cleanup refused")

func namespacePath(name string) (string, error) {
	if !namespaceName.MatchString(name) {
		return "", errors.New("invalid namespace name")
	}
	return filepath.Join(namespaceRoot, name), nil
}

// onThread always restores the calling OS thread before it can rejoin Go's
// scheduler. A failed restore is fatal, just as it is in the socket broker.
func onThread(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origin, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(origin)
	defer func() {
		if unix.Setns(origin, unix.CLONE_NEWNET) != nil {
			panic("cannot restore network setup namespace")
		}
	}()
	return fn()
}

func (NativeNetwork) CreateNamespace(ctx context.Context, name string) (dev, ino uint64, result error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	path, err := namespacePath(name)
	if err != nil {
		return 0, 0, err
	}
	if err = safeDir(namespaceRoot); err != nil {
		return 0, 0, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(fd)
	mounted := false
	defer func() {
		if result != nil {
			if mounted {
				_ = unix.Unmount(path, unix.MNT_DETACH)
			}
			_ = os.Remove(path)
		}
	}()
	result = onThread(func() error {
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
			return err
		}
		dev, ino = uint64(st.Dev), st.Ino
		if err := unix.Mount("/proc/thread-self/ns/net", path, "none", unix.MS_BIND, ""); err != nil {
			return err
		}
		mounted = true
		return nil
	})
	return
}

func openOwnedNamespace(r Resource) (int, error) {
	if r.NamespaceDev == 0 || r.NamespaceIno == 0 {
		return -1, errors.New("state lacks native namespace ownership; use the previous version to recover older managed state")
	}
	path, err := namespacePath(r.Namespace)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if uint64(st.Dev) != r.NamespaceDev || st.Ino != r.NamespaceIno {
		unix.Close(fd)
		return -1, errOwnership
	}
	return fd, nil
}

func inOwnedNamespace(ctx context.Context, r Resource, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := openOwnedNamespace(r)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return onThread(func() error {
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			return err
		}
		return fn()
	})
}

func routeHandle() (*netlink.Handle, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = h.SetSocketTimeout(5 * time.Second); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func ownedLink(h *netlink.Handle, r Resource) (netlink.Link, error) {
	if !strings.HasPrefix(r.DeviceAlias, "vpngate:") || len(r.DeviceAlias) != 40 {
		return nil, errors.New("state lacks native interface ownership")
	}
	l, err := h.LinkByName(r.Device)
	if err != nil {
		return nil, err
	}
	if l.Type() != "wireguard" || l.Attrs().Alias != r.DeviceAlias || r.DeviceIndex != 0 && l.Attrs().Index != r.DeviceIndex {
		return nil, errOwnership
	}
	return l, nil
}

func (NativeNetwork) CreateDevice(ctx context.Context, name, alias string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	h, err := routeHandle()
	if err != nil {
		return 0, err
	}
	defer h.Close()
	a := netlink.NewLinkAttrs()
	a.Name = name
	a.Alias = alias
	l := &netlink.Wireguard{LinkAttrs: a}
	if err = h.LinkAdd(l); err != nil {
		// An ACK can fail after the kernel applied a request. Only our random
		// ownership tag permits rollback; a pre-existing same-name link is safe.
		if own, e := ownedLink(h, Resource{Device: name, DeviceAlias: alias}); e == nil {
			_ = h.LinkDel(own)
		}
		return 0, err
	}
	// Some kernels do not retain IFLA_IFALIAS during WireGuard creation.
	// Set it explicitly after a successful exclusive create, before journaling
	// or moving the interface. Failures here remove this just-created link.
	created, err := h.LinkByName(name)
	if err != nil {
		return 0, err
	}
	if err = h.LinkSetAlias(created, alias); err != nil {
		return 0, errors.Join(err, h.LinkDel(created))
	}
	own, err := ownedLink(h, Resource{Device: name, DeviceAlias: alias, DeviceIndex: created.Attrs().Index})
	if err != nil {
		return 0, err
	}
	return own.Attrs().Index, nil
}

func (NativeNetwork) MoveDevice(ctx context.Context, r Resource) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := openOwnedNamespace(r)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	h, err := routeHandle()
	if err != nil {
		return err
	}
	defer h.Close()
	l, err := ownedLink(h, r)
	if err != nil {
		return err
	}
	return h.LinkSetNsFd(l, fd)
}

func kernelConfig(w config.WireGuard, endpoint string) (wgtypes.Config, error) {
	var out wgtypes.Config
	private, e := wgtypes.ParseKey(w.PrivateKey)
	if e != nil {
		return out, errors.New("invalid WireGuard private key")
	}
	public, e := wgtypes.ParseKey(w.PublicKey)
	if e != nil {
		return out, errors.New("invalid WireGuard peer key")
	}
	ep, e := netip.ParseAddrPort(endpoint)
	if e != nil {
		return out, errors.New("invalid resolved WireGuard endpoint")
	}
	keepalive := time.Duration(w.Keepalive) * time.Second
	peer := wgtypes.PeerConfig{PublicKey: public, Endpoint: net.UDPAddrFromAddrPort(ep), ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &keepalive}
	if w.PresharedKey != "" {
		key, e := wgtypes.ParseKey(w.PresharedKey)
		if e != nil {
			return out, errors.New("invalid WireGuard preshared key")
		}
		peer.PresharedKey = &key
	}
	for _, p := range w.Allowed {
		p = p.Masked()
		peer.AllowedIPs = append(peer.AllowedIPs, net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
	}
	return wgtypes.Config{PrivateKey: &private, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer}}, nil
}

func (NativeNetwork) Configure(ctx context.Context, r Resource, w config.WireGuard, endpoint string) error {
	cfg, err := kernelConfig(w, endpoint)
	if err != nil {
		return err
	}
	return inOwnedNamespace(ctx, r, func() error {
		h, err := routeHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		l, err := ownedLink(h, r)
		if err != nil {
			return err
		}
		client, err := wgctrl.New()
		if err != nil {
			return errors.New("kernel WireGuard control unavailable")
		}
		defer client.Close()
		deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		stop := context.AfterFunc(deadline, func() { client.Close() })
		defer stop()
		if err = client.ConfigureDevice(r.Device, cfg); err != nil {
			return errors.New("kernel WireGuard configuration failed")
		}
		lo, err := h.LinkByName("lo")
		if err != nil {
			return err
		}
		if err = h.LinkSetUp(lo); err != nil {
			return err
		}
		if err = h.LinkSetMTU(l, w.MTU); err != nil {
			return err
		}
		if err = h.LinkSetUp(l); err != nil {
			return err
		}
		for _, p := range w.Addresses {
			if err := ctx.Err(); err != nil {
				return err
			}
			a := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}}
			if err = h.AddrAdd(l, a); err != nil {
				return err
			}
		}
		if err = h.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Scope: netlink.SCOPE_LINK, Protocol: unix.RTPROT_BOOT, Table: unix.RT_TABLE_MAIN}); err != nil {
			return err
		}
		if w.IPv6() {
			if err = h.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Scope: netlink.SCOPE_UNIVERSE, Protocol: unix.RTPROT_BOOT, Table: unix.RT_TABLE_MAIN, Priority: 1024}); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
}

func missingLink(err error) bool {
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing) || errors.Is(err, unix.ENODEV)
}

func (NativeNetwork) DeleteDevice(ctx context.Context, r Resource) error {
	remove := func() error {
		h, err := routeHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		l, err := ownedLink(h, r)
		if missingLink(err) {
			return nil
		}
		if r.DeviceIndex == 0 && errors.Is(err, errOwnership) {
			// Creation was never confirmed. A same-name link without our tag
			// belongs to somebody else; it must not block namespace rollback.
			return nil
		}
		if err != nil {
			return err
		}
		return h.LinkDel(l)
	}
	if err := inOwnedNamespace(ctx, r, remove); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Checking both locations recovers a journal that predates a successful move.
	return remove()
}

func (NativeNetwork) DeleteNamespace(ctx context.Context, r Resource) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := openOwnedNamespace(r)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	path, _ := namespacePath(r.Namespace)
	if err = unix.Unmount(path, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("cannot unmount owned namespace: %w", err)
	}
	return os.Remove(path)
}
