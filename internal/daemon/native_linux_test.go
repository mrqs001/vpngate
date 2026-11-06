//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrqs001/vpngate/internal/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func nativeTestPlan(t *testing.T) Plan {
	t.Helper()
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config{Name: "native-test", Fetch: &config.Fetch{Listen: "127.0.0.1:15400"}, Tunnels: []config.Tunnel{{
		ID: "a", DNS: []string{"192.0.2.1"}, Inline: &config.InlineWireGuard{
			PrivateKey: private.String(), PublicKey: peer.PublicKey().String(), PresharedKey: psk.String(),
			Endpoint: "127.0.0.1:51820", Addresses: []string{"192.0.2.2/24", "fd00:1234::2/64"}, MTU: 1380, Keepalive: 25,
		},
	}}}
	p, err := Prepare(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Opt in with VPNGATE_NATIVE_TEST=1. The test re-execs in fresh user, mount
// and network namespaces before it can touch /run or any network resource.
// No ip/wg executable is used by the test or the implementation under test.
func TestNativeNetworkIsolation(t *testing.T) {
	if os.Getenv("VPNGATE_NATIVE_TEST") != "1" {
		t.Skip("set VPNGATE_NATIVE_TEST=1 to test kernel WireGuard in disposable namespaces")
	}
	userNS, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	netNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("VPNGATE_NATIVE_PARENT_USER") == "" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// A root CI launcher may lose access to the runner-owned home directory
		// after entering a user namespace. Inherit this executable like the
		// production worker does, without reopening its parent directories.
		executable, err := os.Open(exe)
		if err != nil {
			t.Fatal(err)
		}
		defer executable.Close()
		cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--net", "--fork", "--kill-child", "/proc/self/fd/3", "-test.run=^TestNativeNetworkIsolation$", "-test.v", "-test.timeout=60s")
		cmd.ExtraFiles = []*os.File{executable}
		cmd.Env = append(os.Environ(), "VPNGATE_NATIVE_PARENT_USER="+userNS, "VPNGATE_NATIVE_PARENT_NET="+netNS)
		output, err := cmd.CombinedOutput()
		t.Logf("%s", output)
		if err != nil {
			t.Fatalf("isolated kernel tests failed: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 || userNS == os.Getenv("VPNGATE_NATIVE_PARENT_USER") || netNS == os.Getenv("VPNGATE_NATIVE_PARENT_NET") {
		t.Fatal("refusing to test outside disposable user/network namespaces")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", 0, "mode=755"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	native := NativeNetwork{}
	t.Run("configuration-and-cleanup", func(t *testing.T) {
		p := nativeTestPlan(t)
		var r Resource
		cleanup, err := p.setup(ctx, native, func(v Resource) error { r = v; return nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := cleanup(); err != nil {
				t.Error(err)
			}
		})
		if r.HostDevice || r.DeviceIndex == 0 || r.NamespaceIno == 0 {
			t.Fatal("incomplete ownership journal")
		}
		if err := inOwnedNamespace(ctx, r, func() error {
			h, err := routeHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			l, err := ownedLink(h, r)
			if err != nil {
				return err
			}
			if l.Attrs().MTU != 1380 || l.Attrs().TxQLen != 1000 || l.Attrs().Flags&1 == 0 {
				return errors.New("link MTU, queue default or up state differs")
			}
			addrs, err := h.AddrList(l, netlink.FAMILY_ALL)
			if err != nil {
				return err
			}
			found := map[string]bool{}
			for _, a := range addrs {
				found[a.IPNet.String()] = true
			}
			if !found["192.0.2.2/24"] || !found["fd00:1234::2/64"] {
				return errors.New("addresses lost host bits or an IP family")
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				routes, err := h.RouteList(l, family)
				if err != nil {
					return err
				}
				found := false
				for _, route := range routes {
					if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0" {
						found = true
						if route.Protocol != unix.RTPROT_BOOT || route.Table != unix.RT_TABLE_MAIN {
							return errors.New("default route differs")
						}
					}
				}
				if !found {
					return errors.New("missing full-tunnel route")
				}
			}
			client, err := wgctrl.New()
			if err != nil {
				return err
			}
			defer client.Close()
			device, err := client.Device(r.Device)
			if err != nil {
				return err
			}
			w := p.Profiles[0]
			if device.PrivateKey.String() != w.PrivateKey || len(device.Peers) != 1 {
				return errors.New("WireGuard identity or peer count differs")
			}
			peer := device.Peers[0]
			if peer.PublicKey.String() != w.PublicKey || peer.PresharedKey.String() != w.PresharedKey || peer.Endpoint.String() != w.Endpoint || peer.PersistentKeepaliveInterval.Seconds() != 25 || len(peer.AllowedIPs) != 2 {
				return errors.New("WireGuard peer configuration differs")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(namespaceRoot, r.Namespace)); !os.IsNotExist(err) {
			t.Fatal("owned namespace remains")
		}
	})
	t.Run("existing-namespace-is-preserved", func(t *testing.T) {
		p := nativeTestPlan(t)
		r := p.Resources[0]
		r.NamespaceDev, r.NamespaceIno, err = native.CreateNamespace(ctx, r.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := native.DeleteNamespace(ctx, r); err != nil {
				t.Error(err)
			}
		})
		if _, err := p.Setup(ctx, native); err == nil {
			t.Fatal("adopted existing namespace")
		}
		fd, err := openOwnedNamespace(r)
		if err != nil {
			t.Fatal("existing namespace was removed")
		}
		unix.Close(fd)
	})
	t.Run("existing-profile-format", func(t *testing.T) {
		p := nativeTestPlan(t)
		w := p.Profiles[0]
		path := filepath.Join(t.TempDir(), "provider.conf")
		profile := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 192.0.2.2/32\nDNS = 192.0.2.1\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0\n", w.PrivateKey, w.PublicKey, w.PresharedKey)
		if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
			t.Fatal(err)
		}
		c := p.Config
		c.Tunnels[0].Inline = nil
		c.Tunnels[0].WireGuard = path
		c.Tunnels[0].DNS = nil
		p, err := Prepare(c)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Config.Tunnels[0].DNS) != 1 || p.Config.Tunnels[0].DNS[0] != "192.0.2.1" {
			t.Fatal("profile DNS not inherited")
		}
		cleanup, err := p.Setup(ctx, native)
		if err != nil {
			t.Fatal(err)
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("existing-interface-is-preserved", func(t *testing.T) {
		p := nativeTestPlan(t)
		h, err := routeHandle()
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		a := netlink.NewLinkAttrs()
		a.Name = p.Resources[0].Device
		foreign := &netlink.Dummy{LinkAttrs: a}
		if err := h.LinkAdd(foreign); err != nil {
			t.Fatal(err)
		}
		defer h.LinkDel(foreign)
		var r Resource
		if _, err := p.setup(ctx, native, func(v Resource) error { r = v; return nil }); err == nil {
			t.Fatal("adopted foreign interface")
		}
		if _, err := h.LinkByName(foreign.Name); err != nil {
			t.Fatal("foreign interface was removed")
		}
		if err := native.DeleteDevice(ctx, r); err != nil {
			t.Fatal("failed-creation recovery blocked by foreign link:", err)
		}
		if _, err := os.Stat(filepath.Join(namespaceRoot, r.Namespace)); !os.IsNotExist(err) {
			t.Fatal("rollback left namespace")
		}
	})
	t.Run("configuration-failure-rolls-back", func(t *testing.T) {
		p := nativeTestPlan(t)
		w := p.Profiles[0]
		w.Addresses = append(w.Addresses, netip.MustParsePrefix("192.0.2.2/24"))
		p.Profiles[0] = w
		if _, err := p.Setup(ctx, native); err == nil {
			t.Fatal("expected duplicate address error")
		}
		if _, err := os.Stat(filepath.Join(namespaceRoot, p.Resources[0].Namespace)); !os.IsNotExist(err) {
			t.Fatal("rollback left namespace")
		}
	})
	t.Run("stale-host-location-recovers", func(t *testing.T) {
		p := nativeTestPlan(t)
		var r Resource
		cleanup, err := p.setup(ctx, native, func(v Resource) error {
			if v.HostDevice {
				r = v
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if err := native.DeleteDevice(ctx, r); err != nil {
			t.Fatal(err)
		}
		if err := native.DeleteNamespace(ctx, r); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("replaced-namespace-is-preserved", func(t *testing.T) {
		p := nativeTestPlan(t)
		var old Resource
		_, err := p.setup(ctx, native, func(v Resource) error { old = v; return nil })
		if err != nil {
			t.Fatal(err)
		}
		// Pin the old inode so the replacement cannot reuse it.
		fd, err := openOwnedNamespace(old)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := native.DeleteDevice(ctx, old); err != nil {
			t.Fatal(err)
		}
		if err := native.DeleteNamespace(ctx, old); err != nil {
			t.Fatal(err)
		}
		replacement := old
		replacement.NamespaceDev, replacement.NamespaceIno, err = native.CreateNamespace(ctx, old.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		defer native.DeleteNamespace(ctx, replacement)
		if err := native.DeleteDevice(ctx, old); !errors.Is(err, errOwnership) {
			t.Fatal("device cleanup entered replaced namespace:", err)
		}
		if err := native.DeleteNamespace(ctx, old); !errors.Is(err, errOwnership) {
			t.Fatal("namespace replacement was not refused:", err)
		}
	})
	t.Run("changed-interface-is-preserved", func(t *testing.T) {
		p := nativeTestPlan(t)
		var r Resource
		_, err := p.setup(ctx, native, func(v Resource) error { r = v; return nil })
		if err != nil {
			t.Fatal(err)
		}
		defer native.DeleteNamespace(ctx, r)
		if err := inOwnedNamespace(ctx, r, func() error {
			h, err := routeHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			l, err := ownedLink(h, r)
			if err != nil {
				return err
			}
			return h.LinkSetAlias(l, "foreign-owner")
		}); err != nil {
			t.Fatal(err)
		}
		if err := native.DeleteDevice(ctx, r); !errors.Is(err, errOwnership) {
			t.Fatal("changed interface ownership was not refused:", err)
		}
	})
	entries, err := os.ReadDir(namespaceRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("namespace leak: %v, %v", entries, err)
	}
	h, err := routeHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	links, err := h.LinkList()
	if err != nil || len(links) != 1 || links[0].Attrs().Name != "lo" {
		t.Fatal("host interface leak", err)
	}
}

func TestOldManagedStateNeedsPreviousCleanup(t *testing.T) {
	_, err := openOwnedNamespace(Resource{Namespace: "vpg-old", Owned: true})
	if err == nil || !strings.Contains(err.Error(), "previous version") {
		t.Fatal("legacy ownership was not refused", err)
	}
}

func TestKernelConfigRedactsInvalidKeys(t *testing.T) {
	p := nativeTestPlan(t)
	w := p.Profiles[0]
	w.PrivateKey = "PRIVATE-SENTINEL"
	_, err := kernelConfig(w, w.Endpoint)
	if err == nil || strings.Contains(err.Error(), w.PrivateKey) {
		t.Fatal("invalid key was accepted or exposed")
	}
}
