//go:build linux

package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

// Network only configures owned resources; it is never used by the traffic path.
type Network interface {
	CreateNamespace(context.Context, string) (uint64, uint64, error)
	CreateDevice(context.Context, string, string) (int, error)
	MoveDevice(context.Context, Resource) error
	Configure(context.Context, Resource, config.WireGuard, string) error
	DeleteDevice(context.Context, Resource) error
	DeleteNamespace(context.Context, Resource) error
}

type Resource struct {
	ID           string `json:"id"`
	Namespace    string `json:"namespace"`
	Device       string `json:"device,omitempty"`
	Owned        bool   `json:"owned"`
	HostDevice   bool   `json:"host_device,omitempty"`
	NamespaceDev uint64 `json:"namespace_dev,omitempty"`
	NamespaceIno uint64 `json:"namespace_ino,omitempty"`
	DeviceIndex  int    `json:"device_index,omitempty"`
	DeviceAlias  string `json:"device_alias,omitempty"`
}
type Plan struct {
	Config    config.Config
	Profiles  map[int]config.WireGuard
	Resources []Resource
}

func Names(instance, lane string) (string, string) {
	h := sha256.Sum256([]byte(instance + "\x00" + lane))
	s := hex.EncodeToString(h[:])
	return "vpg-" + s[:12], "vpg" + s[:10]
}

func Prepare(c config.Config) (Plan, error) {
	p := Plan{Config: c, Profiles: map[int]config.WireGuard{}}
	peers := map[string]bool{}
	for i, t := range c.Tunnels {
		res := Resource{ID: t.ID, Namespace: t.Attach}
		if t.WireGuard != "" || t.Inline != nil {
			var w config.WireGuard
			var err error
			if t.Inline != nil {
				w, err = t.Inline.Profile()
			} else {
				w, err = config.ReadWireGuard(t.WireGuard)
			}
			if err != nil {
				return Plan{}, fmt.Errorf("tunnel %s: %w", t.ID, err)
			}
			if !w.IPv4() {
				return Plan{}, fmt.Errorf("tunnel %s: v1 requires an IPv4 full-tunnel profile", t.ID)
			}
			fingerprint := w.PrivateKey + "\x00" + w.PublicKey
			if peers[fingerprint] {
				return Plan{}, errors.New("duplicate WireGuard identity/peer; use a distinct peer configuration per tunnel")
			}
			peers[fingerprint] = true
			if len(t.DNS) == 0 {
				p.Config.Tunnels[i].DNS = w.DNS
			}
			if len(p.Config.Tunnels[i].DNS) == 0 {
				return Plan{}, fmt.Errorf("tunnel %s: explicit DNS is required", t.ID)
			}
			p.Config.Tunnels[i].IPv6 = w.IPv6()
			for _, s := range p.Config.Tunnels[i].DNS {
				if a, e := netip.ParseAddr(s); e != nil || a.Is6() && !w.IPv6() {
					return Plan{}, fmt.Errorf("tunnel %s: DNS address family is unavailable", t.ID)
				}
			}
			p.Profiles[i] = w
			res.Namespace, res.Device = Names(c.Name, t.ID)
			res.Owned = true
		}
		p.Resources = append(p.Resources, res)
	}
	if err := p.Config.Validate(); err != nil {
		return Plan{}, err
	}
	return p, nil
}

// Setup refuses existing objects and rolls back only resources created by this
// invocation, with namespace identity and interface ownership checks.
func (p Plan) Setup(ctx context.Context, r Network) (func() error, error) {
	return p.setup(ctx, r, nil)
}

func (p Plan) setup(ctx context.Context, r Network, record func(Resource) error) (func() error, error) {
	var undos []func() error
	cleanup := func() error {
		var errs []error
		for i := len(undos) - 1; i >= 0; i-- {
			if err := undos[i](); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	fail := func(err error) (func() error, error) { return nil, errors.Join(err, cleanup()) }
	for i, res := range p.Resources {
		if !res.Owned {
			continue
		}
		w := p.Profiles[i]
		host, port, _ := net.SplitHostPort(w.Endpoint)
		if _, err := netip.ParseAddr(host); err != nil {
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ips, e := net.DefaultResolver.LookupNetIP(resolveCtx, "ip", host)
			cancel()
			if e != nil || len(ips) == 0 {
				return fail(fmt.Errorf("tunnel %s: VPN endpoint bootstrap lookup failed", res.ID))
			}
			host = ips[0].String()
		}
		// Only the VPN server bootstrap is resolved on the host, before the tunnel exists.
		endpoint := net.JoinHostPort(host, port)
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return fail(err)
		}
		res.DeviceAlias = "vpngate:" + hex.EncodeToString(token[:])
		var err error
		res.NamespaceDev, res.NamespaceIno, err = r.CreateNamespace(ctx, res.Namespace)
		if err != nil {
			return fail(fmt.Errorf("tunnel %s: namespace unavailable or already exists: %w", res.ID, err))
		}
		namespaceResource := res
		undos = append(undos, func() error { return r.DeleteNamespace(context.Background(), namespaceResource) })
		if record != nil {
			if err := record(res); err != nil {
				return fail(err)
			}
		}
		res.DeviceIndex, err = r.CreateDevice(ctx, res.Device, res.DeviceAlias)
		if err != nil {
			return fail(fmt.Errorf("tunnel %s: interface unavailable or already exists: %w", res.ID, err))
		}
		res.HostDevice = true
		deviceResource := res
		// DeleteDevice checks both locations, including a crash/failure between
		// the kernel move and its ownership-journal update.
		undos = append(undos, func() error { return r.DeleteDevice(context.Background(), deviceResource) })
		if record != nil {
			if err := record(res); err != nil {
				return fail(err)
			}
		}
		if err := r.MoveDevice(ctx, res); err != nil {
			return fail(err)
		}
		res.HostDevice = false
		if record != nil {
			if err := record(res); err != nil {
				return fail(err)
			}
		}
		if err := r.Configure(ctx, res, w, endpoint); err != nil {
			return fail(fmt.Errorf("tunnel %s: interface configuration failed: %w", res.ID, err))
		}
	}
	return cleanup, nil
}
