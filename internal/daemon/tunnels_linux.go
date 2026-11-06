//go:build linux

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mrqs001/vpngate/internal/config"
)

type Runner interface {
	Run(context.Context, string, []string, string) error
}
type Commands struct{}

func (Commands) Run(ctx context.Context, program string, args []string, input string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = strings.NewReader(input)
	// wg may echo malformed profile lines. Never return its raw output.
	if cmd.Run() != nil {
		return errors.New("network setup command failed")
	}
	return nil
}

type Resource struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	Device     string `json:"device,omitempty"`
	Owned      bool   `json:"owned"`
	HostDevice bool   `json:"host_device,omitempty"`
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
		if t.WireGuard != "" {
			w, err := config.ReadWireGuard(t.WireGuard)
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

// Setup only touches deterministic names reserved for this instance, refuses
// existing objects, and rolls back only commands that succeeded in this call.
func (p Plan) Setup(ctx context.Context, r Runner) (func() error, error) {
	return p.setup(ctx, r, nil)
}

func (p Plan) setup(ctx context.Context, r Runner, record func(Resource) error) (func() error, error) {
	type undo struct{ args []string }
	var undos []undo
	cleanup := func() error {
		var errs []error
		for i := len(undos) - 1; i >= 0; i-- {
			if err := r.Run(context.Background(), "/usr/bin/ip", undos[i].args, ""); err != nil {
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
		if err := r.Run(ctx, "/usr/bin/ip", []string{"netns", "add", res.Namespace}, ""); err != nil {
			return fail(fmt.Errorf("tunnel %s: namespace unavailable or already exists", res.ID))
		}
		undos = append(undos, undo{[]string{"netns", "delete", res.Namespace}})
		if record != nil {
			if err := record(res); err != nil {
				return fail(err)
			}
		}
		if err := r.Run(ctx, "/usr/bin/ip", []string{"link", "add", res.Device, "type", "wireguard"}, ""); err != nil {
			return fail(fmt.Errorf("tunnel %s: interface unavailable or already exists", res.ID))
		}
		undos = append(undos, undo{[]string{"link", "delete", res.Device}})
		res.HostDevice = true
		if record != nil {
			if err := record(res); err != nil {
				return fail(err)
			}
		}
		if err := r.Run(ctx, "/usr/bin/ip", []string{"link", "set", res.Device, "netns", res.Namespace}, ""); err != nil {
			return fail(err)
		}
		undos[len(undos)-1] = undo{[]string{"-n", res.Namespace, "link", "delete", res.Device}}
		res.HostDevice = false
		if record != nil {
			if err := record(res); err != nil {
				return fail(err)
			}
		}
		commands := [][]string{
			{"netns", "exec", res.Namespace, "/usr/bin/wg", "setconf", res.Device, "/dev/stdin"},
			{"-n", res.Namespace, "link", "set", "lo", "up"},
			{"-n", res.Namespace, "link", "set", res.Device, "mtu", strconv.Itoa(w.MTU), "up"},
		}
		for j, args := range commands {
			input := ""
			if j == 0 {
				input = w.Setconf(endpoint)
			}
			if err := r.Run(ctx, "/usr/bin/ip", args, input); err != nil {
				return fail(fmt.Errorf("tunnel %s: interface setup failed", res.ID))
			}
		}
		for _, address := range w.Addresses {
			if err := r.Run(ctx, "/usr/bin/ip", []string{"-n", res.Namespace, "address", "add", address.String(), "dev", res.Device}, ""); err != nil {
				return fail(err)
			}
		}
		if err := r.Run(ctx, "/usr/bin/ip", []string{"-n", res.Namespace, "route", "add", "default", "dev", res.Device}, ""); err != nil {
			return fail(err)
		}
		if w.IPv6() {
			if err := r.Run(ctx, "/usr/bin/ip", []string{"-n", res.Namespace, "-6", "route", "add", "default", "dev", res.Device}, ""); err != nil {
				return fail(err)
			}
		}
	}
	return cleanup, nil
}
