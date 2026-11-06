package config

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// WireGuard intentionally accepts a single-peer full-tunnel profile, not wg-quick
// shell hooks. Error messages never contain values or private configuration lines.
type WireGuard struct {
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	Endpoint     string
	Addresses    []netip.Prefix
	DNS          []string
	Allowed      []netip.Prefix
	MTU          int
	Keepalive    int
}

func ReadWireGuard(path string) (WireGuard, error) {
	f, err := os.Open(path)
	if err != nil {
		return WireGuard{}, errors.New("cannot open WireGuard profile")
	}
	defer f.Close()
	if s, err := f.Stat(); err != nil || !s.Mode().IsRegular() || s.Size() > 65536 {
		return WireGuard{}, errors.New("WireGuard profile must be a regular file of at most 64 KiB")
	}
	w := WireGuard{MTU: 1420}
	sc := bufio.NewScanner(f)
	section, seen := "", map[string]bool{}
	for line := 1; sc.Scan(); line++ {
		s := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		if s == "" {
			continue
		}
		fail := func() (WireGuard, error) {
			return WireGuard{}, fmt.Errorf("unsupported or invalid WireGuard setting at line %d", line)
		}
		if strings.HasPrefix(s, "[") {
			if s != "[Interface]" && s != "[Peer]" || seen[s] {
				return fail()
			}
			section = s
			seen[s] = true
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || section == "" || seen[section+k] {
			return fail()
		}
		seen[section+k] = true
		switch section + k {
		case "[Interface]PrivateKey":
			if !key(v) {
				return fail()
			}
			w.PrivateKey = v
		case "[Peer]PublicKey":
			if !key(v) {
				return fail()
			}
			w.PublicKey = v
		case "[Peer]PresharedKey":
			if !key(v) {
				return fail()
			}
			w.PresharedKey = v
		case "[Interface]Address":
			for _, x := range strings.Split(v, ",") {
				p, e := netip.ParsePrefix(strings.TrimSpace(x))
				if e != nil || p.Addr().IsUnspecified() {
					return fail()
				}
				w.Addresses = append(w.Addresses, p)
			}
		case "[Interface]DNS":
			for _, x := range strings.Split(v, ",") {
				x = strings.TrimSpace(x)
				p, e := netip.ParseAddr(x)
				if e != nil || p.IsUnspecified() || p.IsLoopback() || p.IsMulticast() || p.Zone() != "" {
					return fail()
				}
				w.DNS = append(w.DNS, x)
			}
		case "[Peer]AllowedIPs":
			for _, x := range strings.Split(v, ",") {
				p, e := netip.ParsePrefix(strings.TrimSpace(x))
				if e != nil {
					return fail()
				}
				w.Allowed = append(w.Allowed, p.Masked())
			}
		case "[Peer]Endpoint":
			h, p, e := net.SplitHostPort(v)
			n, e2 := strconv.Atoi(p)
			if e != nil || e2 != nil || h == "" || n < 1 || n > 65535 {
				return fail()
			}
			w.Endpoint = v
		case "[Interface]MTU":
			n, e := strconv.Atoi(v)
			if e != nil || n < 1280 || n > 9000 {
				return fail()
			}
			w.MTU = n
		case "[Peer]PersistentKeepalive":
			n, e := strconv.Atoi(v)
			if e != nil || n < 0 || n > 65535 {
				return fail()
			}
			w.Keepalive = n
		default:
			return fail()
		}
	}
	if sc.Err() != nil {
		return WireGuard{}, errors.New("cannot read WireGuard profile")
	}
	if w.PrivateKey == "" || w.PublicKey == "" || w.Endpoint == "" || len(w.Addresses) == 0 {
		return WireGuard{}, errors.New("WireGuard profile is missing required interface/peer settings")
	}
	for _, a := range w.Addresses {
		want := netip.MustParsePrefix("0.0.0.0/0")
		if a.Addr().Is6() {
			want = netip.MustParsePrefix("::/0")
		}
		found := false
		for _, p := range w.Allowed {
			if p == want {
				found = true
			}
		}
		if !found {
			return WireGuard{}, errors.New("each interface address family requires a full-tunnel AllowedIPs route")
		}
	}
	return w, nil
}

func key(s string) bool { b, e := base64.StdEncoding.DecodeString(s); return e == nil && len(b) == 32 }
func (w WireGuard) IPv6() bool {
	for _, a := range w.Addresses {
		if a.Addr().Is6() {
			return true
		}
	}
	return false
}
func (w WireGuard) IPv4() bool {
	for _, a := range w.Addresses {
		if a.Addr().Is4() {
			return true
		}
	}
	return false
}
