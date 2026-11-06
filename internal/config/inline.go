package config

import (
	"errors"
	"net/netip"
)

// InlineWireGuard allows a complete managed gateway in one JSON file. Keys
// retain WireGuard's usual base64 encoding and never enter Runtime or status.
type InlineWireGuard struct {
	PrivateKey   string   `json:"private_key"`
	PublicKey    string   `json:"peer_public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	Endpoint     string   `json:"endpoint"`
	Addresses    []string `json:"addresses"`
	MTU          int      `json:"mtu,omitempty"`
	Keepalive    int      `json:"persistent_keepalive_seconds,omitempty"`
}

func (c InlineWireGuard) Profile() (WireGuard, error) {
	w := WireGuard{PrivateKey: c.PrivateKey, PublicKey: c.PublicKey, PresharedKey: c.PresharedKey, Endpoint: c.Endpoint, MTU: c.MTU, Keepalive: c.Keepalive}
	if !key(c.PrivateKey) || !key(c.PublicKey) || c.PresharedKey != "" && !key(c.PresharedKey) {
		return WireGuard{}, errors.New("WireGuard keys must be base64-encoded 32-byte keys")
	}
	ep, e := netip.ParseAddrPort(c.Endpoint)
	if e != nil || ep.Port() == 0 || ep.Addr().IsUnspecified() || ep.Addr().IsMulticast() || ep.Addr().Zone() != "" || ep.Addr().Is4In6() {
		return WireGuard{}, errors.New("inline WireGuard endpoint requires an IP literal and nonzero port")
	}
	if len(c.Addresses) < 1 || len(c.Addresses) > 2 {
		return WireGuard{}, errors.New("configure one WireGuard address per IP family")
	}
	families := map[bool]bool{}
	for _, s := range c.Addresses {
		p, e := netip.ParsePrefix(s)
		if e != nil || p.Addr().IsUnspecified() || p.Addr().IsLoopback() || p.Addr().IsMulticast() || p.Addr().Is4In6() || families[p.Addr().Is6()] {
			return WireGuard{}, errors.New("WireGuard addresses require distinct-family unicast prefixes")
		}
		families[p.Addr().Is6()] = true
		w.Addresses = append(w.Addresses, p)
		if p.Addr().Is4() {
			w.Allowed = append(w.Allowed, netip.MustParsePrefix("0.0.0.0/0"))
		} else {
			w.Allowed = append(w.Allowed, netip.MustParsePrefix("::/0"))
		}
	}
	if w.MTU == 0 {
		w.MTU = 1420
	}
	if w.MTU < 1280 || w.MTU > 9000 || w.Keepalive < 0 || w.Keepalive > 65535 {
		return WireGuard{}, errors.New("WireGuard MTU or keepalive outside supported range")
	}
	return w, nil
}
