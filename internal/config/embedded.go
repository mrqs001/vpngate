package config

import (
	"errors"
	"net/netip"
)

// EmbeddedWireGuard is a single peer, full-tunnel configuration. Keys use the
// standard WireGuard base64 format. It is never included in Runtime or status.
type EmbeddedWireGuard struct {
	PrivateKey   string   `json:"private_key"`
	PublicKey    string   `json:"peer_public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	Endpoint     string   `json:"endpoint"`
	Addresses    []string `json:"addresses"`
	MTU          int      `json:"mtu,omitempty"`
	Keepalive    int      `json:"persistent_keepalive_seconds,omitempty"`
}

func (w *EmbeddedWireGuard) Validate() error {
	if !key(w.PrivateKey) || !key(w.PublicKey) || w.PresharedKey != "" && !key(w.PresharedKey) {
		return errors.New("wireguard keys must be base64-encoded 32-byte keys")
	}
	endpoint, err := netip.ParseAddrPort(w.Endpoint)
	if err != nil || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().Zone() != "" {
		return errors.New("wireguard endpoint must be an IP literal and nonzero port")
	}
	if len(w.Addresses) < 1 || len(w.Addresses) > 2 {
		return errors.New("wireguard addresses require one address per configured IP family")
	}
	families := map[bool]bool{}
	for _, address := range w.Addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().Is4In6() || families[prefix.Addr().Is6()] {
			return errors.New("wireguard addresses must be unique-family unicast IP prefixes")
		}
		families[prefix.Addr().Is6()] = true
	}
	if w.MTU == 0 {
		w.MTU = 1420
	}
	if w.MTU < 1280 || w.MTU > 9000 || w.Keepalive < 0 || w.Keepalive > 65535 {
		return errors.New("wireguard MTU or keepalive outside supported range")
	}
	return nil
}
