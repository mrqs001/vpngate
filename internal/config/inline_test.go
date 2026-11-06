package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func inlineConfig() Config {
	return Config{Name: "inline", Fetch: &Fetch{Listen: "127.0.0.1:15400"}, Tunnels: []Tunnel{{ID: "a", DNS: []string{"10.17.0.1"}, Inline: &InlineWireGuard{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=", Endpoint: "192.0.2.1:51820", Addresses: []string{"10.17.0.2/32", "fd17::2/128"},
	}}}}
}

func TestInlineFullTunnelAndRuntimeRedaction(t *testing.T) {
	c := inlineConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	w, err := c.Tunnels[0].Inline.Profile()
	if err != nil {
		t.Fatal(err)
	}
	if !w.IPv4() || !w.IPv6() || w.MTU != 1420 || len(w.Allowed) != 2 || w.Addresses[0].Addr().String() != "10.17.0.2" {
		t.Fatal("inline conversion")
	}
	r, err := c.Runtime()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{w.PrivateKey, w.PublicKey, w.Endpoint} {
		if strings.Contains(string(b), secret) {
			t.Fatal("WireGuard secret in worker runtime")
		}
	}
}

func TestInlineRejectsInvalidSettingsAndRedacts(t *testing.T) {
	for _, edit := range []func(*Config){
		func(c *Config) { c.Tunnels[0].WireGuard = "also.conf" },
		func(c *Config) { c.Tunnels[0].Attach = "also" },
		func(c *Config) { c.Tunnels[0].DNS = nil },
		func(c *Config) { c.Tunnels[0].Inline.PrivateKey = "secret-must-not-appear" },
		func(c *Config) { c.Tunnels[0].Inline.PresharedKey = "secret-must-not-appear" },
		func(c *Config) { c.Tunnels[0].Inline.Endpoint = "secret-must-not-appear:51820" },
		func(c *Config) { c.Tunnels[0].Inline.Endpoint = "192.0.2.1:0" },
		func(c *Config) { c.Tunnels[0].Inline.MTU = 1 },
		func(c *Config) { c.Tunnels[0].Inline.Keepalive = -1 },
		func(c *Config) { c.Tunnels[0].Inline.Addresses = []string{"0.0.0.0/0"} },
		func(c *Config) { c.Tunnels[0].Inline.Addresses = []string{"10.0.0.2/32", "10.0.0.3/32"} },
	} {
		c := inlineConfig()
		edit(&c)
		err := c.Validate()
		if err == nil || strings.Contains(err.Error(), "secret-must-not-appear") {
			t.Fatal("invalid or unredacted configuration", err)
		}
	}
}
