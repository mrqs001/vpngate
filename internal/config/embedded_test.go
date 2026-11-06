package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func embeddedConfig() Config {
	return Config{Name: "embedded", Fetch: &Fetch{Listen: "127.0.0.1:15400"}, Tunnels: []Tunnel{{
		ID: "a", DNS: []string{"10.17.0.1"}, Embedded: &EmbeddedWireGuard{
			PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
			PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=",
			Addresses:  []string{"10.17.0.2/32"}, Endpoint: "192.0.2.1:51820",
		},
	}}}
}

func TestEmbeddedConfigAndRuntimeRedaction(t *testing.T) {
	c := embeddedConfig()
	c.Tunnels[0].Embedded.Addresses = append(c.Tunnels[0].Embedded.Addresses, "fd00::2/128")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Embedded() || !c.Tunnels[0].IPv6 || c.RunAs != "" || c.Tunnels[0].Embedded.MTU != 1420 {
		t.Fatal("embedded defaults")
	}
	r, err := c.Runtime()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{c.Tunnels[0].Embedded.PrivateKey, c.Tunnels[0].Embedded.PublicKey, c.Tunnels[0].Embedded.Endpoint} {
		if strings.Contains(string(b), secret) {
			t.Fatal("WireGuard configuration in runtime")
		}
	}
}

func TestEmbeddedRejectsAmbiguityAndInvalidSettings(t *testing.T) {
	t.Run("duplicate-peer", func(t *testing.T) {
		c := embeddedConfig()
		other := c.Tunnels[0]
		other.ID = "b"
		c.Tunnels = append(c.Tunnels, other)
		if c.Validate() == nil {
			t.Fatal("duplicate peer identity accepted")
		}
	})
	for _, edit := range []func(*Config){
		func(c *Config) { c.Tunnels[0].Attach = "ns" },
		func(c *Config) { c.Tunnels[0].WireGuard = "profile.conf" },
		func(c *Config) {
			c.Tunnels = append(c.Tunnels, Tunnel{ID: "b", Attach: "ns", DNS: []string{"1.1.1.1"}})
		},
		func(c *Config) { c.Tunnels[0].DNS = nil },
		func(c *Config) { c.Tunnels[0].Embedded.PrivateKey = "secret-must-not-appear" },
		func(c *Config) { c.Tunnels[0].Embedded.Endpoint = "secret-must-not-appear:51820" },
		func(c *Config) { c.Tunnels[0].Embedded.Addresses = []string{"0.0.0.0/0"} },
		func(c *Config) { c.Tunnels[0].Embedded.Addresses = []string{"10.0.0.2/32", "10.0.0.3/32"} },
		func(c *Config) { c.Tunnels[0].Embedded.MTU = 100 },
		func(c *Config) { c.Tunnels[0].Embedded.Keepalive = -1 },
		func(c *Config) { c.Tunnels[0].Listen = "127.0.0.1:15401" },
		func(c *Config) { c.Fetch = nil },
		func(c *Config) { c.PublicStatus = true },
		func(c *Config) { c.RunAs = "nobody" },
		func(c *Config) { c.RelayMode = "splice" },
	} {
		c := embeddedConfig()
		edit(&c)
		err := c.Validate()
		if err == nil || strings.Contains(err.Error(), "secret-must-not-appear") {
			t.Fatal("invalid or unredacted embedded config", err)
		}
	}
}
