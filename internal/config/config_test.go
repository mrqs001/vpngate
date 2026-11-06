package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFiveHundredIndependentEndpoints(t *testing.T) {
	c := Config{Name: "test"}
	for i := 0; i < 500; i++ {
		c.Tunnels = append(c.Tunnels, Tunnel{ID: fmt.Sprintf("lane-%d", i), Listen: fmt.Sprintf("127.0.0.1:%d", 15000+i), Attach: fmt.Sprintf("ns-%d", i), DNS: []string{"1.1.1.1"}})
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.MaxConnections != 4096 || c.PerTunnel != 512 || c.DownloadMBPS != 0 || c.WorkerThreads != 2 || c.RelayMode != "buffered" {
		t.Fatal("unexpected defaults")
	}
	c.Tunnels = append(c.Tunnels, c.Tunnels[0])
	if c.Validate() == nil {
		t.Fatal("501 tunnels accepted")
	}
}

func TestFetchOnlyConfiguration(t *testing.T) {
	c := Config{Name: "fetch", Fetch: &Fetch{Listen: "127.0.0.1:15400"}, Tunnels: []Tunnel{{ID: "a", Attach: "a", DNS: []string{"1.1.1.1"}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Fetch.InsecureSkipVerify || c.Fetch.MaxInflight != 512 || c.Fetch.MaxAttempts != 3 {
		t.Fatal("fetch defaults")
	}
	c.Tunnels[0].Listen = c.Fetch.Listen
	if c.Validate() == nil {
		t.Fatal("duplicate fetch and proxy listener accepted")
	}
	c.Tunnels[0].Listen = ""
	c.Fetch.Listen = "192.0.2.1:15400"
	if c.Validate() == nil {
		t.Fatal("fetch exposed beyond loopback")
	}
}

func TestConfigRejectsAmbiguityAndUnprotectedListeners(t *testing.T) {
	base := func() Config {
		return Config{Name: "test", Tunnels: []Tunnel{{ID: "a", Listen: "127.0.0.1:15000", Attach: "a", DNS: []string{"1.1.1.1"}}}}
	}
	for _, edit := range []func(*Config){
		func(c *Config) { c.Tunnels[0].Listen = "0.0.0.0:15000" },
		func(c *Config) { c.Tunnels[0].Listen = "192.0.2.1:15000" },
		func(c *Config) { c.Tunnels[0].Listen = "127.0.0.1:8888" },
		func(c *Config) { c.Tunnels[0].WireGuard = "also.conf" },
		func(c *Config) { c.Tunnels[0].DNS = nil },
		func(c *Config) { c.Tunnels[0].DNS = []string{"localhost"} },
		func(c *Config) { c.Tunnels[0].Attach = "../host" },
		func(c *Config) { c.WorkerThreads = 65 },
		func(c *Config) { c.RelayMode = "unknown" },
		func(c *Config) { c.Tunnels[0].Interface = "../../host" },
		func(c *Config) { c.Tunnels = append(c.Tunnels, c.Tunnels[0]) },
	} {
		c := base()
		edit(&c)
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

const profile = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=
Address = 10.17.0.2/32
DNS = 10.17.0.1
[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func TestWireGuardProfileIsDeclarativeAndErrorsRedact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.conf")
	for _, extra := range []string{"", "\nPostUp = secret-must-not-appear", "\nPrivateKey = secret-must-not-appear"} {
		if err := os.WriteFile(path, []byte(profile+extra), 0600); err != nil {
			t.Fatal(err)
		}
		w, err := ReadWireGuard(path)
		if extra == "" {
			if err != nil {
				t.Fatal(err)
			}
			if !w.IPv4() || w.IPv6() || w.MTU != 1420 {
				t.Fatal("profile mismatch")
			}
		} else {
			if err == nil || strings.Contains(err.Error(), "secret-must-not-appear") {
				t.Fatal("unsafe profile validation")
			}
		}
	}
}
