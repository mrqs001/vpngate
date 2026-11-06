package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type Config struct {
	Fetch          *Fetch   `json:"fetch,omitempty"`
	Name           string   `json:"name"`
	PublicStatus   bool     `json:"public_status,omitempty"`
	RunAs          string   `json:"run_as,omitempty"`
	WorkerThreads  int      `json:"worker_threads,omitempty"`
	RelayMode      string   `json:"relay_mode,omitempty"`
	MaxConnections int      `json:"max_connections,omitempty"`
	PerTunnel      int      `json:"per_tunnel_connections,omitempty"`
	DownloadMBPS   float64  `json:"download_mbps,omitempty"`
	ConnectSeconds int      `json:"connect_timeout_seconds,omitempty"`
	IdleSeconds    int      `json:"idle_timeout_seconds,omitempty"`
	Username       string   `json:"username,omitempty"`
	PasswordEnv    string   `json:"password_env,omitempty"`
	Tunnels        []Tunnel `json:"tunnels"`
}

// Fetch is an optional request-aware endpoint. A tunnel's fixed proxy listener
// may be omitted when Fetch is configured. Zero values select bounded defaults.
type Fetch struct {
	Listen                string   `json:"listen"`
	MaxInflight           int      `json:"max_inflight,omitempty"`
	MaxPending            int      `json:"max_pending,omitempty"`
	InitialPerTunnel      int      `json:"initial_per_tunnel,omitempty"`
	TimeoutSeconds        int      `json:"timeout_seconds,omitempty"`
	MaxAttempts           int      `json:"max_attempts,omitempty"`
	HTTP2                 *bool    `json:"http2,omitempty"`
	InsecureSkipVerify    bool     `json:"insecure_skip_verify,omitempty"`
	RetryForbiddenOrigins []string `json:"retry_forbidden_origins,omitempty"`
}

func (f *Fetch) UseHTTP2() bool { return f.HTTP2 == nil || *f.HTTP2 }

func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("invalid origin")
	}
	p := u.Port()
	if p == "" {
		p = "80"
		if u.Scheme == "https" {
			p = "443"
		}
	}
	n, e := strconv.ParseUint(p, 10, 16)
	if e != nil || n == 0 {
		return "", errors.New("invalid origin port")
	}
	return u.Scheme + "://" + strings.ToLower(net.JoinHostPort(u.Hostname(), strconv.Itoa(int(n)))), nil
}

type Tunnel struct {
	ID        string           `json:"id"`
	Listen    string           `json:"listen"`
	WireGuard string           `json:"wireguard_config,omitempty"`
	Inline    *InlineWireGuard `json:"wireguard,omitempty"`
	// Attach is deliberately explicit: an attached namespace is never configured or deleted.
	Attach    string   `json:"attach_namespace,omitempty"`
	Interface string   `json:"outbound_interface,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	IPv6      bool     `json:"ipv6,omitempty"`
	Ports     []uint16 `json:"allowed_ports,omitempty"`
}

// Runtime is sent over an inherited pipe to the unprivileged child. VPN keys and
// configuration paths are intentionally absent. Never serialize it into logs/state.
type Runtime struct {
	Fetch          *Fetch
	RelayMode      string
	MaxConnections int
	PerTunnel      int
	DownloadMBPS   float64
	ConnectSeconds int
	IdleSeconds    int
	Username       string
	Password       string
	Tunnels        []Lane
}

type Lane struct {
	ID     string
	Listen string
	DNS    []string
	IPv6   bool
	Ports  []uint16
}

func Load(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open gateway configuration")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 2<<20))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, errors.New("invalid gateway JSON (unknown fields are rejected)")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("gateway configuration must contain one JSON object")
	}
	if err = c.Validate(); err != nil {
		return c, err
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if t.WireGuard != "" && !filepath.IsAbs(t.WireGuard) {
			t.WireGuard = filepath.Join(base, t.WireGuard)
		}
	}
	return c, nil
}

func (c *Config) Validate() error {
	if !identifier.MatchString(c.Name) {
		return errors.New("name must be a short lowercase identifier")
	}
	if len(c.Tunnels) < 1 || len(c.Tunnels) > 500 {
		return errors.New("configure between 1 and 500 tunnels")
	}
	if c.RunAs == "" {
		c.RunAs = "nobody"
	}
	if c.WorkerThreads == 0 {
		c.WorkerThreads = 2
	}
	if c.WorkerThreads < 1 || c.WorkerThreads > 64 {
		return errors.New("worker_threads must be between 1 and 64")
	}
	if c.RelayMode == "" {
		c.RelayMode = "buffered"
	}
	if c.RelayMode != "buffered" && c.RelayMode != "splice" {
		return errors.New("relay_mode must be buffered or splice")
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 4096
	}
	if c.PerTunnel == 0 {
		c.PerTunnel = min(512, c.MaxConnections)
	}
	if c.ConnectSeconds == 0 {
		c.ConnectSeconds = 10
	}
	if c.IdleSeconds == 0 {
		c.IdleSeconds = 600
	}
	if c.MaxConnections < 1 || c.MaxConnections > 65536 || c.PerTunnel < 1 || c.PerTunnel > c.MaxConnections {
		return errors.New("invalid connection limits (per-tunnel limit must not exceed global limit)")
	}
	if !ValidRate(c.DownloadMBPS) {
		return errors.New("invalid download_mbps (0 is unlimited)")
	}
	if c.ConnectSeconds < 1 || c.ConnectSeconds > 120 || c.IdleSeconds < 1 || c.IdleSeconds > 86400 {
		return errors.New("timeouts outside supported range")
	}
	if (c.Username == "") != (c.PasswordEnv == "") {
		return errors.New("username and password_env must be supplied together")
	}
	ids, listeners, namespaces := map[string]bool{}, map[string]bool{}, map[string]bool{}
	if f := c.Fetch; f != nil {
		a, err := netip.ParseAddrPort(f.Listen)
		if err != nil || !a.Addr().IsLoopback() || a.Port() < 1024 || a.Port() >= 8000 && a.Port() <= 8999 {
			return errors.New("fetch.listen must be an explicit loopback IP and port >=1024 outside 8000–8999")
		}
		listeners[a.String()] = true
		if f.MaxInflight == 0 {
			f.MaxInflight = min(512, c.MaxConnections)
		}
		if f.MaxPending == 0 {
			f.MaxPending = 1024
		}
		if f.InitialPerTunnel == 0 {
			f.InitialPerTunnel = min(32, c.PerTunnel)
		}
		if f.TimeoutSeconds == 0 {
			f.TimeoutSeconds = 30
		}
		if f.MaxAttempts == 0 {
			f.MaxAttempts = 3
		}
		if f.MaxInflight < 1 || f.MaxInflight > c.MaxConnections || f.MaxPending < 1 || f.MaxPending > 65536 || f.InitialPerTunnel < 1 || f.InitialPerTunnel > c.PerTunnel || f.TimeoutSeconds < 1 || f.TimeoutSeconds > 3600 || f.MaxAttempts < 1 || f.MaxAttempts > 5 {
			return errors.New("fetch limits outside supported range")
		}
		if len(f.RetryForbiddenOrigins) > 128 {
			return errors.New("too many fetch origin policies")
		}
		for i, origin := range f.RetryForbiddenOrigins {
			normalized, err := CanonicalOrigin(origin)
			if err != nil {
				return errors.New("retry_forbidden_origins must contain http(s) origins without paths or credentials")
			}
			f.RetryForbiddenOrigins[i] = normalized
		}
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if !identifier.MatchString(t.ID) || ids[t.ID] {
			return fmt.Errorf("tunnel %d: invalid or duplicate id", i)
		}
		ids[t.ID] = true
		if t.Listen != "" || c.Fetch == nil {
			a, err := netip.ParseAddrPort(t.Listen)
			if err != nil || a.Port() < 1024 || a.Port() >= 8000 && a.Port() <= 8999 || a.Addr().IsUnspecified() {
				return fmt.Errorf("tunnel %s: use an explicit listen IP and port >=1024 outside 8000–8999", t.ID)
			}
			if listeners[a.String()] {
				return fmt.Errorf("tunnel %s: duplicate listen endpoint", t.ID)
			}
			listeners[a.String()] = true
			if !a.Addr().IsLoopback() && c.Username == "" {
				return errors.New("non-loopback listeners require proxy authentication")
			}
		}
		modes := 0
		if t.WireGuard != "" {
			modes++
		}
		if t.Inline != nil {
			modes++
		}
		if t.Attach != "" {
			modes++
		}
		if modes != 1 {
			return fmt.Errorf("tunnel %s: specify exactly one of wireguard, wireguard_config or attach_namespace", t.ID)
		}
		if t.Inline != nil {
			if _, err := t.Inline.Profile(); err != nil {
				return fmt.Errorf("tunnel %s: %w", t.ID, err)
			}
			if len(t.DNS) == 0 {
				return fmt.Errorf("tunnel %s: inline WireGuard requires explicit DNS", t.ID)
			}
		}
		if t.Attach != "" {
			if !identifier.MatchString(t.Attach) || namespaces[t.Attach] {
				return fmt.Errorf("tunnel %s: invalid or duplicate attached namespace", t.ID)
			}
			namespaces[t.Attach] = true
			if len(t.DNS) == 0 {
				return fmt.Errorf("tunnel %s: attached namespaces require explicit DNS", t.ID)
			}
		}
		if t.Interface != "" && (!interfaceName.MatchString(t.Interface) || t.Attach == "") {
			return errors.New("outbound_interface must name an interface inside an attached namespace; managed tunnels select their own")
		}
		if len(t.DNS) > 4 || len(t.Ports) > 64 {
			return fmt.Errorf("tunnel %s: at most four DNS servers and 64 destination ports", t.ID)
		}
		for _, s := range t.DNS {
			ip, err := netip.ParseAddr(s)
			if err != nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.Zone() != "" {
				return fmt.Errorf("tunnel %s: DNS must be a non-loopback IP literal", t.ID)
			}
		}
		if len(t.Ports) == 0 {
			t.Ports = []uint16{80, 443}
		}
		for _, p := range t.Ports {
			if p == 0 {
				return errors.New("destination port zero is invalid")
			}
		}
	}
	return nil
}

func ValidRate(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1e6 }

func (c Config) Runtime() (Runtime, error) {
	r := Runtime{Fetch: c.Fetch, RelayMode: c.RelayMode, MaxConnections: c.MaxConnections, PerTunnel: c.PerTunnel, DownloadMBPS: c.DownloadMBPS,
		ConnectSeconds: c.ConnectSeconds, IdleSeconds: c.IdleSeconds, Username: c.Username}
	if c.PasswordEnv != "" {
		r.Password = os.Getenv(c.PasswordEnv)
		if r.Password == "" {
			return r, errors.New("proxy password environment variable is empty")
		}
	}
	for _, t := range c.Tunnels {
		r.Tunnels = append(r.Tunnels, Lane{ID: t.ID, Listen: t.Listen, DNS: t.DNS, IPv6: t.IPv6, Ports: t.Ports})
	}
	return r, nil
}

func ListenNetwork(address string) string {
	host, _, _ := net.SplitHostPort(address)
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		return "tcp6"
	}
	return "tcp4"
}
