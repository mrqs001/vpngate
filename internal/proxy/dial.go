package proxy

import (
	"container/list"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mrqs001/vpngate/internal/config"
)

type SocketDialer interface {
	Dial(context.Context, int, string, netip.AddrPort) (net.Conn, error)
}

var errLaneDNS = errors.New("lane DNS failed")

type cacheEntry struct {
	key     string
	ips     []netip.Addr
	expires time.Time
}
type Resolver struct {
	sockets SocketDialer
	mu      sync.Mutex
	cache   map[string]*list.Element
	order   *list.List
	flights map[string]*lookup
	ctx     context.Context
	cancel  context.CancelFunc
}
type lookup struct {
	done chan struct{}
	ips  []netip.Addr
	err  error
}

func NewResolver(s SocketDialer) *Resolver {
	ctx, cancel := context.WithCancel(context.Background())
	return &Resolver{sockets: s, cache: map[string]*list.Element{}, order: list.New(), flights: map[string]*lookup{}, ctx: ctx, cancel: cancel}
}
func (r *Resolver) Close() { r.cancel() }

func (r *Resolver) Resolve(ctx context.Context, lane int, c config.Lane, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.Is6() && !c.IPv6 {
			return nil, errors.New("address family unavailable")
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	host = strings.ToLower(dns.Fqdn(host))
	if _, ok := dns.IsDomainName(host); !ok || len(host) > 254 {
		return nil, errors.New("invalid destination hostname")
	}
	key := strconv.Itoa(lane) + ":" + host
	r.mu.Lock()
	if e := r.cache[key]; e != nil {
		v := e.Value.(cacheEntry)
		if time.Now().Before(v.expires) {
			r.order.MoveToFront(e)
			ips := append([]netip.Addr(nil), v.ips...)
			r.mu.Unlock()
			return ips, nil
		}
		r.order.Remove(e)
		delete(r.cache, key)
	}
	f := r.flights[key]
	if f == nil {
		if len(r.flights) >= 512 {
			r.mu.Unlock()
			return nil, errors.New("DNS lookup limit reached")
		}
		f = &lookup{done: make(chan struct{})}
		r.flights[key] = f
		go func() {
			qctx, cancel := context.WithTimeout(r.ctx, 6*time.Second)
			defer cancel()
			ips, err := r.lookup(qctx, lane, c, host, key)
			r.mu.Lock()
			f.ips, f.err = ips, err
			delete(r.flights, key)
			close(f.done)
			r.mu.Unlock()
		}()
	}
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		return append([]netip.Addr(nil), f.ips...), f.err
	}
}

func (r *Resolver) lookup(ctx context.Context, lane int, c config.Lane, host, key string) ([]netip.Addr, error) {
	type result struct {
		ips []netip.Addr
		ttl uint32
		err error
	}
	count := 1
	if c.IPv6 {
		count = 2
	}
	results := make(chan result, count)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if qtype == dns.TypeAAAA && !c.IPv6 {
			continue
		}
		go func(qtype uint16) {
			ips, ttl, err := r.query(ctx, lane, c.DNS, host, qtype)
			results <- result{ips, ttl, err}
		}(qtype)
	}
	var ips []netip.Addr
	ttl := uint32(300)
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case v := <-results:
			if v.err == nil {
				ips = append(ips, v.ips...)
				if v.ttl < ttl {
					ttl = v.ttl
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("lane DNS resolution failed")
	}
	// Prefer IPv4 consistently; the caller tries every returned address within its deadline.
	for i := 0; i < len(ips); i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[j].Is4() && ips[i].Is6() {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}
	if ttl > 0 {
		r.mu.Lock()
		if old := r.cache[key]; old != nil {
			r.order.Remove(old)
		}
		r.cache[key] = r.order.PushFront(cacheEntry{key, append([]netip.Addr(nil), ips...), time.Now().Add(time.Duration(ttl) * time.Second)})
		for r.order.Len() > 8192 {
			e := r.order.Back()
			delete(r.cache, e.Value.(cacheEntry).key)
			r.order.Remove(e)
		}
		r.mu.Unlock()
	}
	return ips, nil
}

func (r *Resolver) query(ctx context.Context, lane int, servers []string, host string, qtype uint16) ([]netip.Addr, uint32, error) {
	for _, server := range servers {
		addr, err := netip.ParseAddr(server)
		if err != nil {
			continue
		}
		endpoint := netip.AddrPortFrom(addr, 53)
		q := new(dns.Msg)
		q.SetQuestion(host, qtype)
		q.SetEdns0(1232, false)
		// A single dropped UDP reply must not fail every caller sharing this
		// lookup. Retry once, then use TCP, always through this same VPN lane.
		truncated := false
		for _, network := range []string{"udp", "udp", "tcp"} {
			if network == "udp" && truncated {
				continue
			}
			budget := 750 * time.Millisecond
			if network == "tcp" {
				budget = 1500 * time.Millisecond
			}
			qctx, cancel := context.WithTimeout(ctx, budget)
			conn, err := r.sockets.Dial(qctx, lane, network, endpoint)
			if err != nil {
				cancel()
				continue
			}
			stop := context.AfterFunc(qctx, func() { conn.Close() })
			response, _, err := (&dns.Client{Net: network, Timeout: budget}).ExchangeWithConnContext(qctx, q, &dns.Conn{Conn: conn})
			stop()
			conn.Close()
			cancel()
			if err != nil || response == nil || !response.Response || response.Id != q.Id || len(response.Question) != 1 || response.Question[0] != q.Question[0] {
				continue
			}
			if response.Rcode != dns.RcodeSuccess {
				break
			}
			if response.Truncated {
				if network == "udp" {
					truncated = true
					continue
				}
				break
			}
			names := map[string]bool{strings.ToLower(host): true}
			ttl := uint32(300)
			for hop := 0; hop < 8; hop++ {
				added := false
				for _, rr := range response.Answer {
					if cn, ok := rr.(*dns.CNAME); ok && names[strings.ToLower(cn.Hdr.Name)] {
						target := strings.ToLower(cn.Target)
						if !names[target] {
							names[target] = true
							added = true
						}
						if cn.Hdr.Ttl < ttl {
							ttl = cn.Hdr.Ttl
						}
					}
				}
				if !added {
					break
				}
			}
			var ips []netip.Addr
			for _, rr := range response.Answer {
				if !names[strings.ToLower(rr.Header().Name)] {
					continue
				}
				var ip net.IP
				switch a := rr.(type) {
				case *dns.A:
					if qtype == dns.TypeA {
						ip = a.A
					}
				case *dns.AAAA:
					if qtype == dns.TypeAAAA {
						ip = a.AAAA
					}
				}
				if a, ok := netip.AddrFromSlice(ip); ok {
					ips = append(ips, a.Unmap())
					if rr.Header().Ttl < ttl {
						ttl = rr.Header().Ttl
					}
				}
			}
			if len(ips) > 0 {
				return ips, ttl, nil
			}
			break
		}
	}
	return nil, 0, errors.New("DNS query failed")
}

func (r *Resolver) DialContext(lane int, c config.Lane, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, errors.New("only TCP targets are supported")
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid destination")
		}
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || p == 0 {
			return nil, errors.New("invalid destination port")
		}
		ips, err := r.Resolve(ctx, lane, c, host)
		if err != nil {
			return nil, errors.Join(errLaneDNS, err)
		}
		for _, ip := range ips {
			// Bound individual addresses so an unreachable first answer cannot consume every attempt.
			attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
			conn, err := r.sockets.Dial(attempt, lane, "tcp", netip.AddrPortFrom(ip, uint16(p)))
			cancel()
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("lane connection failed")
	}
}
