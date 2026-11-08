package proxy

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrqs001/vpngate/internal/signed"
)

// signedRequest carries what only /fetch_signed needs; /fetch requests
// leave fetchRequest.signed nil.
type signedRequest struct{ omit []string }

// signedLane holds one lane's browser-fingerprint transport, created on the
// first /fetch_signed request routed to that lane.
type signedLane struct {
	once sync.Once
	t    atomic.Pointer[signed.Transport]
}

func (g *Gateway) signedTransport(lane int) *signed.Transport {
	l := &g.signed[lane]
	l.once.Do(func() {
		c := g.cfg.Tunnels[lane]
		l.t.Store(signed.NewTransport(g.resolver.DialContext(lane, c, time.Duration(g.cfg.ConnectSeconds)*time.Second), signed.Chrome,
			signed.Options{RootCAs: g.signedRoots, InsecureSkipVerify: g.cfg.Fetch.InsecureSkipVerify, HTTP2: g.cfg.Fetch.UseHTTP2(),
				ResponseHeaderTimeout: time.Duration(g.cfg.Fetch.TimeoutSeconds) * time.Second, IdleConnTimeout: 90 * time.Second,
				MaxIdleConnsPerHost: min(128, g.cfg.PerTunnel), MaxResponseHeaderBytes: 64 << 10}))
	})
	return l.t.Load()
}
