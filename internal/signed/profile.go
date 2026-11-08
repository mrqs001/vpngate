// Package signed sends HTTP requests that look like a browser on the wire:
// the TLS ClientHello, the HTTP/2 connection preface and frames, and the
// request headers and their order. It knows nothing about vpngate's lanes or
// scheduling; the caller supplies the dialer.
package signed

import (
	"strconv"
	"strings"

	utls "github.com/mrqs001/vpngate/internal/third_party/utls"
	"golang.org/x/net/http2"
)

// Setting is one HTTP/2 SETTINGS parameter, sent in slice order.
type Setting struct {
	ID  http2.SettingID
	Val uint32
}

// Profile holds every value that identifies one browser. All header names
// are lowercase; H1Order holds the names in the case the browser writes them
// over HTTP/1.1.
type Profile struct {
	HelloID        utls.ClientHelloID
	Settings       []Setting
	ConnectionFlow uint32   // connection-level WINDOW_UPDATE after the preface
	Pseudo         []string // HTTP/2 pseudo-header order
	NavigateOrder  []string // GET and HEAD: a top-level navigation
	FetchOrder     []string // every other method: a same-origin fetch()
	H1Order        []string
	Navigate       map[string]string
	Fetch          map[string]string
	PlainHTTPDrop  []string // not sent to http:// targets (not a secure context)
	PlainEncoding  string   // accept-encoding for http:// targets
	UserAgent      string
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
const chromeCHUA = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`

// Chrome is Chrome 156 on Windows. Its ClientHello is the uTLS Chrome 155
// spec, checked against a real Chrome 155 capture; Chrome's BoringSSL hello
// did not change in 156. Header values and orders follow surf's Chrome 156
// desktop profile (see testdata/SOURCES.md).
var Chrome = &Profile{
	HelloID: utls.HelloChrome_155,
	Settings: []Setting{
		{http2.SettingHeaderTableSize, 65536},
		{http2.SettingEnablePush, 0},
		{http2.SettingInitialWindowSize, 6291456},
		{http2.SettingMaxHeaderListSize, 262144},
	},
	ConnectionFlow: 15663105,
	Pseudo:         []string{":method", ":authority", ":scheme", ":path"},
	NavigateOrder: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "authorization",
		"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
		"sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"},
	FetchOrder: []string{"content-length", "pragma", "cache-control", "sec-ch-ua-platform", "authorization",
		"user-agent", "sec-ch-ua", "content-type", "sec-ch-ua-mobile", "accept", "origin", "sec-fetch-site",
		"sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"},
	// Chrome over HTTP/1.1: Host first, then Connection, client hints in
	// lowercase and the rest in Chrome's capitalisation. It sends no
	// priority header on HTTP/1.1.
	H1Order: []string{"Connection", "Content-Length", "Pragma", "Cache-Control", "sec-ch-ua", "sec-ch-ua-mobile",
		"sec-ch-ua-platform", "Authorization", "Upgrade-Insecure-Requests", "User-Agent", "Content-Type",
		"Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Referer",
		"Accept-Encoding", "Accept-Language", "Cookie"},
	Navigate: map[string]string{
		"sec-ch-ua":                 chromeCHUA,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Windows"`,
		"upgrade-insecure-requests": "1",
		"user-agent":                chromeUA,
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"sec-fetch-site":            "none",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-user":            "?1",
		"sec-fetch-dest":            "document",
		"accept-encoding":           "gzip, deflate, br, zstd",
		"accept-language":           "en-US,en;q=0.9",
		"priority":                  "u=0, i",
	},
	Fetch: map[string]string{
		"sec-ch-ua":          chromeCHUA,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
		"user-agent":         chromeUA,
		"accept":             "*/*",
		"sec-fetch-site":     "same-origin",
		"sec-fetch-mode":     "cors",
		"sec-fetch-dest":     "empty",
		"accept-encoding":    "gzip, deflate, br, zstd",
		"accept-language":    "en-US,en;q=0.9",
		"priority":           "u=1, i",
	},
	PlainHTTPDrop: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site",
		"sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest"},
	PlainEncoding: "gzip, deflate",
	UserAgent:     chromeUA,
}

// Akamai returns the HTTP/2 fingerprint string the profile produces:
// SETTINGS|WINDOW_UPDATE|PRIORITY frames|pseudo-header order.
func (p *Profile) Akamai() string {
	var b strings.Builder
	for i, s := range p.Settings {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(strconv.FormatUint(uint64(s.ID), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(s.Val), 10))
	}
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(p.ConnectionFlow), 10))
	b.WriteString("|0|")
	for i, h := range p.Pseudo {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte(h[1])
	}
	return b.String()
}

// Weight returns the HTTP/2 HEADERS priority weight field (wire weight minus
// one) for a priority header value. Chrome derives both from one request
// priority: urgency u=N is SPDY priority N, and Chromium's
// Spdy3PriorityToHttp2Weight gives int(255.9/7*(7-N))+1. A missing or
// invalid urgency is the RFC 9218 default, u=3.
func Weight(priority string) uint8 {
	u := 3
	for _, item := range strings.Split(priority, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(item), "=")
		if ok && k == "u" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 7 {
				u = n
			}
		}
	}
	const steps = float32(255.9) / 7        // Chromium computes in float
	return uint8(int(steps * float32(7-u))) // wire weight int(...)+1, minus one
}
