package signed

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Field is one request header with a lowercase name.
type Field struct{ Name, Value string }

// libraryUA lists User-Agent prefixes that HTTP libraries send by default.
// A client value starting with one of them counts as "not sent", so Chrome's
// value stays. Documented in docs/fetch.md; keep the two lists in step.
var libraryUA = []string{"python-requests/", "python-httpx/", "Python/3", "Python-urllib/", "aiohttp/",
	"Go-http-client/", "curl/", "Wget/", "okhttp/", "axios/", "node-fetch", "undici"}

// libraryValues lists exact header values that HTTP libraries send by
// default and that count as "not sent".
var libraryValues = map[string][]string{
	"accept":          {"*/*"},
	"accept-encoding": {"gzip, deflate", "gzip, deflate, br", "identity", "gzip"},
	"connection":      {"keep-alive"},
}

func hopByHop(name, value string) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host":
		return true
	case "te":
		return !strings.EqualFold(strings.TrimSpace(value), "trailers")
	}
	return false
}

func libraryDefault(name, value string) bool {
	if name == "user-agent" {
		for _, p := range libraryUA {
			if strings.HasPrefix(value, p) {
				return true
			}
		}
		return false
	}
	return slices.Contains(libraryValues[name], value)
}

// navigation reports whether a method gets the top-level navigation set.
func navigation(method string) bool { return method == http.MethodGet || method == http.MethodHead }

// Headers merges a client's headers with the profile's defaults and returns
// them in the browser's order, without pseudo-headers or host. A client
// header replaces the default of the same name, unless it is empty or a
// known HTTP-library default. omit names defaults to leave out.
func (p *Profile) Headers(method string, u *url.URL, client http.Header, omit []string) []Field {
	defaults, order := p.Navigate, p.NavigateOrder
	if !navigation(method) {
		defaults, order = p.Fetch, p.FetchOrder
	}
	plain := u.Scheme == "http"
	sent := make(map[string]string, len(client))
	for k, vs := range client {
		name := strings.ToLower(k)
		v := strings.Join(vs, ", ")
		if name == "cookie" {
			v = strings.Join(vs, "; ")
		}
		if v == "" || hopByHop(name, v) || libraryDefault(name, v) {
			continue
		}
		sent[name] = v
	}
	out := make([]Field, 0, len(order)+len(sent))
	for _, name := range order {
		if v, ok := sent[name]; ok {
			out = append(out, Field{name, v})
			delete(sent, name)
			continue
		}
		if slices.Contains(omit, name) || (plain && slices.Contains(p.PlainHTTPDrop, name)) {
			continue
		}
		v, ok := defaults[name]
		switch {
		case name == "origin" && !navigation(method):
			v, ok = u.Scheme+"://"+u.Host, true
		case name == "accept-encoding" && plain && ok:
			v = p.PlainEncoding
		}
		if ok {
			out = append(out, Field{name, v})
		}
	}
	extra := make([]string, 0, len(sent))
	for name := range sent {
		extra = append(extra, name)
	}
	slices.Sort(extra)
	for _, name := range extra {
		out = append(out, Field{name, sent[name]})
	}
	return out
}

// ParseOmit parses Vpngate-Omit values: comma-separated header names,
// case-insensitive. Pseudo-headers and host cannot be omitted.
func ParseOmit(values []string) []string {
	var out []string
	for _, v := range values {
		for _, name := range strings.Split(v, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || name == "host" || strings.HasPrefix(name, ":") {
				continue
			}
			out = append(out, name)
		}
	}
	return out
}
