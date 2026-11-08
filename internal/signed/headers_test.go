package signed

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func names(fs []Field) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Name
	}
	return out
}

func value(fs []Field, name string) (string, bool) {
	for _, f := range fs {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func header(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestHeaders(t *testing.T) {
	https, _ := url.Parse("https://a.example/x")
	plain, _ := url.Parse("http://a.example/")
	navigation := goldenNames(t)
	cases := []struct {
		name   string
		method string
		u      *url.URL
		client http.Header
		omit   []string
		order  []string          // nil: not checked
		want   map[string]string // exact values
		absent []string
	}{
		{name: "defaults", method: "GET", u: https, order: navigation},
		{name: "library defaults ignored", method: "GET", u: https,
			client: header("User-Agent", "python-requests/2.32.3", "Accept", "*/*", "Accept-Encoding", "gzip, deflate", "Connection", "keep-alive"),
			order:  navigation,
			want: map[string]string{"user-agent": Chrome.UserAgent, "accept": Chrome.Navigate["accept"],
				"accept-encoding": "gzip, deflate, br, zstd"},
			absent: []string{"connection"}},
		{name: "custom UA wins", method: "GET", u: https, client: header("User-Agent", "MyBot/1.0"), order: navigation,
			want: map[string]string{"user-agent": "MyBot/1.0"}},
		{name: "empty UA is not sent", method: "GET", u: https, client: header("User-Agent", ""),
			want: map[string]string{"user-agent": Chrome.UserAgent}},
		{name: "omit", method: "GET", u: https, omit: ParseOmit([]string{"Sec-Fetch-User, upgrade-insecure-requests"}),
			absent: []string{"sec-fetch-user", "upgrade-insecure-requests"}},
		{name: "post", method: "POST", u: https, client: header("Content-Type", "application/json", "Content-Length", "2"),
			order: []string{"content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
				"accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language", "priority"},
			want: map[string]string{"origin": "https://a.example", "sec-fetch-mode": "cors", "priority": "u=1, i", "accept": "*/*"}},
		{name: "post keeps client origin", method: "POST", u: https, client: header("Origin", "https://b.example"),
			want: map[string]string{"origin": "https://b.example"}},
		{name: "plain http", method: "GET", u: plain, want: map[string]string{"accept-encoding": "gzip, deflate"},
			absent: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest"}},
		{name: "unknown headers last, sorted", method: "GET", u: https, client: header("X-B", "2", "X-A", "1"),
			order: append(append([]string{}, navigation...), "x-a", "x-b")},
		{name: "cookie and referer in place", method: "GET", u: https, client: header("Cookie", "a=1", "Referer", "https://r.example/"),
			order: []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
				"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "cookie", "priority"},
			want: map[string]string{"cookie": "a=1", "referer": "https://r.example/"}},
		{name: "hop-by-hop dropped", method: "GET", u: https,
			client: header("Keep-Alive", "300", "Proxy-Connection", "x", "Transfer-Encoding", "chunked", "Upgrade", "h2c", "Te", "gzip"),
			order:  navigation, absent: []string{"keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te"}},
		{name: "te trailers kept", method: "GET", u: https, client: header("TE", "trailers"), want: map[string]string{"te": "trailers"}},
		{name: "head is a navigation", method: "HEAD", u: https, order: navigation},
		{name: "repeated client values joined", method: "GET", u: https, client: header("Accept-Language", "de", "Accept-Language", "en"),
			want: map[string]string{"accept-language": "de, en"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Chrome.Headers(c.method, c.u, c.client, c.omit)
			if c.order != nil && !reflect.DeepEqual(names(got), c.order) {
				t.Errorf("order\n got %v\nwant %v", names(got), c.order)
			}
			for k, v := range c.want {
				if have, _ := value(got, k); have != v {
					t.Errorf("%s=%q want %q", k, have, v)
				}
			}
			for _, k := range c.absent {
				if _, ok := value(got, k); ok {
					t.Errorf("%s present", k)
				}
			}
			for _, f := range got {
				if f.Name == "host" || f.Name[0] == ':' {
					t.Errorf("unexpected %s", f.Name)
				}
			}
		})
	}
}

func goldenNames(t *testing.T) []string {
	var out []string
	for _, kv := range goldenNavigation(t) {
		out = append(out, kv[0])
	}
	return out
}

func TestParseOmit(t *testing.T) {
	got := ParseOmit([]string{" Sec-Fetch-User ,HOST", ":path, priority", ""})
	if !reflect.DeepEqual(got, []string{"sec-fetch-user", "priority"}) {
		t.Fatal(got)
	}
	if ParseOmit(nil) != nil {
		t.Fatal("nil input must give nil")
	}
}
