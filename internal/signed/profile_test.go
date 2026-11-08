package signed

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestChromeAkamai(t *testing.T) {
	if got := Chrome.Akamai(); got != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Fatal(got)
	}
}

func TestWeight(t *testing.T) {
	for in, want := range map[string]uint8{"u=0, i": 255, "u=1, i": 219, "u=2": 182, "u=3": 146, "u=4": 109,
		"u=5": 73, "u=6": 36, "u=7": 0, "": 146, "garbage": 146, "i, u=1": 219, "u=9": 146} {
		if got := Weight(in); got != want {
			t.Errorf("%q: %d want %d", in, got, want)
		}
	}
}

// goldenNavigation returns the regular headers of the golden's HTTP/2
// navigation request, in order.
func goldenNavigation(t *testing.T) [][2]string {
	t.Helper()
	f, err := os.Open("testdata/chrome-156-windows.golden")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][2]string
	in := false
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		switch {
		case strings.HasPrefix(line, "## "):
			in = line == "## http/2 navigation"
		case in && strings.HasPrefix(line, "HEADERS"):
		case in && !strings.HasPrefix(line, ":") && strings.Contains(line, ": "):
			k, v, _ := strings.Cut(line, ": ")
			out = append(out, [2]string{k, v})
		}
	}
	if len(out) < 10 {
		t.Fatal("golden navigation block not found")
	}
	return out
}

func TestChromeHeadersMatchSurfGolden(t *testing.T) {
	var order []string
	for _, n := range Chrome.NavigateOrder {
		if _, ok := Chrome.Navigate[n]; ok {
			order = append(order, n)
		}
	}
	golden := goldenNavigation(t)
	if len(order) != len(golden) {
		t.Fatalf("defaults %v, golden %v", order, golden)
	}
	for i, kv := range golden {
		if order[i] != kv[0] || Chrome.Navigate[kv[0]] != kv[1] {
			t.Errorf("header %d: have %s=%q want %s=%q", i, order[i], Chrome.Navigate[order[i]], kv[0], kv[1])
		}
	}
	if Chrome.UserAgent != Chrome.Navigate["user-agent"] || Chrome.Fetch["user-agent"] != Chrome.UserAgent {
		t.Fatal("user agent differs between sets")
	}
}

func TestChromeFetchDefaults(t *testing.T) {
	want := map[string]string{"accept": "*/*", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors",
		"sec-fetch-dest": "empty", "priority": "u=1, i", "sec-ch-ua-platform": `"Windows"`}
	for k, v := range want {
		if Chrome.Fetch[k] != v {
			t.Errorf("%s=%q want %q", k, Chrome.Fetch[k], v)
		}
	}
	for _, k := range []string{"sec-fetch-user", "upgrade-insecure-requests"} {
		if _, ok := Chrome.Fetch[k]; ok {
			t.Errorf("fetch set has navigation-only %s", k)
		}
	}
	for _, list := range [][]string{Chrome.NavigateOrder, Chrome.FetchOrder} {
		seen := map[string]bool{}
		for _, n := range list {
			if n != strings.ToLower(n) || seen[n] {
				t.Fatalf("order entry %q not lowercase or repeated", n)
			}
			seen[n] = true
		}
	}
}
