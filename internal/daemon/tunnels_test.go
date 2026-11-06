package daemon

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/mrqs001/vpngate/internal/config"
)

type call struct {
	program string
	args    []string
	input   string
}
type fakeRunner struct {
	calls  []call
	failAt int
}

func (f *fakeRunner) Run(ctx context.Context, p string, args []string, input string) error {
	f.calls = append(f.calls, call{p, append([]string(nil), args...), input})
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return errors.New("fixture failure")
	}
	return nil
}
func plan() Plan {
	ns, dev := Names("test", "one")
	return Plan{Config: config.Config{Name: "test"}, Resources: []Resource{{ID: "attached", Namespace: "external", Owned: false}, {ID: "one", Namespace: ns, Device: dev, Owned: true}},
		Profiles: map[int]config.WireGuard{1: {PrivateKey: "fixture-private", PublicKey: "fixture-public", Endpoint: "192.0.2.1:51820",
			Addresses: []netip.Prefix{netip.MustParsePrefix("10.17.0.2/32")}, Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MTU: 1420}}}
}
func TestSetupOnlyTouchesOwnedObjectsAndPipesKeys(t *testing.T) {
	p := plan()
	r := &fakeRunner{}
	cleanup, e := p.Setup(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range r.calls {
		a := strings.Join(c.args, " ")
		if strings.Contains(a, "external") || strings.Contains(a, "fixture-private") {
			t.Fatal("touched attached namespace or exposed key in argv")
		}
		if strings.Contains(a, "route add") && !strings.HasPrefix(a, "-n ") {
			t.Fatal("modified host routes")
		}
		if c.input != "" && !strings.Contains(a, "setconf") {
			t.Fatal("unexpected secret transport")
		}
	}
	if e = cleanup(); e != nil {
		t.Fatal(e)
	}
	last := r.calls[len(r.calls)-1]
	if !reflect.DeepEqual(last.args, []string{"netns", "delete", p.Resources[1].Namespace}) {
		t.Fatal("cleanup did not remove owned namespace")
	}
}
func TestRollbackAtEverySetupStep(t *testing.T) {
	for n := 1; n <= 7; n++ {
		p := plan()
		r := &fakeRunner{failAt: n}
		if _, e := p.Setup(context.Background(), r); e == nil {
			t.Fatalf("failure %d ignored", n)
		}
		if n == 1 && len(r.calls) != 1 {
			t.Fatal("deleted namespace that failed creation")
		}
		if n > 1 {
			if !reflect.DeepEqual(r.calls[len(r.calls)-1].args, []string{"netns", "delete", p.Resources[1].Namespace}) {
				t.Fatalf("failure %d did not roll back namespace", n)
			}
		}
	}
}

func TestOwnershipJournalTracksHostToNamespaceMove(t *testing.T) {
	p := plan()
	r := &fakeRunner{}
	var journal []Resource
	cleanup, e := p.setup(context.Background(), r, func(v Resource) error { journal = append(journal, v); return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	if len(journal) != 3 || journal[0].HostDevice || !journal[1].HostDevice || journal[2].HostDevice {
		t.Fatal("ownership journal missed a namespace/device transition")
	}
	for _, v := range journal {
		if !v.Owned || v.ID == "attached" {
			t.Fatal("journal claimed attached resources")
		}
	}
}
