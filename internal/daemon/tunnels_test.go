package daemon

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/mrqs001/vpngate/internal/config"
)

type fakeNetwork struct {
	calls  []string
	failAt int
}

func (f *fakeNetwork) call(op string) error {
	f.calls = append(f.calls, op)
	if f.failAt == len(f.calls) {
		return errors.New("fixture failure")
	}
	return nil
}
func (f *fakeNetwork) CreateNamespace(_ context.Context, name string) (uint64, uint64, error) {
	return 4, 123, f.call("namespace " + name)
}
func (f *fakeNetwork) CreateDevice(_ context.Context, name, alias string) (int, error) {
	return 7, f.call("device " + name)
}
func (f *fakeNetwork) MoveDevice(_ context.Context, r Resource) error {
	return f.call("move " + r.Device)
}
func (f *fakeNetwork) Configure(_ context.Context, r Resource, w config.WireGuard, endpoint string) error {
	return f.call("configure " + r.Device)
}
func (f *fakeNetwork) DeleteDevice(_ context.Context, r Resource) error {
	return f.call("delete-device " + r.Device)
}
func (f *fakeNetwork) DeleteNamespace(_ context.Context, r Resource) error {
	return f.call("delete-namespace " + r.Namespace)
}
func plan() Plan {
	ns, dev := Names("test", "one")
	return Plan{Config: config.Config{Name: "test"}, Resources: []Resource{{ID: "attached", Namespace: "external"}, {ID: "one", Namespace: ns, Device: dev, Owned: true}}, Profiles: map[int]config.WireGuard{1: {PrivateKey: "fixture-private", PublicKey: "fixture-public", Endpoint: "192.0.2.1:51820", Addresses: []netip.Prefix{netip.MustParsePrefix("10.17.0.2/32")}, Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MTU: 1420}}}
}
func TestSetupOnlyTouchesOwnedObjects(t *testing.T) {
	p := plan()
	n := &fakeNetwork{}
	cleanup, err := p.Setup(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	for _, call := range n.calls {
		if strings.Contains(call, "external") || strings.Contains(call, "fixture-private") {
			t.Fatal("touched attached namespace or exposed secret")
		}
	}
	if len(n.calls) != 6 || n.calls[4] != "delete-device "+p.Resources[1].Device || n.calls[5] != "delete-namespace "+p.Resources[1].Namespace {
		t.Fatal("cleanup order", n.calls)
	}
}
func TestRollbackAtEverySetupStep(t *testing.T) {
	for step := 1; step <= 4; step++ {
		p := plan()
		n := &fakeNetwork{failAt: step}
		if _, err := p.Setup(context.Background(), n); err == nil {
			t.Fatal("failure ignored", step)
		}
		if step == 1 && len(n.calls) != 1 {
			t.Fatal("removed unowned namespace")
		}
		if step > 1 && n.calls[len(n.calls)-1] != "delete-namespace "+p.Resources[1].Namespace {
			t.Fatal("namespace not rolled back", step)
		}
		if step == 2 && len(n.calls) != 3 {
			t.Fatal("removed device that failed creation")
		}
	}
}
func TestOwnershipJournalTracksHostToNamespaceMove(t *testing.T) {
	p := plan()
	n := &fakeNetwork{}
	var journal []Resource
	cleanup, err := p.setup(context.Background(), n, func(r Resource) error { journal = append(journal, r); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(journal) != 3 || journal[0].HostDevice || !journal[1].HostDevice || journal[2].HostDevice {
		t.Fatal("missing ownership transition")
	}
	for _, r := range journal {
		if !r.Owned || r.NamespaceDev != 4 || r.NamespaceIno != 123 || len(r.DeviceAlias) != 40 {
			t.Fatal("missing namespace identity or link ownership")
		}
	}
	if journal[0].DeviceIndex != 0 || journal[1].DeviceIndex != 7 || journal[2].DeviceIndex != 7 {
		t.Fatal("missing interface index")
	}
}
func TestJournalFailuresRollBackOwnedResources(t *testing.T) {
	for step := 1; step <= 3; step++ {
		p := plan()
		n := &fakeNetwork{}
		writes := 0
		_, err := p.setup(context.Background(), n, func(Resource) error {
			writes++
			if writes == step {
				return errors.New("journal failure")
			}
			return nil
		})
		if err == nil || n.calls[len(n.calls)-1] != "delete-namespace "+p.Resources[1].Namespace {
			t.Fatal("journal failure leaked resources", step, n.calls)
		}
	}
}
