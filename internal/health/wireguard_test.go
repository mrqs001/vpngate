package health

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWireGuardTelemetryParsesFragmentsAndDoesNotExposeKeys(t *testing.T) {
	timestamp := make([]byte, 16)
	native.PutUint64(timestamp, 1234567)
	secret := bytes.Repeat([]byte("private-key-do-not-publish"), 2)
	peer := append(attribute(2, secret), attribute(6, timestamp)...)
	data := append(attribute(3, secret), attribute(8, attribute(1, peer))...)
	var state WireGuard
	if err := parseDevice(data, &state); err != nil {
		t.Fatal(err)
	}
	continuation := attribute(8, attribute(1, attribute(9, []byte{})))
	if err := parseDevice(continuation, &state); err != nil {
		t.Fatal(err)
	}
	never := attribute(8, attribute(2, attribute(6, make([]byte, 16))))
	if err := parseDevice(never, &state); err != nil {
		t.Fatal(err)
	}
	if state.Peers != 2 || state.LatestHandshakeUnix != 1234567 {
		t.Fatal(state)
	}
	encoded, err := json.Marshal(state)
	if err != nil || bytes.Contains(encoded, []byte("private")) || string(encoded) != `{"peers":2,"latest_handshake_unix":1234567}` {
		t.Fatal("unexpected exported telemetry", string(encoded), err)
	}
	for _, bad := range [][]byte{{1}, {3, 0, 0, 0}, attribute(8, []byte{9, 0, 0, 0}), attribute(8, attribute(1, attribute(6, []byte{1})))} {
		if parseDevice(bad, &WireGuard{}) == nil {
			t.Fatal("malformed reply accepted")
		}
	}
}

func TestReadOnlyInterfaceFlags(t *testing.T) {
	buffer := make([]byte, 64<<10)
	r := inspectLink("lo", buffer)
	if r.NamespaceState != "present" || r.InterfaceUp == nil {
		t.Fatal(r)
	}
	r = inspectLink("vpg-no-such", buffer)
	if r.Error != "interface_missing" {
		t.Fatal(r)
	}
}
