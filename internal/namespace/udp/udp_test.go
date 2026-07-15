package udp

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

var (
	_ Namespace = (*fakeNamespace)(nil)
	_ Socket    = (*fakeSocket)(nil)
)

type fakeNamespace struct{ socket nscore.Resource }

func (n *fakeNamespace) TryBindUDP(nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.socket, nscore.ProgressDone, nil
}

type fakeSocket struct{}

func (*fakeSocket) Close() error                   { return nil }
func (*fakeSocket) Readiness() nscore.Readiness    { return nscore.ReadyWritable }
func (*fakeSocket) LocalEndpoint() nscore.Endpoint { return endpoint(4000) }
func (*fakeSocket) TrySend([]byte, nscore.Endpoint) (nscore.Progress, error) {
	return nscore.ProgressDone, nil
}
func (*fakeSocket) TryReceive(dst []byte) (DatagramResult, error) {
	return DatagramResult{Copied: len(dst), DatagramBytes: len(dst), Source: endpoint(53), Ready: true}, nil
}

func TestNarrowUDPFacetAndDatagramValidation(t *testing.T) {
	socket := &fakeSocket{}
	backend := &fakeNamespace{socket: socket}
	resource, progress, err := backend.TryBindUDP(endpoint(0))
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("TryBindUDP = %v, %v", progress, err)
	}
	typed, ok := resource.(Socket)
	if !ok {
		t.Fatalf("socket resource type = %T", resource)
	}
	result, err := typed.TryReceive(make([]byte, 3))
	if err != nil || !result.Valid(3) {
		t.Fatalf("TryReceive = %+v, %v", result, err)
	}
	if (DatagramResult{Ready: true}).Valid(0) {
		t.Fatal("ready datagram without a valid source accepted")
	}
	if (DatagramResult{Ready: true, DatagramBytes: MaxDatagramPayloadBytes + 1, Source: endpoint(53), Truncated: true}).Valid(0) {
		t.Fatal("oversized UDP datagram accepted")
	}
	for name, source := range map[string]nscore.Endpoint{
		"port":      {Port: 53},
		"scope":     {ScopeID: 7},
		"flow info": {FlowInfo: 11},
	} {
		if (DatagramResult{Source: source}).Valid(0) {
			t.Fatalf("not-ready datagram with %s metadata accepted", name)
		}
	}
}

func endpoint(port uint16) nscore.Endpoint {
	return nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: port}
}
