package icmpv6

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

func TestSupportedOperationsAreNarrow(t *testing.T) {
	for _, operation := range []Operation{OperationEcho, OperationNeighborResolve, OperationNeighborLookup, OperationNeighborSeed, OperationNeighborRemove} {
		if !SupportedOperations.Supports(operation) {
			t.Fatalf("supported operation %d rejected", operation)
		}
	}
	for _, operation := range []Operation{OperationRouterDiscovery, OperationRedirect, OperationDAD, OperationSLAAC, OperationRawPacket, 255} {
		if SupportedOperations.Supports(operation) {
			t.Fatalf("unsupported operation %d advertised", operation)
		}
	}
}

func TestEchoAndNeighborValidation(t *testing.T) {
	global := netip.MustParseAddr("2001:db8::7")
	linkLocal := netip.MustParseAddr("fe80::7")
	if !(EchoRequest{Destination: global, Payload: []byte("echo")}).Valid() {
		t.Fatal("global echo rejected")
	}
	if !(EchoRequest{Destination: linkLocal, ScopeID: 3}).Valid() {
		t.Fatal("scoped link-local echo rejected")
	}
	for _, request := range []EchoRequest{
		{},
		{Destination: netip.IPv6Unspecified()},
		{Destination: netip.MustParseAddr("ff02::1")},
		{Destination: netip.MustParseAddr("::ffff:192.0.2.1")},
		{Destination: linkLocal},
		{Destination: global, ScopeID: 3},
	} {
		if request.Valid() {
			t.Fatalf("invalid echo request accepted: %+v", request)
		}
	}
	neighbor := Neighbor{Address: linkLocal, ScopeID: 3, MAC: [6]byte{0x02, 1, 2, 3, 4, 5}}
	if !neighbor.Valid() || !(NeighborRequest{Address: linkLocal, ScopeID: 3}).Valid() {
		t.Fatal("valid neighbor rejected")
	}
	for _, mac := range [][6]byte{{}, {1, 2, 3, 4, 5, 6}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		invalid := neighbor
		invalid.MAC = mac
		if invalid.Valid() {
			t.Fatalf("invalid MAC accepted: %x", mac)
		}
	}
	result := EchoResult{Source: global, Identifier: 7, Sequence: 9, Copied: 2, PayloadBytes: 4}
	if !result.Valid(2) || (EchoResult{Source: global, Copied: 3, PayloadBytes: 2}).Valid(3) {
		t.Fatal("echo result bounds validation failed")
	}
}

func TestResourceContractsCompile(t *testing.T) {
	var _ nscore.Resource = (Echo)(nil)
	var _ nscore.Resource = (Resolution)(nil)
}
