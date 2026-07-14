package icmpv6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
)

func TestEchoRequestAndResultCheckedAtomic(t *testing.T) {
	memory := make([]byte, 256)
	copy(memory[160:], "ping6")
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("fe80::7"), ScopeID: 9}
	if !EncodeEchoRequestV1(memory, 16, endpoint, 160, 5) || !CheckEchoV1(memory, 16, 96) {
		t.Fatal("checked echo request rejected")
	}
	request, ok := DecodeEchoRequestV1(memory, 16)
	if !ok || request.Destination != endpoint.Address || request.ScopeID != 9 || string(request.Payload) != "ping6" {
		t.Fatalf("request = %+v %v", request, ok)
	}
	if CheckEchoV1(memory, 16, 20) {
		t.Fatal("overlapping output accepted")
	}
	result := icmpns.EchoResult{Source: endpoint.Address, ScopeID: 9, Identifier: 3, Sequence: 4, Copied: 3, PayloadBytes: 5}
	before := bytes.Repeat([]byte{0xa5}, int(EchoResultV1Size))
	copy(memory[96:], before)
	if !EncodeEchoResultV1(memory, 96, result, 3) {
		t.Fatal("result encode")
	}
	if binary.LittleEndian.Uint16(memory[128:130]) != 3 || binary.LittleEndian.Uint16(memory[130:132]) != 4 {
		t.Fatal("result identity mismatch")
	}
	copy(memory[96:], before)
	if EncodeEchoResultV1(memory, 96, icmpns.EchoResult{Source: endpoint.Address, ScopeID: 9, Copied: 4, PayloadBytes: 3}, 4) || !bytes.Equal(memory[96:96+EchoResultV1Size], before) {
		t.Fatal("invalid result mutated output")
	}
}

func TestNeighborAndOperationsLayouts(t *testing.T) {
	memory := make([]byte, 128)
	neighbor := icmpns.Neighbor{Address: netip.MustParseAddr("2001:db8::8"), MAC: [6]byte{0x02, 1, 2, 3, 4, 5}}
	if !EncodeNeighborV1(memory, 8, neighbor) {
		t.Fatal("neighbor encode")
	}
	decoded, ok := DecodeNeighborV1(memory, 8)
	if !ok || decoded != neighbor {
		t.Fatalf("neighbor = %+v %v", decoded, ok)
	}
	memory[8+neighborReservedOffset] = 1
	if _, ok := DecodeNeighborV1(memory, 8); ok {
		t.Fatal("reserved neighbor accepted")
	}
	if !EncodeOperationsV1(memory, 80, icmpns.SupportedOperations) || binary.LittleEndian.Uint32(memory[80:84]) != uint32(icmpns.SupportedOperations) {
		t.Fatal("operations encoding failed")
	}
	if EncodeOperationsV1(memory, 80, 1<<31) {
		t.Fatal("unknown operation bit encoded")
	}
}
