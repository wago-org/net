package icmpv4

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
)

func TestEchoRequestV1CheckedIndirectPayload(t *testing.T) {
	memory := make([]byte, 256)
	copy(memory[128:], "echo")
	destination := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1")}
	if !EncodeEchoRequestV1(memory, 16, destination, 128, 4) {
		t.Fatal("encode request")
	}
	if !CheckEchoV1(memory, 16, 80) {
		t.Fatal("checked request rejected")
	}
	request, ok := DecodeEchoRequestV1(memory, 16)
	if !ok || request.Destination != destination.Address || string(request.Payload) != "echo" {
		t.Fatalf("decoded request = %+v, %v", request, ok)
	}
	if CheckEchoV1(memory, 16, 20) {
		t.Fatal("overlapping handle output accepted")
	}
	binary.LittleEndian.PutUint32(memory[48:52], 16)
	if CheckEchoV1(memory, 16, 80) {
		t.Fatal("payload overlapping request accepted")
	}
	binary.LittleEndian.PutUint32(memory[48:52], 128)
	memory[56] = 1
	if _, ok := DecodeEchoRequestV1(memory, 16); ok {
		t.Fatal("nonzero reserved request accepted")
	}
}

func TestEchoResultV1AtomicEncodingAndRanges(t *testing.T) {
	memory := bytes.Repeat([]byte{0xa5}, 128)
	result := icmpns.Result{Source: netip.MustParseAddr("192.0.2.9"), Identifier: 7, Sequence: 11, Copied: 3, PayloadBytes: 8}
	if !CheckResultV1(memory, 0, 3, 32) {
		t.Fatal("disjoint result ranges rejected")
	}
	if CheckResultV1(memory, 32, 3, 32) {
		t.Fatal("overlapping result ranges accepted")
	}
	if !EncodeEchoResultV1(memory, 32, result, 3) {
		t.Fatal("encode result")
	}
	endpoint, ok := abicore.DecodeEndpointV1(memory, 32)
	if !ok || endpoint.Address != result.Source || endpoint.Port != 0 {
		t.Fatalf("result source = %+v, %v", endpoint, ok)
	}
	if got := binary.LittleEndian.Uint16(memory[64:66]); got != result.Identifier {
		t.Fatalf("identifier = %d", got)
	}
	if got := binary.LittleEndian.Uint16(memory[66:68]); got != result.Sequence {
		t.Fatalf("sequence = %d", got)
	}
	if got := binary.LittleEndian.Uint32(memory[68:72]); got != uint32(result.Copied) {
		t.Fatalf("copied = %d", got)
	}
	if got := binary.LittleEndian.Uint32(memory[72:76]); got != uint32(result.PayloadBytes) {
		t.Fatalf("payload bytes = %d", got)
	}
	before := append([]byte(nil), memory...)
	if EncodeEchoResultV1(memory, 32, icmpns.Result{Source: result.Source, Copied: 4, PayloadBytes: 3}, 4) {
		t.Fatal("invalid result encoded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("invalid result mutated memory")
	}
}
