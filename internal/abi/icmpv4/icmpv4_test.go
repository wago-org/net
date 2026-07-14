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

func TestEchoRequestRejectsMalformedFixedFields(t *testing.T) {
	memory := make([]byte, 128)
	destination := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1")}
	if !EncodeEchoRequestV1(memory, 0, destination, 80, 4) {
		t.Fatal("encode request")
	}
	for name, mutate := range map[string]func([]byte){
		"unknown family": func(encoded []byte) { encoded[0] = 0xff },
		"address flags":  func(encoded []byte) { encoded[1] = 1 },
		"port":           func(encoded []byte) { binary.LittleEndian.PutUint16(encoded[2:4], 1) },
		"reserved":       func(encoded []byte) { encoded[requestReservedOffset] = 1 },
		"payload overflow": func(encoded []byte) {
			binary.LittleEndian.PutUint32(encoded[requestPayloadPtrOffset:requestPayloadPtrOffset+4], ^uint32(0)-1)
			binary.LittleEndian.PutUint32(encoded[requestPayloadLenOffset:requestPayloadLenOffset+4], 4)
		},
	} {
		t.Run(name, func(t *testing.T) {
			malformed := append([]byte(nil), memory...)
			mutate(malformed)
			if _, ok := DecodeEchoRequestV1(malformed, 0); ok {
				t.Fatal("malformed request accepted")
			}
		})
	}
	if CheckEchoV1(memory, ^uint32(0)-EchoRequestV1Size+2, 64) || CheckResultV1(memory, ^uint32(0)-1, 4, 0) {
		t.Fatal("overflowing indirect range accepted")
	}
}

func FuzzICMPv4V1Layouts(f *testing.F) {
	valid := make([]byte, 256)
	destination := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1")}
	copy(valid[160:], "echo")
	if !EncodeEchoRequestV1(valid, 16, destination, 160, 4) {
		f.Fatal("seed request")
	}
	f.Add(valid, uint32(16), uint32(96), uint32(160), uint32(4))
	f.Add([]byte{0xff, 1, 2, 3}, ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, requestPtr, outputPtr, payloadPtr, payloadLen uint32) {
		if len(memory) > 4096 {
			t.Skip()
		}
		before := append([]byte(nil), memory...)
		decoded, ok := DecodeEchoRequestV1(memory, requestPtr)
		_ = CheckEchoV1(memory, requestPtr, outputPtr)
		_ = CheckResultV1(memory, payloadPtr, payloadLen, outputPtr)
		if !bytes.Equal(memory, before) {
			t.Fatal("request validation mutated memory")
		}
		if ok && !decoded.Valid() {
			t.Fatal("decoded invalid request")
		}

		encoded := append([]byte(nil), memory...)
		encodedBefore := append([]byte(nil), encoded...)
		if !EncodeEchoRequestV1(encoded, outputPtr, destination, payloadPtr, payloadLen) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed request encode mutated memory")
		}
		result := icmpns.Result{Source: netip.MustParseAddr("192.0.2.9"), Identifier: 7, Sequence: 11, Copied: 3, PayloadBytes: 8}
		encoded = append(encoded[:0], memory...)
		encodedBefore = append(encodedBefore[:0], encoded...)
		if !EncodeEchoResultV1(encoded, outputPtr, result, 3) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed result encode mutated memory")
		}
	})
}
