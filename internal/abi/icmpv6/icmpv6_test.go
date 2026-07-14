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

func TestEchoAndNeighborRejectMalformedFixedFields(t *testing.T) {
	memory := make([]byte, 192)
	destination := nscore.Endpoint{Address: netip.MustParseAddr("fe80::7"), ScopeID: 9}
	copy(memory[160:], "ping6")
	if !EncodeEchoRequestV1(memory, 0, destination, 160, 5) {
		t.Fatal("encode echo request")
	}
	for name, mutate := range map[string]func([]byte){
		"unknown family": func(encoded []byte) { encoded[0] = 0xff },
		"address flags":  func(encoded []byte) { encoded[1] = 1 },
		"port":           func(encoded []byte) { binary.LittleEndian.PutUint16(encoded[2:4], 1) },
		"flow info":      func(encoded []byte) { binary.LittleEndian.PutUint32(encoded[24:28], 1) },
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
				t.Fatal("malformed echo request accepted")
			}
		})
	}
	if CheckEchoV1(memory, ^uint32(0)-EchoRequestV1Size+2, 64) || CheckEchoResultV1(memory, ^uint32(0)-1, 4, 0) {
		t.Fatal("overflowing echo range accepted")
	}

	neighbor := icmpns.Neighbor{Address: netip.MustParseAddr("2001:db8::8"), MAC: [6]byte{0x02, 1, 2, 3, 4, 5}}
	if !EncodeNeighborV1(memory, 0, neighbor) {
		t.Fatal("encode neighbor")
	}
	for name, mutate := range map[string]func([]byte){
		"IPv4 address": func(encoded []byte) { encoded[0] = 1 },
		"port":         func(encoded []byte) { binary.LittleEndian.PutUint16(encoded[2:4], 1) },
		"scope":        func(encoded []byte) { binary.LittleEndian.PutUint32(encoded[4:8], 1) },
		"flow info":    func(encoded []byte) { binary.LittleEndian.PutUint32(encoded[24:28], 1) },
		"zero MAC":     func(encoded []byte) { clear(encoded[neighborMACOffset : neighborMACOffset+6]) },
		"reserved":     func(encoded []byte) { encoded[neighborReservedOffset] = 1 },
	} {
		t.Run("neighbor "+name, func(t *testing.T) {
			malformed := append([]byte(nil), memory...)
			mutate(malformed)
			if _, ok := DecodeNeighborV1(malformed, 0); ok {
				t.Fatal("malformed neighbor accepted")
			}
		})
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

func FuzzICMPv6V1Layouts(f *testing.F) {
	valid := make([]byte, 256)
	destination := nscore.Endpoint{Address: netip.MustParseAddr("fe80::7"), ScopeID: 9}
	copy(valid[192:], "ping6")
	if !EncodeEchoRequestV1(valid, 16, destination, 192, 5) {
		f.Fatal("seed echo request")
	}
	neighbor := icmpns.Neighbor{Address: netip.MustParseAddr("2001:db8::8"), MAC: [6]byte{0x02, 1, 2, 3, 4, 5}}
	if !EncodeNeighborV1(valid, 96, neighbor) {
		f.Fatal("seed neighbor")
	}
	f.Add(valid, uint32(16), uint32(128), uint32(192), uint32(5))
	f.Add([]byte{0xff, 1, 2, 3}, ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, inputPtr, outputPtr, payloadPtr, payloadLen uint32) {
		if len(memory) > 4096 {
			t.Skip()
		}
		before := append([]byte(nil), memory...)
		request, requestOK := DecodeEchoRequestV1(memory, inputPtr)
		neighborValue, neighborOK := DecodeNeighborV1(memory, inputPtr)
		_, _ = DecodeNeighborKeyV1(memory, inputPtr)
		_ = CheckEchoV1(memory, inputPtr, outputPtr)
		_ = CheckEchoResultV1(memory, payloadPtr, payloadLen, outputPtr)
		if !bytes.Equal(memory, before) {
			t.Fatal("layout validation mutated memory")
		}
		if requestOK && !request.Valid() {
			t.Fatal("decoded invalid echo request")
		}
		if neighborOK {
			if !neighborValue.Valid() {
				t.Fatal("decoded invalid neighbor")
			}
			canonical := make([]byte, NeighborV1Size)
			if !EncodeNeighborV1(canonical, 0, neighborValue) {
				t.Fatal("decoded neighbor did not re-encode")
			}
			if roundTrip, ok := DecodeNeighborV1(canonical, 0); !ok || roundTrip != neighborValue {
				t.Fatalf("neighbor round trip = %+v, %v", roundTrip, ok)
			}
		}

		encoded := append([]byte(nil), memory...)
		encodedBefore := append([]byte(nil), encoded...)
		if !EncodeEchoRequestV1(encoded, outputPtr, destination, payloadPtr, payloadLen) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed echo request encode mutated memory")
		}
		result := icmpns.EchoResult{Source: destination.Address, ScopeID: destination.ScopeID, Identifier: 3, Sequence: 4, Copied: 3, PayloadBytes: 5}
		encoded = append(encoded[:0], memory...)
		encodedBefore = append(encodedBefore[:0], encoded...)
		if !EncodeEchoResultV1(encoded, outputPtr, result, 3) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed echo result encode mutated memory")
		}
		encoded = append(encoded[:0], memory...)
		encodedBefore = append(encodedBefore[:0], encoded...)
		if !EncodeNeighborV1(encoded, outputPtr, neighbor) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed neighbor encode mutated memory")
		}
	})
}
