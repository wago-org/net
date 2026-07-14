package linklocal4

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
)

func TestRequestCheckedDisjointAndCanonical(t *testing.T) {
	memory := make([]byte, 96)
	request := linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}
	if !EncodeRequestV1(memory, 0, request) || !CheckRequestV1(memory, 0, 40) {
		t.Fatal("valid request rejected")
	}
	decoded, ok := DecodeRequestV1(memory, 0)
	if !ok || decoded != request {
		t.Fatalf("decoded = %+v, %v", decoded, ok)
	}
	if CheckRequestV1(memory, 0, 24) {
		t.Fatal("overlapping handle output accepted")
	}
	memory[1] = 1
	if _, ok := DecodeRequestV1(memory, 0); ok {
		t.Fatal("nonzero address flags accepted")
	}
}

func TestResultEncodingIsAtomicAndFixed(t *testing.T) {
	memory := bytes.Repeat([]byte{0xaa}, 64)
	before := append([]byte(nil), memory...)
	result := linklocalns.Result{Address: netip.MustParseAddr("169.254.42.7"), Subnet: linklocalns.Prefix, Conflicts: 3, Applied: true}
	if EncodeResultV1(memory, 32, result) || !bytes.Equal(memory, before) {
		t.Fatal("short result output mutated memory")
	}
	if !EncodeResultV1(memory, 0, result) {
		t.Fatal("valid result rejected")
	}
	if binary.LittleEndian.Uint32(memory[32:36]) != 16 || binary.LittleEndian.Uint32(memory[36:40]) != 3 || binary.LittleEndian.Uint32(memory[40:44]) != ResultFlagApplied || binary.LittleEndian.Uint32(memory[44:48]) != 0 {
		t.Fatalf("encoded result = %x", memory[:48])
	}
}

func TestRequestRejectsMalformedAddressFields(t *testing.T) {
	memory := make([]byte, RequestV1Size)
	if !EncodeRequestV1(memory, 0, linklocalns.Request{}) {
		t.Fatal("encode empty request")
	}
	for name, mutate := range map[string]func([]byte){
		"unknown family": func(encoded []byte) { encoded[0] = 0xff },
		"address flags":  func(encoded []byte) { encoded[1] = 1 },
		"port":           func(encoded []byte) { binary.LittleEndian.PutUint16(encoded[2:4], 1) },
		"scope":          func(encoded []byte) { binary.LittleEndian.PutUint32(encoded[4:8], 1) },
		"reserved":       func(encoded []byte) { encoded[28] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			malformed := append([]byte(nil), memory...)
			mutate(malformed)
			if _, ok := DecodeRequestV1(malformed, 0); ok {
				t.Fatal("malformed request accepted")
			}
		})
	}
	if CheckRequestV1(memory, ^uint32(0)-RequestV1Size+2, 0) || CheckRequestV1(memory, 0, ^uint32(0)) {
		t.Fatal("overflowing fixed range accepted")
	}
}

func FuzzLinkLocal4V1Layouts(f *testing.F) {
	valid := make([]byte, 128)
	request := linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}
	if !EncodeRequestV1(valid, 8, request) {
		f.Fatal("seed request")
	}
	f.Add(valid, uint32(8), uint32(64))
	f.Add([]byte{0xff, 1, 2, 3}, ^uint32(0), ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, requestPtr, outputPtr uint32) {
		if len(memory) > 4096 {
			t.Skip()
		}
		before := append([]byte(nil), memory...)
		decoded, ok := DecodeRequestV1(memory, requestPtr)
		_ = CheckRequestV1(memory, requestPtr, outputPtr)
		if !bytes.Equal(memory, before) {
			t.Fatal("request validation mutated memory")
		}
		if ok && !decoded.Valid() {
			t.Fatal("decoded invalid request")
		}

		encoded := append([]byte(nil), memory...)
		encodedBefore := append([]byte(nil), encoded...)
		if !EncodeRequestV1(encoded, outputPtr, request) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed request encode mutated memory")
		}
		result := linklocalns.Result{Address: request.FirstCandidate, Subnet: linklocalns.Prefix, Applied: true}
		encoded = append(encoded[:0], memory...)
		encodedBefore = append(encodedBefore[:0], encoded...)
		if !EncodeResultV1(encoded, outputPtr, result) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed result encode mutated memory")
		}
	})
}
