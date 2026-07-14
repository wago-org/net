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
