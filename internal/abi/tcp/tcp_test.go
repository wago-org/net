package tcp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/resource"
)

func TestV1CheckedRangesAndAtomicCodecs(t *testing.T) {
	if StreamV1Size != 72 || IOResultV1Size != 8 {
		t.Fatalf("TCP layout sizes = %d/%d", StreamV1Size, IOResultV1Size)
	}
	memory := bytes.Repeat([]byte{0x5a}, 160)
	if !CheckListenV1(memory, 0, 32) || CheckListenV1(memory, 16, 32) || CheckListenV1(memory, 0, 156) {
		t.Fatal("TCP listen range validation mismatch")
	}
	if !CheckCreateV1(memory, 0, 32) || CheckCreateV1(memory, 16, 32) || CheckCreateV1(memory, 0, 100) {
		t.Fatal("TCP create range validation mismatch")
	}
	if !CheckIOV1(memory, 0, 16, 16) || CheckIOV1(memory, 4, 16, 12) || CheckIOV1(memory, 160, 1, 0) {
		t.Fatal("TCP IO range validation mismatch")
	}
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 49152}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	handle := resource.Handle(0x0102030405060708)
	if !EncodeStreamV1(memory, 32, handle, local, remote) {
		t.Fatal("EncodeStreamV1 failed")
	}
	if got := binary.LittleEndian.Uint64(memory[32:40]); got != uint64(handle) {
		t.Fatalf("TCP stream handle = %#x", got)
	}
	if got, ok := abicore.DecodeEndpointV1(memory, 40); !ok || got != local {
		t.Fatalf("TCP local endpoint = %+v, %v", got, ok)
	}
	if got, ok := abicore.DecodeEndpointV1(memory, 72); !ok || got != remote {
		t.Fatalf("TCP remote endpoint = %+v, %v", got, ok)
	}
	if !EncodeIOResultV1(memory, 120, namespace.IOResult{Bytes: 3, State: namespace.IOReady}, 8) {
		t.Fatal("EncodeIOResultV1 failed")
	}
	if got := binary.LittleEndian.Uint32(memory[120:124]); got != 3 || binary.LittleEndian.Uint32(memory[124:128]) != 0 {
		t.Fatalf("TCP IO result = %d/%#x", got, binary.LittleEndian.Uint32(memory[124:128]))
	}

	before := append([]byte(nil), memory...)
	if EncodeStreamV1(memory, 100, handle, local, remote) || EncodeIOResultV1(memory, 120, namespace.IOResult{State: namespace.IOWouldBlock}, 8) {
		t.Fatal("invalid TCP result encoded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("rejected TCP codec mutated memory")
	}
}

func FuzzV1Layouts(f *testing.F) {
	f.Add(make([]byte, 160), uint32(0), uint32(32), uint32(8))
	f.Add([]byte{1, 2, 3}, ^uint32(0), ^uint32(0), uint32(16))
	f.Fuzz(func(t *testing.T, memory []byte, ptr, count, size uint32) {
		_ = CheckListenV1(memory, ptr, count)
		_ = CheckCreateV1(memory, ptr, count)
		_ = CheckIOV1(memory, ptr, count, size)
		_ = EncodeStreamV1(memory, ptr, resource.Handle(1), namespace.Endpoint{}, namespace.Endpoint{})
		_ = EncodeIOResultV1(memory, ptr, namespace.IOResult{Bytes: int(count), State: namespace.IOReady}, int(size))
	})
}
