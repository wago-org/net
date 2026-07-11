package udp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/namespace"
)

func TestReceiveResultV1AtomicEncoding(t *testing.T) {
	if ReceiveResultV1Size != 48 || ReceiveFlagTruncated != 1 || !ValidReceiveFlagsV1(0) || !ValidReceiveFlagsV1(ReceiveFlagTruncated) || ValidReceiveFlagsV1(2) {
		t.Fatal("UDP ABI values changed")
	}
	result := namespace.DatagramResult{
		Copied: 3, DatagramBytes: 5,
		Source:    namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 5300},
		Truncated: true, Ready: true,
	}
	memory := bytes.Repeat([]byte{0xaa}, int(ReceiveResultV1Size)+2)
	if !EncodeReceiveResultV1(memory, 1, result, 3) {
		t.Fatal("EncodeReceiveResultV1 failed")
	}
	encoded := memory[1 : 1+ReceiveResultV1Size]
	if got := binary.LittleEndian.Uint32(encoded[32:36]); got != 3 {
		t.Fatalf("copied = %d", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[36:40]); got != 5 {
		t.Fatalf("datagram bytes = %d", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[40:44]); got != ReceiveFlagTruncated {
		t.Fatalf("flags = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[44:48]); got != 0 {
		t.Fatalf("reserved = %#x", got)
	}

	before := append([]byte(nil), memory...)
	if EncodeReceiveResultV1(memory, 3, result, 3) {
		t.Fatal("out-of-bounds result encoded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("rejected result mutated memory")
	}
	bad := result
	bad.Ready = false
	if EncodeReceiveResultV1(memory, 0, bad, 3) {
		t.Fatal("not-ready result encoded")
	}
}

func FuzzReceiveResultV1(f *testing.F) {
	f.Add(make([]byte, ReceiveResultV1Size), uint32(0), uint32(0), uint32(0))
	f.Add([]byte{1, 2, 3}, ^uint32(0), uint32(1), uint32(1))
	f.Fuzz(func(t *testing.T, memory []byte, ptr, copied, datagramBytes uint32) {
		before := append([]byte(nil), memory...)
		result := namespace.DatagramResult{
			Copied: int(copied), DatagramBytes: int(datagramBytes),
			Source: namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 53},
			Ready:  true,
		}
		ok := EncodeReceiveResultV1(memory, ptr, result, int(copied))
		if uint64(ptr)+uint64(ReceiveResultV1Size) > uint64(len(memory)) && (ok || !bytes.Equal(memory, before)) {
			t.Fatal("rejected UDP result write mutated memory")
		}
	})
}
