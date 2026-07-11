package core

import (
	"bytes"
	"testing"
)

func TestSliceBoundaries(t *testing.T) {
	memory := make([]byte, 8)
	tests := []struct {
		name        string
		ptr, length uint32
		want        bool
	}{
		{"empty memory start", 0, 0, true},
		{"whole memory", 0, 8, true},
		{"zero at end", 8, 0, true},
		{"last byte", 7, 1, true},
		{"one past end", 8, 1, false},
		{"straddles end", 7, 2, false},
		{"uint32 sum exceeds memory", ^uint32(0), 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Slice(memory, tc.ptr, tc.length)
			if ok != tc.want {
				t.Fatalf("Slice(%d, %d) ok = %v, want %v", tc.ptr, tc.length, ok, tc.want)
			}
			if ok && len(got) != int(tc.length) {
				t.Fatalf("Slice length = %d, want %d", len(got), tc.length)
			}
		})
	}
	if got, ok := Slice(nil, 0, 0); !ok || len(got) != 0 {
		t.Fatalf("Slice(nil, 0, 0) = %v, %v", got, ok)
	}
}

func TestRejectedWritesDoNotMutateMemory(t *testing.T) {
	memory := []byte{1, 2, 3, 4}
	before := append([]byte(nil), memory...)
	if Write(memory, 3, []byte{9, 9}) {
		t.Fatal("out-of-bounds Write succeeded")
	}
	if Zero(memory, 3, 2) {
		t.Fatal("out-of-bounds Zero succeeded")
	}
	if WriteUint32LE(memory, 1, 0x11223344) {
		t.Fatal("out-of-bounds WriteUint32LE succeeded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatalf("rejected writes changed memory: got %v want %v", memory, before)
	}
}

func TestMemoryHelpers(t *testing.T) {
	memory := make([]byte, 8)
	if !Write(memory, 1, []byte{1, 2, 3}) {
		t.Fatal("Write failed")
	}
	if !bytes.Equal(memory[1:4], []byte{1, 2, 3}) {
		t.Fatalf("Write bytes = %v", memory)
	}
	if !WriteUint32LE(memory, 4, 0x11223344) {
		t.Fatal("WriteUint32LE failed")
	}
	if got, ok := ReadUint32LE(memory, 4); !ok || got != 0x11223344 {
		t.Fatalf("ReadUint32LE = %#x, %v", got, ok)
	}
	if !Zero(memory, 1, 3) || !bytes.Equal(memory[1:4], []byte{0, 0, 0}) {
		t.Fatalf("Zero result = %v", memory)
	}

	overlap := []byte{1, 2, 3, 4}
	if !Write(overlap, 1, overlap[:3]) {
		t.Fatal("overlapping Write failed")
	}
	if !bytes.Equal(overlap, []byte{1, 1, 2, 3}) {
		t.Fatalf("overlapping Write = %v", overlap)
	}
}

func FuzzSlice(f *testing.F) {
	f.Add(uint16(8), uint32(8), uint32(0))
	f.Add(uint16(8), ^uint32(0), uint32(2))
	f.Fuzz(func(t *testing.T, size uint16, ptr, length uint32) {
		memory := make([]byte, int(size))
		got, ok := Slice(memory, ptr, length)
		want := uint64(ptr)+uint64(length) <= uint64(len(memory))
		if ok != want {
			t.Fatalf("Slice size=%d ptr=%d length=%d ok=%v want=%v", size, ptr, length, ok, want)
		}
		if ok && uint64(len(got)) != uint64(length) {
			t.Fatalf("valid Slice length = %d, want %d", len(got), length)
		}
	})
}
