// Package core contains shared, allocation-free codecs for the Wago networking
// guest ABI. Callers must not retain slices returned by this package beyond the
// host call that supplied the guest memory.
package core

import "encoding/binary"

// NarrowUint32 converts one raw host parameter only when it is exactly
// representable by the guest ABI's i32 value domain.
func NarrowUint32(value uint64) (uint32, bool) {
	narrowed := uint32(value)
	return narrowed, value == uint64(narrowed)
}

// Slice validates [ptr, ptr+length) using uint64 arithmetic before slicing guest
// memory. A zero-length range at exactly len(memory) is valid.
func Slice(memory []byte, ptr, length uint32) ([]byte, bool) {
	end := uint64(ptr) + uint64(length)
	if end > uint64(len(memory)) {
		return nil, false
	}
	return memory[uint64(ptr):end], true
}

// Write copies src into guest memory only after validating the entire output
// range. Rejected writes leave guest memory unchanged. Overlap follows Go copy
// semantics.
func Write(memory []byte, ptr uint32, src []byte) bool {
	if uint64(len(src)) > uint64(^uint32(0)) {
		return false
	}
	dst, ok := Slice(memory, ptr, uint32(len(src)))
	if !ok {
		return false
	}
	copy(dst, src)
	return true
}

// Zero validates and clears a guest-memory range. Rejected ranges leave memory
// unchanged.
func Zero(memory []byte, ptr, length uint32) bool {
	dst, ok := Slice(memory, ptr, length)
	if !ok {
		return false
	}
	clear(dst)
	return true
}

// ReadUint32LE reads one little-endian uint32 after a checked range lookup.
func ReadUint32LE(memory []byte, ptr uint32) (uint32, bool) {
	b, ok := Slice(memory, ptr, 4)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

// WriteUint32LE writes one little-endian uint32 after validating the complete
// destination. A rejected write does not mutate memory.
func WriteUint32LE(memory []byte, ptr, value uint32) bool {
	b, ok := Slice(memory, ptr, 4)
	if !ok {
		return false
	}
	binary.LittleEndian.PutUint32(b, value)
	return true
}
