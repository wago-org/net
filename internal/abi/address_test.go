package abi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAddressV1IPv4RoundTrip(t *testing.T) {
	address := Address{Family: AddressFamilyIPv4, Port: 8080}
	copy(address.Address[:4], []byte{192, 0, 2, 1})
	memory := bytes.Repeat([]byte{0xaa}, int(AddressV1Size)+4)
	if !EncodeAddressV1(memory, 2, address) {
		t.Fatal("EncodeAddressV1 failed")
	}
	encoded := memory[2 : 2+AddressV1Size]
	if encoded[0] != byte(AddressFamilyIPv4) || encoded[1] != 0 {
		t.Fatalf("family/flags = %v", encoded[:2])
	}
	if got := binary.LittleEndian.Uint16(encoded[2:4]); got != 8080 {
		t.Fatalf("port = %d", got)
	}
	if !bytes.Equal(encoded[8:12], []byte{192, 0, 2, 1}) || !allZero(encoded[12:]) {
		t.Fatalf("encoded IPv4 address = %x", encoded)
	}
	got, ok := DecodeAddressV1(memory, 2)
	if !ok || got != address {
		t.Fatalf("DecodeAddressV1 = %+v, %v; want %+v", got, ok, address)
	}
}

func TestAddressV1IPv6RoundTrip(t *testing.T) {
	address := Address{
		Family:   AddressFamilyIPv6,
		Port:     443,
		ScopeID:  7,
		FlowInfo: 0x000a_bcde,
		Address:  [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}
	memory := make([]byte, AddressV1Size)
	if !EncodeAddressV1(memory, 0, address) {
		t.Fatal("EncodeAddressV1 failed")
	}
	got, ok := DecodeAddressV1(memory, 0)
	if !ok || got != address {
		t.Fatalf("DecodeAddressV1 = %+v, %v; want %+v", got, ok, address)
	}
}

func TestAddressV1RejectsInvalidStructures(t *testing.T) {
	valid4 := Address{Family: AddressFamilyIPv4, Address: [16]byte{127, 0, 0, 1}}
	valid6 := Address{Family: AddressFamilyIPv6, Address: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	tests := []struct {
		name    string
		address Address
	}{
		{"unknown family", Address{Family: 9}},
		{"unknown flags", Address{Family: AddressFamilyIPv4, Flags: 1}},
		{"IPv4 scope", func() Address { a := valid4; a.ScopeID = 1; return a }()},
		{"IPv4 flow info", func() Address { a := valid4; a.FlowInfo = 1; return a }()},
		{"IPv4 nonzero tail", func() Address { a := valid4; a.Address[15] = 1; return a }()},
		{"IPv6 flow overflow", func() Address { a := valid6; a.FlowInfo = 0x0010_0000; return a }()},
		{"IPv6 global scope", func() Address { a := valid6; a.ScopeID = 1; return a }()},
		{"IPv4-mapped IPv6", Address{Family: AddressFamilyIPv6, Address: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			memory := bytes.Repeat([]byte{0x5a}, int(AddressV1Size))
			before := append([]byte(nil), memory...)
			if EncodeAddressV1(memory, 0, tc.address) {
				t.Fatal("invalid address encoded successfully")
			}
			if !bytes.Equal(memory, before) {
				t.Fatal("invalid address partially mutated output")
			}
		})
	}
}

func TestAddressV1DecodeRejectsReservedAndMalformedFields(t *testing.T) {
	valid := Address{Family: AddressFamilyIPv4, Address: [16]byte{192, 0, 2, 1}}
	memory := make([]byte, AddressV1Size)
	if !EncodeAddressV1(memory, 0, valid) {
		t.Fatal("encode valid address")
	}

	mutations := []struct {
		name string
		fn   func([]byte)
	}{
		{"flags", func(b []byte) { b[1] = 1 }},
		{"reserved", func(b []byte) { b[28] = 1 }},
		{"family", func(b []byte) { b[0] = 0 }},
		{"IPv4 tail", func(b []byte) { b[23] = 1 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			bad := append([]byte(nil), memory...)
			mutation.fn(bad)
			if _, ok := DecodeAddressV1(bad, 0); ok {
				t.Fatal("malformed address decoded successfully")
			}
		})
	}
	if _, ok := DecodeAddressV1(memory[:AddressV1Size-1], 0); ok {
		t.Fatal("short address decoded successfully")
	}
}

func TestAddressV1EncodeValidatesOutputBeforeMutation(t *testing.T) {
	address := Address{Family: AddressFamilyIPv4, Address: [16]byte{127, 0, 0, 1}}
	memory := bytes.Repeat([]byte{0x7c}, int(AddressV1Size))
	before := append([]byte(nil), memory...)
	if EncodeAddressV1(memory, 1, address) {
		t.Fatal("out-of-bounds encode succeeded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("out-of-bounds encode partially mutated output")
	}
}

func FuzzDecodeAddressV1(f *testing.F) {
	seed := make([]byte, AddressV1Size)
	seed[0] = byte(AddressFamilyIPv4)
	copy(seed[8:12], []byte{127, 0, 0, 1})
	f.Add(seed, uint32(0))
	f.Add([]byte{1, 2, 3}, ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, ptr uint32) {
		address, ok := DecodeAddressV1(memory, ptr)
		if !ok {
			return
		}
		encoded := make([]byte, AddressV1Size)
		if !EncodeAddressV1(encoded, 0, address) {
			t.Fatal("decoded address could not be encoded")
		}
		roundTrip, ok := DecodeAddressV1(encoded, 0)
		if !ok || roundTrip != address {
			t.Fatalf("round trip = %+v, %v; want %+v", roundTrip, ok, address)
		}
	})
}

func allZero(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}
