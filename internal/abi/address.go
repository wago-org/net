package abi

import "encoding/binary"

const (
	// AddressV1Size is the encoded byte size of wago_net_addr_v1.
	AddressV1Size uint32 = 32

	AddressFlagMaskV1 uint8 = 0 // ABI v1 defines no input flags yet.
)

// AddressFamily is the explicit address family stored in wago_net_addr_v1.
type AddressFamily uint8

const (
	AddressFamilyIPv4 AddressFamily = 1
	AddressFamilyIPv6 AddressFamily = 2
)

// Address is the host representation of wago_net_addr_v1. Address bytes remain
// in network byte order. Integer fields are encoded little-endian.
type Address struct {
	Family   AddressFamily
	Flags    uint8
	Port     uint16
	ScopeID  uint32
	Address  [16]byte
	FlowInfo uint32
}

// DecodeAddressV1 validates and decodes one fixed-width address. It performs no
// guest-memory mutation and returns false for an invalid range or structure.
func DecodeAddressV1(memory []byte, ptr uint32) (Address, bool) {
	b, ok := Slice(memory, ptr, AddressV1Size)
	if !ok {
		return Address{}, false
	}
	var address Address
	address.Family = AddressFamily(b[0])
	address.Flags = b[1]
	address.Port = binary.LittleEndian.Uint16(b[2:4])
	address.ScopeID = binary.LittleEndian.Uint32(b[4:8])
	copy(address.Address[:], b[8:24])
	address.FlowInfo = binary.LittleEndian.Uint32(b[24:28])
	reserved := binary.LittleEndian.Uint32(b[28:32])
	if reserved != 0 || !address.valid() {
		return Address{}, false
	}
	return address, true
}

// EncodeAddressV1 validates address and the complete output range before writing.
// Reserved and currently undefined flag fields are always written as zero.
func EncodeAddressV1(memory []byte, ptr uint32, address Address) bool {
	if !address.valid() {
		return false
	}
	b, ok := Slice(memory, ptr, AddressV1Size)
	if !ok {
		return false
	}
	b[0] = byte(address.Family)
	b[1] = 0
	binary.LittleEndian.PutUint16(b[2:4], address.Port)
	binary.LittleEndian.PutUint32(b[4:8], address.ScopeID)
	copy(b[8:24], address.Address[:])
	binary.LittleEndian.PutUint32(b[24:28], address.FlowInfo)
	binary.LittleEndian.PutUint32(b[28:32], 0)
	return true
}

func (address Address) valid() bool {
	if address.Flags&^AddressFlagMaskV1 != 0 {
		return false
	}
	switch address.Family {
	case AddressFamilyIPv4:
		if address.ScopeID != 0 || address.FlowInfo != 0 {
			return false
		}
		for _, b := range address.Address[4:] {
			if b != 0 {
				return false
			}
		}
		return true
	case AddressFamilyIPv6:
		if address.FlowInfo > 0x000f_ffff || isIPv4MappedIPv6(address.Address) {
			return false
		}
		if address.ScopeID != 0 && !isIPv6Scoped(address.Address) {
			return false
		}
		return true
	default:
		return false
	}
}

func isIPv4MappedIPv6(address [16]byte) bool {
	for _, b := range address[:10] {
		if b != 0 {
			return false
		}
	}
	return address[10] == 0xff && address[11] == 0xff
}

func isIPv6Scoped(address [16]byte) bool {
	// Link-local unicast is fe80::/10. Multicast addresses carry an explicit
	// scope in their low flag/scope nibble and may require an interface scope ID.
	return address[0] == 0xff || (address[0] == 0xfe && address[1]&0xc0 == 0x80)
}
