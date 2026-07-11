// Package dns contains the fixed-width DNS guest ABI codecs.
package dns

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
)

const (
	// DNSNameV1Size is the fixed size of one normalized DNS name. The first
	// uint16 is the byte length, the next uint16 is reserved, bytes 4..256 hold
	// at most 253 ASCII bytes, and bytes 257..259 are reserved padding.
	DNSNameV1Size uint32 = 260
	// DNSQueryV1Size is one inline name, a uint32 record-type bitset, and a
	// reserved uint32.
	DNSQueryV1Size uint32 = 268
	// DNSRecordV1Size is name, type, TTL, address union, and canonical name.
	DNSRecordV1Size uint32 = 560

	DNSRecordTypesA    uint32 = 1
	DNSRecordTypesAAAA uint32 = 2
	dnsRecordTypesMask        = DNSRecordTypesA | DNSRecordTypesAAAA

	DNSRecordTypeA     uint32 = 1
	DNSRecordTypeAAAA  uint32 = 2
	DNSRecordTypeCNAME uint32 = 3

	dnsNameBytesOffset   = 4
	dnsNameBytesCapacity = 253
	dnsQueryTypesOffset  = 260
	dnsQueryReserved     = 264
	dnsRecordTypeOffset  = 260
	dnsRecordTTLOffset   = 264
	dnsRecordAddress     = 268
	dnsRecordCanonical   = 300
)

// DecodeDNSNameV1 decodes a lowercase normalized ASCII name and rejects all
// nonzero reserved or unused bytes.
func DecodeDNSNameV1(memory []byte, ptr uint32) (string, bool) {
	b, ok := abicore.Slice(memory, ptr, DNSNameV1Size)
	if !ok {
		return "", false
	}
	length := int(binary.LittleEndian.Uint16(b[0:2]))
	if length == 0 || length > dnsNameBytesCapacity || binary.LittleEndian.Uint16(b[2:4]) != 0 {
		return "", false
	}
	for _, value := range b[dnsNameBytesOffset+length:] {
		if value != 0 {
			return "", false
		}
	}
	name := string(b[dnsNameBytesOffset : dnsNameBytesOffset+length])
	if !(dnsns.Request{Name: name, Types: dnsns.RecordsA}).Valid() {
		return "", false
	}
	return name, true
}

// EncodeDNSNameV1 atomically writes one normalized name with zero padding.
func EncodeDNSNameV1(memory []byte, ptr uint32, name string) bool {
	if !(dnsns.Request{Name: name, Types: dnsns.RecordsA}).Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, DNSNameV1Size)
	if !ok {
		return false
	}
	var encoded [DNSNameV1Size]byte
	binary.LittleEndian.PutUint16(encoded[0:2], uint16(len(name)))
	copy(encoded[dnsNameBytesOffset:], name)
	copy(output, encoded[:])
	return true
}

// DecodeDNSQueryV1 validates the complete fixed-width query and returns the
// backend-neutral request.
func DecodeDNSQueryV1(memory []byte, ptr uint32) (dnsns.Request, bool) {
	b, ok := abicore.Slice(memory, ptr, DNSQueryV1Size)
	if !ok {
		return dnsns.Request{}, false
	}
	name, ok := DecodeDNSNameV1(memory, ptr)
	if !ok || binary.LittleEndian.Uint32(b[dnsQueryReserved:dnsQueryReserved+4]) != 0 {
		return dnsns.Request{}, false
	}
	types := binary.LittleEndian.Uint32(b[dnsQueryTypesOffset : dnsQueryTypesOffset+4])
	if types == 0 || types&^dnsRecordTypesMask != 0 {
		return dnsns.Request{}, false
	}
	request := dnsns.Request{Name: name, Types: dnsns.RecordTypes(types)}
	return request, request.Valid()
}

// EncodeDNSQueryV1 is used by host tooling and tests to construct one canonical
// fixed query. Guest decoders do not depend on this helper.
func EncodeDNSQueryV1(memory []byte, ptr uint32, request dnsns.Request) bool {
	if !request.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, DNSQueryV1Size)
	if !ok {
		return false
	}
	var encoded [DNSQueryV1Size]byte
	if !EncodeDNSNameV1(encoded[:], 0, request.Name) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[dnsQueryTypesOffset:dnsQueryTypesOffset+4], uint32(request.Types))
	copy(output, encoded[:])
	return true
}

// CheckDNSResolveV1 validates complete query input and handle output ranges and
// requires them to be disjoint before resolver state changes.
func CheckDNSResolveV1(memory []byte, queryPtr, handlePtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: queryPtr, Length: DNSQueryV1Size},
		abicore.Range{Ptr: handlePtr, Length: abicore.HandleV1Size},
	)
}

// EncodeDNSRecordV1 atomically writes a type-tagged record. Address bytes are
// populated only for A/AAAA; canonical name is populated only for CNAME.
func EncodeDNSRecordV1(memory []byte, ptr uint32, record dnsns.Record) bool {
	if !record.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, DNSRecordV1Size)
	if !ok {
		return false
	}
	var encoded [DNSRecordV1Size]byte
	if !EncodeDNSNameV1(encoded[:], 0, record.Name) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[dnsRecordTTLOffset:dnsRecordTTLOffset+4], record.TTLSeconds)
	switch record.Type {
	case dnsns.RecordA:
		binary.LittleEndian.PutUint32(encoded[dnsRecordTypeOffset:dnsRecordTypeOffset+4], DNSRecordTypeA)
		if !abicore.EncodeEndpointV1(encoded[:], dnsRecordAddress, nscore.Endpoint{Address: record.Address}) {
			return false
		}
	case dnsns.RecordAAAA:
		binary.LittleEndian.PutUint32(encoded[dnsRecordTypeOffset:dnsRecordTypeOffset+4], DNSRecordTypeAAAA)
		if !abicore.EncodeEndpointV1(encoded[:], dnsRecordAddress, nscore.Endpoint{Address: record.Address}) {
			return false
		}
	case dnsns.RecordCNAME:
		binary.LittleEndian.PutUint32(encoded[dnsRecordTypeOffset:dnsRecordTypeOffset+4], DNSRecordTypeCNAME)
		if !EncodeDNSNameV1(encoded[:], dnsRecordCanonical, record.CanonicalName) {
			return false
		}
	default:
		return false
	}
	copy(output, encoded[:])
	return true
}
