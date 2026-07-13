// Package mdns contains fixed-width checked multicast DNS guest ABI codecs.
package mdns

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	"github.com/wago-org/net/internal/mdnsname"
	nscore "github.com/wago-org/net/internal/namespace/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
)

const (
	NameV1Size         uint32 = 260
	QueryV1Size        uint32 = 268
	RecordV1Size       uint32 = 832
	AnnouncementV1Size uint32 = 8

	RecordTypesA    uint32 = 1
	RecordTypesPTR  uint32 = 2
	RecordTypesSRV  uint32 = 4
	RecordTypesTXT  uint32 = 8
	recordTypesMask        = RecordTypesA | RecordTypesPTR | RecordTypesSRV | RecordTypesTXT

	RecordTypeA   uint32 = 1
	RecordTypePTR uint32 = 2
	RecordTypeSRV uint32 = 3
	RecordTypeTXT uint32 = 4

	RecordFlagCacheFlush uint32 = 1

	nameBytesOffset   = 4
	nameBytesCapacity = 253
	queryTypesOffset  = 260
	queryReserved     = 264
	recordTypeOffset  = 260
	recordTTLOffset   = 264
	recordAddress     = 268
	recordTarget      = 300
	recordPort        = 560
	recordPriority    = 562
	recordWeight      = 564
	recordTXTLength   = 566
	recordTXT         = 568
	recordFlags       = 824
	recordReserved    = 828
)

func DecodeNameV1(memory []byte, ptr uint32) (string, bool) {
	encoded, ok := abicore.Slice(memory, ptr, NameV1Size)
	if !ok {
		return "", false
	}
	return decodeName(encoded)
}

func EncodeNameV1(memory []byte, ptr uint32, name string) bool {
	if !mdnsname.ValidCanonical(name) {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, NameV1Size)
	if !ok {
		return false
	}
	var encoded [NameV1Size]byte
	putName(encoded[:], name)
	copy(output, encoded[:])
	return true
}

func DecodeQueryV1(memory []byte, ptr uint32) (mdnsns.Request, bool) {
	encoded, ok := abicore.Slice(memory, ptr, QueryV1Size)
	if !ok || binary.LittleEndian.Uint32(encoded[queryReserved:queryReserved+4]) != 0 {
		return mdnsns.Request{}, false
	}
	types := binary.LittleEndian.Uint32(encoded[queryTypesOffset : queryTypesOffset+4])
	if types == 0 || types&^recordTypesMask != 0 {
		return mdnsns.Request{}, false
	}
	name, ok := decodeName(encoded[:NameV1Size])
	if !ok {
		return mdnsns.Request{}, false
	}
	request := mdnsns.Request{Name: name, Types: mdnsns.RecordTypes(types)}
	return request, request.Valid()
}

func EncodeQueryV1(memory []byte, ptr uint32, request mdnsns.Request) bool {
	if !request.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, QueryV1Size)
	if !ok {
		return false
	}
	var encoded [QueryV1Size]byte
	putName(encoded[:NameV1Size], request.Name)
	binary.LittleEndian.PutUint32(encoded[queryTypesOffset:queryTypesOffset+4], uint32(request.Types))
	copy(output, encoded[:])
	return true
}

func CheckQueryV1(memory []byte, requestPtr, handlePtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: requestPtr, Length: QueryV1Size},
		abicore.Range{Ptr: handlePtr, Length: abicore.HandleV1Size},
	)
}

func DecodeAnnouncementV1(memory []byte, ptr uint32) (uint16, bool) {
	encoded, ok := abicore.Slice(memory, ptr, AnnouncementV1Size)
	if !ok || binary.LittleEndian.Uint32(encoded[4:8]) != 0 {
		return 0, false
	}
	service := binary.LittleEndian.Uint32(encoded[0:4])
	return uint16(service), service <= uint32(^uint16(0))
}

func EncodeAnnouncementV1(memory []byte, ptr uint32, service uint16) bool {
	output, ok := abicore.Slice(memory, ptr, AnnouncementV1Size)
	if !ok {
		return false
	}
	var encoded [AnnouncementV1Size]byte
	binary.LittleEndian.PutUint32(encoded[0:4], uint32(service))
	copy(output, encoded[:])
	return true
}

func CheckAnnouncementV1(memory []byte, requestPtr, handlePtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: requestPtr, Length: AnnouncementV1Size},
		abicore.Range{Ptr: handlePtr, Length: abicore.HandleV1Size},
	)
}

func EncodeRecordV1(memory []byte, ptr uint32, record mdnsns.Record) bool {
	if !record.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, RecordV1Size)
	if !ok {
		return false
	}
	var encoded [RecordV1Size]byte
	putName(encoded[:NameV1Size], record.Name)
	binary.LittleEndian.PutUint32(encoded[recordTTLOffset:recordTTLOffset+4], record.TTLSeconds)
	if record.CacheFlush {
		binary.LittleEndian.PutUint32(encoded[recordFlags:recordFlags+4], RecordFlagCacheFlush)
	}
	switch record.Type {
	case mdnsns.RecordA:
		binary.LittleEndian.PutUint32(encoded[recordTypeOffset:recordTypeOffset+4], RecordTypeA)
		if !abicore.EncodeEndpointV1(encoded[:], recordAddress, nscore.Endpoint{Address: record.Address}) {
			return false
		}
	case mdnsns.RecordPTR:
		binary.LittleEndian.PutUint32(encoded[recordTypeOffset:recordTypeOffset+4], RecordTypePTR)
		putName(encoded[recordTarget:recordTarget+NameV1Size], record.Target)
	case mdnsns.RecordSRV:
		binary.LittleEndian.PutUint32(encoded[recordTypeOffset:recordTypeOffset+4], RecordTypeSRV)
		putName(encoded[recordTarget:recordTarget+NameV1Size], record.Target)
		binary.LittleEndian.PutUint16(encoded[recordPort:recordPort+2], record.Port)
		binary.LittleEndian.PutUint16(encoded[recordPriority:recordPriority+2], record.Priority)
		binary.LittleEndian.PutUint16(encoded[recordWeight:recordWeight+2], record.Weight)
	case mdnsns.RecordTXT:
		binary.LittleEndian.PutUint32(encoded[recordTypeOffset:recordTypeOffset+4], RecordTypeTXT)
		binary.LittleEndian.PutUint16(encoded[recordTXTLength:recordTXTLength+2], record.TXTLength)
		copy(encoded[recordTXT:recordTXT+mdnsns.MaxTXTBytes], record.TXT[:record.TXTLength])
	default:
		return false
	}
	copy(output, encoded[:])
	return true
}

func decodeName(encoded []byte) (string, bool) {
	if len(encoded) != int(NameV1Size) || binary.LittleEndian.Uint16(encoded[2:4]) != 0 {
		return "", false
	}
	length := int(binary.LittleEndian.Uint16(encoded[0:2]))
	if length == 0 || length > nameBytesCapacity {
		return "", false
	}
	for _, value := range encoded[nameBytesOffset+length:] {
		if value != 0 {
			return "", false
		}
	}
	name := encoded[nameBytesOffset : nameBytesOffset+length]
	if !mdnsname.ValidCanonicalBytes(name) {
		return "", false
	}
	return string(name), true
}

func putName(output []byte, name string) {
	binary.LittleEndian.PutUint16(output[0:2], uint16(len(name)))
	copy(output[nameBytesOffset:], name)
}
