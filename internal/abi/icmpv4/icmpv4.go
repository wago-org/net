// Package icmpv4 contains the fixed-width ICMPv4 guest ABI codecs.
package icmpv4

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
)

const (
	// EchoRequestV1Size is an IPv4 destination, payload pointer/length, and
	// reserved zero padding.
	EchoRequestV1Size uint32 = 48
	// EchoResultV1Size is a source address, identifier, sequence, copied byte
	// count, complete payload byte count, and reserved zero padding.
	EchoResultV1Size uint32 = 48

	requestPayloadPtrOffset = 32
	requestPayloadLenOffset = 36
	requestReservedOffset   = 40

	resultIdentifierOffset = 32
	resultSequenceOffset   = 34
	resultCopiedOffset     = 36
	resultPayloadOffset    = 40
	resultReservedOffset   = 44
)

// DecodeEchoRequestV1 validates one complete fixed request and its payload
// range. The returned payload aliases guest memory only for the immediate host
// call; adapters must copy it before returning.
func DecodeEchoRequestV1(memory []byte, ptr uint32) (icmpns.Request, bool) {
	encoded, ok := abicore.Slice(memory, ptr, EchoRequestV1Size)
	if !ok || binary.LittleEndian.Uint64(encoded[requestReservedOffset:]) != 0 {
		return icmpns.Request{}, false
	}
	endpoint, ok := abicore.DecodeEndpointV1(memory, ptr)
	if !ok || !endpoint.Address.Is4() || endpoint.Port != 0 || endpoint.ScopeID != 0 || endpoint.FlowInfo != 0 {
		return icmpns.Request{}, false
	}
	payloadPtr := binary.LittleEndian.Uint32(encoded[requestPayloadPtrOffset : requestPayloadPtrOffset+4])
	payloadLen := binary.LittleEndian.Uint32(encoded[requestPayloadLenOffset : requestPayloadLenOffset+4])
	payload, ok := abicore.Slice(memory, payloadPtr, payloadLen)
	if !ok {
		return icmpns.Request{}, false
	}
	request := icmpns.Request{Destination: endpoint.Address, Payload: payload}
	return request, request.Valid()
}

// EncodeEchoRequestV1 constructs one canonical fixed request for tooling and
// tests. Payload bytes must already exist at payloadPtr.
func EncodeEchoRequestV1(memory []byte, ptr uint32, destination nscore.Endpoint, payloadPtr, payloadLen uint32) bool {
	if !destination.Valid() || !destination.Address.Is4() || destination.Port != 0 || destination.ScopeID != 0 || destination.FlowInfo != 0 {
		return false
	}
	if !abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: ptr, Length: EchoRequestV1Size},
		abicore.Range{Ptr: payloadPtr, Length: payloadLen},
	) {
		return false
	}
	var encoded [EchoRequestV1Size]byte
	if !abicore.EncodeEndpointV1(encoded[:], 0, destination) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[requestPayloadPtrOffset:requestPayloadPtrOffset+4], payloadPtr)
	binary.LittleEndian.PutUint32(encoded[requestPayloadLenOffset:requestPayloadLenOffset+4], payloadLen)
	output, _ := abicore.Slice(memory, ptr, EchoRequestV1Size)
	copy(output, encoded[:])
	return true
}

// CheckEchoV1 validates the request, its indirect payload, and a disjoint
// handle output before any backend work begins.
func CheckEchoV1(memory []byte, requestPtr, handlePtr uint32) bool {
	encoded, ok := abicore.Slice(memory, requestPtr, EchoRequestV1Size)
	if !ok {
		return false
	}
	payloadPtr := binary.LittleEndian.Uint32(encoded[requestPayloadPtrOffset : requestPayloadPtrOffset+4])
	payloadLen := binary.LittleEndian.Uint32(encoded[requestPayloadLenOffset : requestPayloadLenOffset+4])
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: requestPtr, Length: EchoRequestV1Size},
		abicore.Range{Ptr: payloadPtr, Length: payloadLen},
		abicore.Range{Ptr: handlePtr, Length: abicore.HandleV1Size},
	)
}

// CheckResultV1 validates disjoint payload and fixed result output ranges.
func CheckResultV1(memory []byte, payloadPtr, payloadLen, resultPtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: payloadPtr, Length: payloadLen},
		abicore.Range{Ptr: resultPtr, Length: EchoResultV1Size},
	)
}

// EncodeEchoResultV1 atomically writes one validated result.
func EncodeEchoResultV1(memory []byte, ptr uint32, result icmpns.Result, payloadCapacity int) bool {
	if !result.Valid(payloadCapacity) {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, EchoResultV1Size)
	if !ok {
		return false
	}
	var encoded [EchoResultV1Size]byte
	if !abicore.EncodeEndpointV1(encoded[:], 0, nscore.Endpoint{Address: result.Source}) {
		return false
	}
	binary.LittleEndian.PutUint16(encoded[resultIdentifierOffset:resultIdentifierOffset+2], result.Identifier)
	binary.LittleEndian.PutUint16(encoded[resultSequenceOffset:resultSequenceOffset+2], result.Sequence)
	binary.LittleEndian.PutUint32(encoded[resultCopiedOffset:resultCopiedOffset+4], uint32(result.Copied))
	binary.LittleEndian.PutUint32(encoded[resultPayloadOffset:resultPayloadOffset+4], uint32(result.PayloadBytes))
	binary.LittleEndian.PutUint32(encoded[resultReservedOffset:resultReservedOffset+4], 0)
	copy(output, encoded[:])
	return true
}
