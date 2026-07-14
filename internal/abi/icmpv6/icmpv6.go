// Package icmpv6 contains fixed-width checked ICMPv6/NDP guest ABI codecs.
package icmpv6

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
)

const (
	EchoRequestV1Size uint32 = 48
	EchoResultV1Size  uint32 = 48
	NeighborKeyV1Size uint32 = 32
	NeighborV1Size    uint32 = 40
	OperationsV1Size  uint32 = 4

	requestPayloadPtrOffset = 32
	requestPayloadLenOffset = 36
	requestReservedOffset   = 40
	resultIdentifierOffset  = 32
	resultSequenceOffset    = 34
	resultCopiedOffset      = 36
	resultPayloadOffset     = 40
	resultReservedOffset    = 44
	neighborMACOffset       = 32
	neighborReservedOffset  = 38
)

func DecodeEchoRequestV1(memory []byte, ptr uint32) (icmpns.EchoRequest, bool) {
	encoded, ok := abicore.Slice(memory, ptr, EchoRequestV1Size)
	if !ok || binary.LittleEndian.Uint64(encoded[requestReservedOffset:]) != 0 {
		return icmpns.EchoRequest{}, false
	}
	endpoint, ok := abicore.DecodeEndpointV1(memory, ptr)
	if !ok || !endpoint.Address.Is6() || endpoint.Port != 0 || endpoint.FlowInfo != 0 {
		return icmpns.EchoRequest{}, false
	}
	payloadPtr := binary.LittleEndian.Uint32(encoded[requestPayloadPtrOffset : requestPayloadPtrOffset+4])
	payloadLen := binary.LittleEndian.Uint32(encoded[requestPayloadLenOffset : requestPayloadLenOffset+4])
	payload, ok := abicore.Slice(memory, payloadPtr, payloadLen)
	if !ok {
		return icmpns.EchoRequest{}, false
	}
	request := icmpns.EchoRequest{Destination: endpoint.Address, ScopeID: endpoint.ScopeID, Payload: payload}
	return request, request.Valid()
}

func EncodeEchoRequestV1(memory []byte, ptr uint32, destination nscore.Endpoint, payloadPtr, payloadLen uint32) bool {
	if !destination.Valid() || !destination.Address.Is6() || destination.Port != 0 || destination.FlowInfo != 0 ||
		!abicore.CheckRanges(memory, true, abicore.Range{Ptr: ptr, Length: EchoRequestV1Size}, abicore.Range{Ptr: payloadPtr, Length: payloadLen}) {
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

func CheckEchoResultV1(memory []byte, payloadPtr, payloadLen, resultPtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: payloadPtr, Length: payloadLen},
		abicore.Range{Ptr: resultPtr, Length: EchoResultV1Size},
	)
}

func EncodeEchoResultV1(memory []byte, ptr uint32, result icmpns.EchoResult, payloadCapacity int) bool {
	if !result.Valid(payloadCapacity) {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, EchoResultV1Size)
	if !ok {
		return false
	}
	var encoded [EchoResultV1Size]byte
	if !abicore.EncodeEndpointV1(encoded[:], 0, nscore.Endpoint{Address: result.Source, ScopeID: result.ScopeID}) {
		return false
	}
	binary.LittleEndian.PutUint16(encoded[resultIdentifierOffset:resultIdentifierOffset+2], result.Identifier)
	binary.LittleEndian.PutUint16(encoded[resultSequenceOffset:resultSequenceOffset+2], result.Sequence)
	binary.LittleEndian.PutUint32(encoded[resultCopiedOffset:resultCopiedOffset+4], uint32(result.Copied))
	binary.LittleEndian.PutUint32(encoded[resultPayloadOffset:resultPayloadOffset+4], uint32(result.PayloadBytes))
	copy(output, encoded[:])
	return true
}

func DecodeNeighborKeyV1(memory []byte, ptr uint32) (icmpns.NeighborRequest, bool) {
	endpoint, ok := abicore.DecodeEndpointV1(memory, ptr)
	if !ok || !endpoint.Address.Is6() || endpoint.Port != 0 || endpoint.FlowInfo != 0 {
		return icmpns.NeighborRequest{}, false
	}
	request := icmpns.NeighborRequest{Address: endpoint.Address, ScopeID: endpoint.ScopeID}
	return request, request.Valid()
}

func EncodeNeighborKeyV1(memory []byte, ptr uint32, request icmpns.NeighborRequest) bool {
	return request.Valid() && abicore.EncodeEndpointV1(memory, ptr, nscore.Endpoint{Address: request.Address, ScopeID: request.ScopeID})
}

func DecodeNeighborV1(memory []byte, ptr uint32) (icmpns.Neighbor, bool) {
	encoded, ok := abicore.Slice(memory, ptr, NeighborV1Size)
	if !ok || binary.LittleEndian.Uint16(encoded[neighborReservedOffset:neighborReservedOffset+2]) != 0 {
		return icmpns.Neighbor{}, false
	}
	request, ok := DecodeNeighborKeyV1(memory, ptr)
	if !ok {
		return icmpns.Neighbor{}, false
	}
	neighbor := icmpns.Neighbor{Address: request.Address, ScopeID: request.ScopeID, MAC: [6]byte(encoded[neighborMACOffset : neighborMACOffset+6])}
	return neighbor, neighbor.Valid()
}

func EncodeNeighborV1(memory []byte, ptr uint32, neighbor icmpns.Neighbor) bool {
	if !neighbor.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, NeighborV1Size)
	if !ok {
		return false
	}
	var encoded [NeighborV1Size]byte
	if !EncodeNeighborKeyV1(encoded[:], 0, icmpns.NeighborRequest{Address: neighbor.Address, ScopeID: neighbor.ScopeID}) {
		return false
	}
	copy(encoded[neighborMACOffset:neighborMACOffset+6], neighbor.MAC[:])
	copy(output, encoded[:])
	return true
}

func EncodeOperationsV1(memory []byte, ptr uint32, operations icmpns.Operations) bool {
	if operations&^icmpns.SupportedOperations != 0 {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, OperationsV1Size)
	if !ok {
		return false
	}
	binary.LittleEndian.PutUint32(output, uint32(operations))
	return true
}
