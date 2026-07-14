// Package linklocal4 contains fixed-width checked IPv4 link-local guest ABI codecs.
package linklocal4

import (
	"encoding/binary"
	"net/netip"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
)

const (
	RequestV1Size uint32 = 32
	ResultV1Size  uint32 = 48

	ResultFlagApplied uint32 = 1

	resultSubnetBits = 32
	resultConflicts  = 36
	resultFlags      = 40
	resultReserved   = 44
)

func CheckRequestV1(memory []byte, requestPtr, handlePtr uint32) bool {
	return abicore.CheckRanges(memory, true, abicore.Range{Ptr: requestPtr, Length: RequestV1Size}, abicore.Range{Ptr: handlePtr, Length: abicore.HandleV1Size})
}

func DecodeRequestV1(memory []byte, ptr uint32) (linklocalns.Request, bool) {
	endpoint, ok := abicore.DecodeEndpointV1(memory, ptr)
	if !ok || endpoint.Port != 0 || endpoint.ScopeID != 0 || endpoint.FlowInfo != 0 || !endpoint.Address.Is4() {
		return linklocalns.Request{}, false
	}
	request := linklocalns.Request{}
	if !endpoint.Address.IsUnspecified() {
		request.FirstCandidate = endpoint.Address
	}
	return request, request.Valid()
}

func EncodeRequestV1(memory []byte, ptr uint32, request linklocalns.Request) bool {
	if !request.Valid() {
		return false
	}
	address := request.FirstCandidate
	if !address.IsValid() {
		address = netip.IPv4Unspecified()
	}
	return abicore.EncodeEndpointV1(memory, ptr, nscore.Endpoint{Address: address})
}

func EncodeResultV1(memory []byte, ptr uint32, result linklocalns.Result) bool {
	if !result.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, ResultV1Size)
	if !ok {
		return false
	}
	var encoded [ResultV1Size]byte
	if !abicore.EncodeEndpointV1(encoded[:], 0, nscore.Endpoint{Address: result.Address}) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[resultSubnetBits:resultSubnetBits+4], uint32(result.Subnet.Bits()))
	binary.LittleEndian.PutUint32(encoded[resultConflicts:resultConflicts+4], uint32(result.Conflicts))
	if result.Applied {
		binary.LittleEndian.PutUint32(encoded[resultFlags:resultFlags+4], ResultFlagApplied)
	}
	binary.LittleEndian.PutUint32(encoded[resultReserved:resultReserved+4], 0)
	copy(output, encoded[:])
	return true
}
