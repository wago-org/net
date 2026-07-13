// Package ntp contains the fixed-width NTP guest ABI codec.
package ntp

import (
	"encoding/binary"
	"time"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
)

const (
	// SampleV1Size is one server address, corrected UTC instant, offset,
	// round-trip delay, stratum metadata, reference ID, and reserved padding.
	SampleV1Size uint32 = 72

	correctedSecondsOffset = 32
	correctedNanosOffset   = 40
	stratumOffset          = 44
	leapOffset             = 45
	versionOffset          = 46
	flagsReservedOffset    = 47
	offsetNanosOffset      = 48
	roundTripNanosOffset   = 56
	referenceIDOffset      = 64
	reservedOffset         = 68
)

// CheckSyncV1 validates one complete handle output before backend work.
func CheckSyncV1(memory []byte, handlePtr uint32) bool {
	return abicore.CheckRanges(memory, false, abicore.Range{Ptr: handlePtr, Length: abicore.HandleV1Size})
}

// CheckResultV1 validates one complete sample output before consuming a result.
func CheckResultV1(memory []byte, resultPtr uint32) bool {
	return abicore.CheckRanges(memory, false, abicore.Range{Ptr: resultPtr, Length: SampleV1Size})
}

// EncodeSampleV1 atomically writes one validated sample.
func EncodeSampleV1(memory []byte, ptr uint32, sample ntpns.Sample) bool {
	if !sample.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, SampleV1Size)
	if !ok {
		return false
	}
	var encoded [SampleV1Size]byte
	if !abicore.EncodeEndpointV1(encoded[:], 0, nscore.Endpoint{Address: sample.Server}) {
		return false
	}
	binary.LittleEndian.PutUint64(encoded[correctedSecondsOffset:correctedSecondsOffset+8], uint64(sample.CorrectedTime.Unix()))
	binary.LittleEndian.PutUint32(encoded[correctedNanosOffset:correctedNanosOffset+4], uint32(sample.CorrectedTime.Nanosecond()))
	encoded[stratumOffset] = sample.Stratum
	encoded[leapOffset] = sample.Leap
	encoded[versionOffset] = sample.Version
	encoded[flagsReservedOffset] = 0
	binary.LittleEndian.PutUint64(encoded[offsetNanosOffset:offsetNanosOffset+8], uint64(int64(sample.Offset)))
	binary.LittleEndian.PutUint64(encoded[roundTripNanosOffset:roundTripNanosOffset+8], uint64(int64(sample.RoundTripDelay)))
	copy(encoded[referenceIDOffset:referenceIDOffset+4], sample.ReferenceID[:])
	binary.LittleEndian.PutUint32(encoded[reservedOffset:reservedOffset+4], 0)
	copy(output, encoded[:])
	return true
}

// DecodeSampleV1 decodes canonical sample bytes for host tooling and tests.
func DecodeSampleV1(memory []byte, ptr uint32) (ntpns.Sample, bool) {
	encoded, ok := abicore.Slice(memory, ptr, SampleV1Size)
	if !ok || encoded[flagsReservedOffset] != 0 || binary.LittleEndian.Uint32(encoded[reservedOffset:reservedOffset+4]) != 0 {
		return ntpns.Sample{}, false
	}
	endpoint, ok := abicore.DecodeEndpointV1(memory, ptr)
	if !ok || !endpoint.Address.Is4() || endpoint.Port != 0 || endpoint.ScopeID != 0 || endpoint.FlowInfo != 0 {
		return ntpns.Sample{}, false
	}
	nanos := binary.LittleEndian.Uint32(encoded[correctedNanosOffset : correctedNanosOffset+4])
	if nanos >= uint32(time.Second) {
		return ntpns.Sample{}, false
	}
	sample := ntpns.Sample{
		Server:         endpoint.Address,
		CorrectedTime:  time.Unix(int64(binary.LittleEndian.Uint64(encoded[correctedSecondsOffset:correctedSecondsOffset+8])), int64(nanos)).UTC(),
		Offset:         time.Duration(int64(binary.LittleEndian.Uint64(encoded[offsetNanosOffset : offsetNanosOffset+8]))),
		RoundTripDelay: time.Duration(int64(binary.LittleEndian.Uint64(encoded[roundTripNanosOffset : roundTripNanosOffset+8]))),
		Stratum:        encoded[stratumOffset],
		Leap:           encoded[leapOffset],
		Version:        encoded[versionOffset],
	}
	copy(sample.ReferenceID[:], encoded[referenceIDOffset:referenceIDOffset+4])
	return sample, sample.Valid()
}
