// Package udp contains the fixed-width UDP guest ABI codecs.
package udp

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	"github.com/wago-org/net/internal/namespace"
)

const (
	// ReceiveResultV1Size is the encoded size of
	// wago_net_udp_receive_result_v1.
	ReceiveResultV1Size  uint32 = 48
	ReceiveFlagTruncated uint32 = 1
	receiveFlagMaskV1           = ReceiveFlagTruncated
)

// EncodeReceiveResultV1 writes source, exact copied/original lengths, and
// truncation metadata after validating the result and complete output range.
func EncodeReceiveResultV1(memory []byte, ptr uint32, result namespace.DatagramResult, bufferSize int) bool {
	if !result.Valid(bufferSize) || !result.Ready || uint64(result.Copied) > uint64(^uint32(0)) || uint64(result.DatagramBytes) > uint64(^uint32(0)) {
		return false
	}
	b, ok := abicore.Slice(memory, ptr, ReceiveResultV1Size)
	if !ok {
		return false
	}
	var encoded [ReceiveResultV1Size]byte
	if !abicore.EncodeEndpointV1(encoded[:], 0, result.Source) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[32:36], uint32(result.Copied))
	binary.LittleEndian.PutUint32(encoded[36:40], uint32(result.DatagramBytes))
	if result.Truncated {
		binary.LittleEndian.PutUint32(encoded[40:44], ReceiveFlagTruncated)
	}
	copy(b, encoded[:])
	return true
}

// ValidReceiveFlagsV1 reports whether flags contains only defined v1 bits.
func ValidReceiveFlagsV1(flags uint32) bool { return flags&^receiveFlagMaskV1 == 0 }
