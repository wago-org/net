// Package tcp contains the fixed-width TCP guest ABI codecs.
package tcp

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

const (
	// StreamV1Size is the encoded size of wago_net_tcp_stream_v1.
	StreamV1Size uint32 = 72
	// IOResultV1Size is the encoded size of wago_net_tcp_io_result_v1.
	IOResultV1Size uint32 = 8
)

// CheckListenV1 validates a complete endpoint input and listener-handle output
// before a listen implementation changes backend state. Nonempty input and
// output ranges must be disjoint.
func CheckListenV1(memory []byte, endpointPtr, listenerPtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: endpointPtr, Length: abicore.AddressV1Size},
		abicore.Range{Ptr: listenerPtr, Length: abicore.HandleV1Size},
	)
}

// CheckCreateV1 validates a complete endpoint input and stream-result output
// before a connect implementation changes backend state. Nonempty input and
// output ranges must be disjoint.
func CheckCreateV1(memory []byte, endpointPtr, streamPtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: endpointPtr, Length: abicore.AddressV1Size},
		abicore.Range{Ptr: streamPtr, Length: StreamV1Size},
	)
}

// CheckIOV1 validates the complete payload and result ranges before a read
// consumes bytes or a write accepts bytes. Nonempty ranges must be disjoint.
func CheckIOV1(memory []byte, payloadPtr, payloadLength, resultPtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: payloadPtr, Length: payloadLength},
		abicore.Range{Ptr: resultPtr, Length: IOResultV1Size},
	)
}

// EncodeStreamV1 atomically writes an opaque handle plus local and remote
// endpoints after validating the entire fixed-width output.
func EncodeStreamV1(memory []byte, ptr uint32, handle resource.Handle, local, remote nscore.Endpoint) bool {
	if handle == 0 || !local.Valid() || !remote.Valid() {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, StreamV1Size)
	if !ok {
		return false
	}
	var encoded [StreamV1Size]byte
	binary.LittleEndian.PutUint64(encoded[0:8], uint64(handle))
	if !abicore.EncodeEndpointV1(encoded[:], 8, local) || !abicore.EncodeEndpointV1(encoded[:], 40, remote) {
		return false
	}
	copy(output, encoded[:])
	return true
}

// EncodeIOResultV1 writes partial read/write progress only for an IOReady
// result. Would-block and EOF are represented by the host status and leave the
// output unchanged.
func EncodeIOResultV1(memory []byte, ptr uint32, result nscore.IOResult, bufferSize int) bool {
	if !result.Valid(bufferSize) || result.State != nscore.IOReady || uint64(result.Bytes) > uint64(^uint32(0)) {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, IOResultV1Size)
	if !ok {
		return false
	}
	var encoded [IOResultV1Size]byte
	binary.LittleEndian.PutUint32(encoded[0:4], uint32(result.Bytes))
	copy(output, encoded[:])
	return true
}
