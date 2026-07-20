// Package tls contains fixed-width TLS guest ABI codecs.
package tls

import (
	"encoding/binary"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/resource"
)

const (
	StreamV1Size         uint32 = 72
	IOResultV1Size       uint32 = 8
	ConnectionInfoV1Size uint32 = 144
	MaxALPNV1Bytes       uint32 = 32
)

func CheckCreateV1(memory []byte, endpointPtr, serverNamePtr, serverNameLength, streamPtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: endpointPtr, Length: abicore.AddressV1Size},
		abicore.Range{Ptr: serverNamePtr, Length: serverNameLength},
		abicore.Range{Ptr: streamPtr, Length: StreamV1Size},
	)
}

func CheckIOV1(memory []byte, payloadPtr, payloadLength, resultPtr uint32) bool {
	return abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: payloadPtr, Length: payloadLength},
		abicore.Range{Ptr: resultPtr, Length: IOResultV1Size},
	)
}

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

func EncodeConnectionInfoV1(memory []byte, ptr uint32, info tlsns.ConnectionInfo) bool {
	if !info.Valid(int(MaxALPNV1Bytes)) {
		return false
	}
	output, ok := abicore.Slice(memory, ptr, ConnectionInfoV1Size)
	if !ok {
		return false
	}
	var encoded [ConnectionInfoV1Size]byte
	if !abicore.EncodeEndpointV1(encoded[:], 0, info.LocalEndpoint) || !abicore.EncodeEndpointV1(encoded[:], 32, info.RemoteEndpoint) {
		return false
	}
	binary.LittleEndian.PutUint16(encoded[64:66], info.TLSVersion)
	binary.LittleEndian.PutUint16(encoded[66:68], info.CipherSuite)
	var flags uint32
	if info.Resumed {
		flags |= 1 << 0
	}
	if info.Role == tlsns.RoleServer {
		flags |= 1 << 1
	}
	if info.PeerAuthenticated {
		flags |= 1 << 2
	}
	binary.LittleEndian.PutUint32(encoded[68:72], flags)
	binary.LittleEndian.PutUint32(encoded[72:76], uint32(info.VerifiedIdentity))
	binary.LittleEndian.PutUint32(encoded[76:80], uint32(len(info.NegotiatedALPN)))
	copy(encoded[80:112], info.NegotiatedALPN)
	copy(encoded[112:144], info.PeerLeafSPKI256[:])
	copy(output, encoded[:])
	return true
}
