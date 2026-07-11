package abi

import (
	"encoding/binary"
	"net/netip"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
)

const (
	// HandleV1Size is the encoded size of one opaque resource handle.
	HandleV1Size uint32 = 8

	// UDPReceiveResultV1Size is the encoded size of
	// wago_net_udp_receive_result_v1.
	UDPReceiveResultV1Size  uint32 = 48
	UDPReceiveFlagTruncated uint32 = 1
	udpReceiveFlagMaskV1           = UDPReceiveFlagTruncated

	// TCPStreamV1Size is the encoded size of wago_net_tcp_stream_v1.
	TCPStreamV1Size uint32 = 72
	// TCPIOResultV1Size is the encoded size of wago_net_tcp_io_result_v1.
	TCPIOResultV1Size uint32 = 8

	// PollBudgetV1Size is the encoded size of wago_net_poll_budget_v1.
	PollBudgetV1Size uint32 = 24
	// PollEventV1Size is the encoded size of wago_net_poll_event_v1.
	PollEventV1Size uint32 = 16
	// PollResultV1Size is the encoded size of wago_net_poll_result_v1.
	PollResultV1Size uint32 = 24
)

// Range is one checked guest-memory interval. It never retains guest memory.
type Range struct {
	Ptr    uint32
	Length uint32
}

// CheckRanges validates every range and optionally requires all nonempty ranges
// to be pairwise disjoint. It performs no guest-memory mutation.
func CheckRanges(memory []byte, disjoint bool, ranges ...Range) bool {
	for i, current := range ranges {
		if _, ok := Slice(memory, current.Ptr, current.Length); !ok {
			return false
		}
		if !disjoint || current.Length == 0 {
			continue
		}
		currentEnd := uint64(current.Ptr) + uint64(current.Length)
		for _, previous := range ranges[:i] {
			if previous.Length == 0 {
				continue
			}
			previousEnd := uint64(previous.Ptr) + uint64(previous.Length)
			if uint64(current.Ptr) < previousEnd && uint64(previous.Ptr) < currentEnd {
				return false
			}
		}
	}
	return true
}

// Elements validates a fixed-width array with overflow-safe count arithmetic.
func Elements(memory []byte, ptr, count, size uint32) ([]byte, bool) {
	length := uint64(count) * uint64(size)
	if length > uint64(^uint32(0)) {
		return nil, false
	}
	return Slice(memory, ptr, uint32(length))
}

// DecodeEndpointV1 decodes one address into the backend-neutral endpoint form.
func DecodeEndpointV1(memory []byte, ptr uint32) (namespace.Endpoint, bool) {
	address, ok := DecodeAddressV1(memory, ptr)
	if !ok {
		return namespace.Endpoint{}, false
	}
	var ip netip.Addr
	switch address.Family {
	case AddressFamilyIPv4:
		ip = netip.AddrFrom4([4]byte(address.Address[:4]))
	case AddressFamilyIPv6:
		ip = netip.AddrFrom16(address.Address)
	default:
		return namespace.Endpoint{}, false
	}
	endpoint := namespace.Endpoint{Address: ip, Port: address.Port, ScopeID: address.ScopeID, FlowInfo: address.FlowInfo}
	return endpoint, endpoint.Valid()
}

// EncodeEndpointV1 validates the endpoint and complete output before mutation.
func EncodeEndpointV1(memory []byte, ptr uint32, endpoint namespace.Endpoint) bool {
	if !endpoint.Valid() {
		return false
	}
	address := Address{Port: endpoint.Port, ScopeID: endpoint.ScopeID, FlowInfo: endpoint.FlowInfo}
	if endpoint.Address.Is4() {
		address.Family = AddressFamilyIPv4
		bytes := endpoint.Address.As4()
		copy(address.Address[:4], bytes[:])
	} else {
		address.Family = AddressFamilyIPv6
		address.Address = endpoint.Address.As16()
	}
	return EncodeAddressV1(memory, ptr, address)
}

// EncodeHandleV1 writes one nonzero opaque handle after checking the full range.
func EncodeHandleV1(memory []byte, ptr uint32, handle resource.Handle) bool {
	if handle == 0 {
		return false
	}
	b, ok := Slice(memory, ptr, HandleV1Size)
	if !ok {
		return false
	}
	binary.LittleEndian.PutUint64(b, uint64(handle))
	return true
}

// EncodeUDPReceiveResultV1 writes source, exact copied/original lengths, and
// truncation metadata after validating the result and complete output range.
func EncodeUDPReceiveResultV1(memory []byte, ptr uint32, result namespace.DatagramResult, bufferSize int) bool {
	if !result.Valid(bufferSize) || !result.Ready || uint64(result.Copied) > uint64(^uint32(0)) || uint64(result.DatagramBytes) > uint64(^uint32(0)) {
		return false
	}
	b, ok := Slice(memory, ptr, UDPReceiveResultV1Size)
	if !ok {
		return false
	}
	var encoded [UDPReceiveResultV1Size]byte
	if !EncodeEndpointV1(encoded[:], 0, result.Source) {
		return false
	}
	binary.LittleEndian.PutUint32(encoded[32:36], uint32(result.Copied))
	binary.LittleEndian.PutUint32(encoded[36:40], uint32(result.DatagramBytes))
	if result.Truncated {
		binary.LittleEndian.PutUint32(encoded[40:44], UDPReceiveFlagTruncated)
	}
	copy(b, encoded[:])
	return true
}

// CheckTCPCreateV1 validates a complete endpoint input and stream-result output
// before a listen/connect implementation changes backend state. Nonempty input
// and output ranges must be disjoint.
func CheckTCPCreateV1(memory []byte, endpointPtr, streamPtr uint32) bool {
	return CheckRanges(memory, true,
		Range{Ptr: endpointPtr, Length: AddressV1Size},
		Range{Ptr: streamPtr, Length: TCPStreamV1Size},
	)
}

// CheckTCPIOV1 validates the complete payload and result ranges before a read
// consumes bytes or a write accepts bytes. Nonempty ranges must be disjoint.
func CheckTCPIOV1(memory []byte, payloadPtr, payloadLength, resultPtr uint32) bool {
	return CheckRanges(memory, true,
		Range{Ptr: payloadPtr, Length: payloadLength},
		Range{Ptr: resultPtr, Length: TCPIOResultV1Size},
	)
}

// EncodeTCPStreamV1 atomically writes an opaque handle plus local and remote
// endpoints after validating the entire fixed-width output.
func EncodeTCPStreamV1(memory []byte, ptr uint32, handle resource.Handle, local, remote namespace.Endpoint) bool {
	if handle == 0 || !local.Valid() || !remote.Valid() {
		return false
	}
	output, ok := Slice(memory, ptr, TCPStreamV1Size)
	if !ok {
		return false
	}
	var encoded [TCPStreamV1Size]byte
	binary.LittleEndian.PutUint64(encoded[0:8], uint64(handle))
	if !EncodeEndpointV1(encoded[:], 8, local) || !EncodeEndpointV1(encoded[:], 40, remote) {
		return false
	}
	copy(output, encoded[:])
	return true
}

// EncodeTCPIOResultV1 writes partial read/write progress only for an IOReady
// result. Would-block and EOF are represented by the host status and leave the
// output unchanged.
func EncodeTCPIOResultV1(memory []byte, ptr uint32, result namespace.IOResult, bufferSize int) bool {
	if !result.Valid(bufferSize) || result.State != namespace.IOReady || uint64(result.Bytes) > uint64(^uint32(0)) {
		return false
	}
	output, ok := Slice(memory, ptr, TCPIOResultV1Size)
	if !ok {
		return false
	}
	var encoded [TCPIOResultV1Size]byte
	binary.LittleEndian.PutUint32(encoded[0:4], uint32(result.Bytes))
	copy(output, encoded[:])
	return true
}

// DecodePollBudgetV1 decodes a finite, structurally valid coordinator budget.
func DecodePollBudgetV1(memory []byte, ptr uint32) (readiness.Budget, bool) {
	b, ok := Slice(memory, ptr, PollBudgetV1Size)
	if !ok {
		return readiness.Budget{}, false
	}
	budget := readiness.Budget{
		Scans:           binary.LittleEndian.Uint32(b[0:4]),
		Events:          binary.LittleEndian.Uint32(b[4:8]),
		ServiceAttempts: binary.LittleEndian.Uint32(b[8:12]),
		Service: namespace.ServiceBudget{
			Packets:    binary.LittleEndian.Uint32(b[12:16]),
			Bytes:      binary.LittleEndian.Uint32(b[16:20]),
			Operations: binary.LittleEndian.Uint32(b[20:24]),
		},
	}
	return budget, budget.Valid()
}

// EncodePollEventsV1 validates all events and the complete array before writing.
func EncodePollEventsV1(memory []byte, ptr uint32, events []readiness.Event) bool {
	b, ok := Elements(memory, ptr, uint32(len(events)), PollEventV1Size)
	if !ok {
		return false
	}
	for _, event := range events {
		if !event.Valid() {
			return false
		}
	}
	clear(b)
	for i, event := range events {
		offset := i * int(PollEventV1Size)
		binary.LittleEndian.PutUint64(b[offset:offset+8], uint64(event.Handle))
		binary.LittleEndian.PutUint32(b[offset+8:offset+12], uint32(event.Readiness))
	}
	return true
}

// EncodePollResultV1 validates the report against budget and writes exact work
// counters after checking the complete output range.
func EncodePollResultV1(memory []byte, ptr uint32, report readiness.Report, budget readiness.Budget) bool {
	if !report.ValidFor(budget) {
		return false
	}
	b, ok := Slice(memory, ptr, PollResultV1Size)
	if !ok {
		return false
	}
	binary.LittleEndian.PutUint32(b[0:4], report.Events)
	binary.LittleEndian.PutUint32(b[4:8], report.Scanned)
	binary.LittleEndian.PutUint32(b[8:12], report.ServiceAttempts)
	binary.LittleEndian.PutUint32(b[12:16], report.ServiceCompleted)
	binary.LittleEndian.PutUint32(b[16:20], report.StaleRegistrations)
	binary.LittleEndian.PutUint32(b[20:24], 0)
	return true
}

// ValidUDPReceiveFlagsV1 reports whether flags contains only defined v1 bits.
func ValidUDPReceiveFlagsV1(flags uint32) bool { return flags&^udpReceiveFlagMaskV1 == 0 }
