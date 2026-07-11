// Package namespace defines the backend-neutral networking contract used by
// protocol adapters. Every operation that may wait for network progress is a
// single nonblocking Try call; implementations must never spin, sleep, or apply
// retry backoff inside these methods.
package namespace

import (
	"net/netip"
	"strings"
)

// Endpoint is a backend-neutral IP endpoint. ScopeID is the numeric IPv6 zone
// selected by the host configuration; netip textual zones are not accepted.
type Endpoint struct {
	Address  netip.Addr
	Port     uint16
	ScopeID  uint32
	FlowInfo uint32
}

// Valid reports whether an endpoint is structurally safe to pass to a backend.
// Authority such as wildcard, loopback, multicast, broadcast, and privileged
// port use is decided separately by policy.
func (e Endpoint) Valid() bool {
	if !e.Address.IsValid() || e.Address.Zone() != "" || e.Address.Is4In6() {
		return false
	}
	if e.Address.Is4() {
		return e.ScopeID == 0 && e.FlowInfo == 0
	}
	if e.FlowInfo > 0x000f_ffff {
		return false
	}
	return e.ScopeID == 0 || isIPv6Scoped(e.Address)
}

// Progress is the result of one nonblocking state-changing attempt.
type Progress uint8

const (
	ProgressDone Progress = iota + 1
	ProgressWouldBlock
	ProgressInProgress
)

// Valid reports whether progress is a defined contract value.
func (p Progress) Valid() bool {
	return p >= ProgressDone && p <= ProgressInProgress
}

// IOState is the result of one nonblocking stream I/O attempt.
type IOState uint8

const (
	IOReady IOState = iota + 1
	IOWouldBlock
	IOEOF
)

// IOResult describes bytes copied by one TryRead or TryWrite call.
type IOResult struct {
	Bytes int
	State IOState
}

// Valid reports whether the result can describe an operation on a buffer of
// size. Would-block and EOF never carry bytes; a ready zero-byte result is valid
// for a zero-length buffer.
func (r IOResult) Valid(size int) bool {
	if size < 0 || r.Bytes < 0 || r.Bytes > size {
		return false
	}
	switch r.State {
	case IOReady:
		return size == 0 || r.Bytes > 0
	case IOWouldBlock, IOEOF:
		return r.Bytes == 0
	default:
		return false
	}
}

// DatagramResult describes exactly one received datagram. DatagramBytes is its
// original payload size, while Copied is the prefix copied into the caller's
// buffer. The unread suffix is discarded when Truncated is true.
type DatagramResult struct {
	Copied        int
	DatagramBytes int
	Source        Endpoint
	Truncated     bool
	Ready         bool
}

// Valid reports whether the receive result is internally consistent. Ready
// distinguishes an empty datagram from no datagram.
func (r DatagramResult) Valid(size int) bool {
	if size < 0 || r.Copied < 0 || r.DatagramBytes < 0 || r.Copied > size || r.Copied > r.DatagramBytes {
		return false
	}
	if !r.Ready {
		return r.Copied == 0 && r.DatagramBytes == 0 && !r.Truncated && !r.Source.Address.IsValid()
	}
	return r.Source.Valid() && r.Truncated == (r.Copied < r.DatagramBytes)
}

// Readiness is a level-triggered snapshot. Unknown bits are invalid.
type Readiness uint32

const (
	ReadyReadable Readiness = 1 << iota
	ReadyWritable
	ReadyAccept
	ReadyConnected
	ReadyDNSResult
	ReadyError
	ReadyClosed

	readinessMask = ReadyReadable | ReadyWritable | ReadyAccept | ReadyConnected | ReadyDNSResult | ReadyError | ReadyClosed
)

// Valid reports whether no unknown readiness bits are set.
func (r Readiness) Valid() bool { return r&^readinessMask == 0 }

// Pollable exposes a lock-bounded, nonblocking readiness snapshot.
type Pollable interface {
	Readiness() Readiness
}

// Resource is the common backend lifetime contract. Close must only detach and
// discard local state; it must not wait for packets, acknowledgements, or DNS.
type Resource interface {
	Pollable
	Close() error
}

// Namespace creates protocol resources and manually services a backend. A
// method returning ProgressWouldBlock returns no new resource. TCP and DNS may
// return a resource with ProgressInProgress so callers can poll it.
type Namespace interface {
	Resource
	TryBindUDP(local Endpoint) (UDPSocket, Progress, error)
	TryListenTCP(local Endpoint) (TCPListener, Progress, error)
	TryConnectTCP(remote Endpoint) (TCPStream, Progress, error)
	TryResolve(request DNSRequest) (DNSQuery, Progress, error)
	TryService(budget ServiceBudget) (ServiceReport, Progress, error)
}

// UDPSocket preserves datagram boundaries. TrySend accepts the whole datagram
// on ProgressDone and accepts none on other progress values.
type UDPSocket interface {
	Resource
	LocalEndpoint() Endpoint
	TryReceive(dst []byte) (DatagramResult, error)
	TrySend(payload []byte, remote Endpoint) (Progress, error)
}

// TCPListener accepts only fully established streams.
type TCPListener interface {
	Resource
	LocalEndpoint() Endpoint
	TryAccept() (TCPStream, Progress, error)
}

// TCPStream exposes nonblocking connection completion and byte-stream I/O.
type TCPStream interface {
	Resource
	LocalEndpoint() Endpoint
	RemoteEndpoint() Endpoint
	TryFinishConnect() (Progress, error)
	TryRead(dst []byte) (IOResult, error)
	TryWrite(src []byte) (IOResult, error)
	TryShutdownWrite() (Progress, error)
}

// DNSRecordType is independent of any backend DNS package.
type DNSRecordType uint8

const (
	DNSRecordA DNSRecordType = iota + 1
	DNSRecordAAAA
	DNSRecordCNAME
)

// DNSRecordTypes is a request bitset.
type DNSRecordTypes uint8

const (
	DNSRecordsA DNSRecordTypes = 1 << iota
	DNSRecordsAAAA

	dnsRecordTypesMask = DNSRecordsA | DNSRecordsAAAA
)

// DNSRequest starts one bounded asynchronous lookup. Name must already be a
// normalized absolute-or-relative ASCII DNS name without a trailing dot.
type DNSRequest struct {
	Name  string
	Types DNSRecordTypes
}

// Valid reports whether a request has at least one known query type.
func (r DNSRequest) Valid() bool {
	return validDNSName(r.Name) && r.Types != 0 && r.Types&^dnsRecordTypesMask == 0
}

// DNSRecord is a backend-neutral result. Address is set only for A and AAAA;
// CanonicalName is set only for CNAME.
type DNSRecord struct {
	Name          string
	Type          DNSRecordType
	TTLSeconds    uint32
	Address       netip.Addr
	CanonicalName string
}

// Valid reports whether type-specific fields are consistent and mapped
// addresses cannot cross family policy.
func (r DNSRecord) Valid() bool {
	if !validDNSName(r.Name) {
		return false
	}
	switch r.Type {
	case DNSRecordA:
		return r.Address.Is4() && !r.Address.Is4In6() && r.CanonicalName == ""
	case DNSRecordAAAA:
		return r.Address.Is6() && !r.Address.Is4In6() && r.Address.Zone() == "" && r.CanonicalName == ""
	case DNSRecordCNAME:
		return !r.Address.IsValid() && validDNSName(r.CanonicalName)
	default:
		return false
	}
}

// DNSNext is the result of one TryNext call.
type DNSNext uint8

const (
	DNSNextReady DNSNext = iota + 1
	DNSNextWouldBlock
	DNSNextEOF
)

// DNSQuery streams bounded records without returning backend-owned slices.
type DNSQuery interface {
	Resource
	TryNext() (DNSRecord, DNSNext, error)
}

// ServiceBudget bounds one manual backend service attempt in every dimension.
type ServiceBudget struct {
	Packets    uint32
	Bytes      uint32
	Operations uint32
}

// Valid requires each independent bound to be finite and nonzero.
func (b ServiceBudget) Valid() bool {
	return b.Packets > 0 && b.Bytes > 0 && b.Operations > 0
}

// ServiceReport describes work completed by one TryService call.
type ServiceReport struct {
	Packets    uint32
	Bytes      uint32
	Operations uint32
}

// ValidFor reports whether no budget dimension was exceeded.
func (r ServiceReport) ValidFor(b ServiceBudget) bool {
	return b.Valid() && r.Packets <= b.Packets && r.Bytes <= b.Bytes && r.Operations <= b.Operations
}

// ValidResult also checks progress semantics: service either completes at least
// one bounded unit or reports would-block with a zero report. It is never an
// asynchronously in-progress operation.
func (r ServiceReport) ValidResult(b ServiceBudget, progress Progress) bool {
	if !r.ValidFor(b) {
		return false
	}
	switch progress {
	case ProgressDone:
		return r.Packets != 0 || r.Bytes != 0 || r.Operations != 0
	case ProgressWouldBlock:
		return r == (ServiceReport{})
	default:
		return false
	}
}

func isIPv6Scoped(address netip.Addr) bool {
	bytes := address.As16()
	return bytes[0] == 0xff || (bytes[0] == 0xfe && bytes[1]&0xc0 == 0x80)
}

func validDNSName(name string) bool {
	if name == "" || len(name) > 253 || name != strings.ToLower(name) || strings.HasSuffix(name, ".") {
		return false
	}
	if address, err := netip.ParseAddr(name); err == nil && address.IsValid() {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
