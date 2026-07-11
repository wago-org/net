// Package namespace temporarily aggregates protocol contracts while their
// narrow compilation units are extracted. Shared ownership, lifecycle, service,
// readiness, endpoint, and failure contracts live in namespace/core.
package namespace

import (
	"net/netip"
	"strings"

	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
)

type Endpoint = nscore.Endpoint
type Progress = nscore.Progress

const (
	ProgressDone       = nscore.ProgressDone
	ProgressWouldBlock = nscore.ProgressWouldBlock
	ProgressInProgress = nscore.ProgressInProgress
)

type IOState = nscore.IOState

const (
	IOReady      = nscore.IOReady
	IOWouldBlock = nscore.IOWouldBlock
	IOEOF        = nscore.IOEOF
)

type IOResult = nscore.IOResult
type Readiness = nscore.Readiness

const (
	ReadyReadable  = nscore.ReadyReadable
	ReadyWritable  = nscore.ReadyWritable
	ReadyAccept    = nscore.ReadyAccept
	ReadyConnected = nscore.ReadyConnected
	ReadyDNSResult = nscore.ReadyDNSResult
	ReadyError     = nscore.ReadyError
	ReadyClosed    = nscore.ReadyClosed
)

type Pollable = nscore.Pollable
type Resource = nscore.Resource
type ServiceBudget = nscore.ServiceBudget
type ServiceReport = nscore.ServiceReport

// Namespace is the temporary aggregate of the protocol-neutral base plus every
// protocol facet. New shared code must depend only on namespace/core.Namespace.
type Namespace interface {
	nscore.Namespace
	TryBindUDP(local Endpoint) (UDPSocket, Progress, error)
	TryResolve(request DNSRequest) (DNSQuery, Progress, error)
}

// UDPSocket preserves datagram boundaries. TrySend accepts the whole datagram
// on ProgressDone and accepts none on other progress values.
type UDPSocket interface {
	Resource
	LocalEndpoint() Endpoint
	TryReceive(dst []byte) (DatagramResult, error)
	TrySend(payload []byte, remote Endpoint) (Progress, error)
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

type TCPListener = tcpns.Listener
type TCPStream = tcpns.Stream

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
	Cancel() error
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
