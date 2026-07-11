// Package core defines the backend-neutral networking contracts shared by all
// protocol adapters. Every operation that may wait for network progress is a
// single nonblocking Try call; implementations must never spin, sleep, or apply
// retry backoff inside these methods.
package core

import "net/netip"

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
func (p Progress) Valid() bool { return p >= ProgressDone && p <= ProgressInProgress }

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

// Namespace is the protocol-neutral ownership and service contract for one
// backend namespace. Protocol packages assert their own narrow facet on the same
// object; core never imports those facets.
type Namespace interface {
	Resource
	TryService(budget ServiceBudget) (ServiceReport, Progress, error)
}

// NamespaceCarrier preserves the concrete namespace behind the quota-owning
// resource wrapper so protocol operation packages can assert narrow facets.
type NamespaceCarrier interface {
	NamespaceBackend() Namespace
}

// ServiceBudget bounds one manual backend service attempt in every dimension.
type ServiceBudget struct {
	Packets    uint32
	Bytes      uint32
	Operations uint32
}

// Valid requires each independent bound to be finite and nonzero.
func (b ServiceBudget) Valid() bool { return b.Packets > 0 && b.Bytes > 0 && b.Operations > 0 }

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
