// Package core defines the backend-neutral networking contracts shared by all
// protocol adapters. Every operation that may wait for network progress is a
// single nonblocking Try call; implementations must never spin, sleep, or apply
// retry backoff inside these methods.
package core

import (
	"errors"
	"net/netip"
)

var (
	// ErrInvalidNamespaceComposition reports a nil base, empty service key, or
	// nil service value while assembling one exact namespace.
	ErrInvalidNamespaceComposition = errors.New("net: invalid namespace composition")
	// ErrDuplicateNamespaceService reports two selected modules claiming the
	// same protocol-local service on one namespace.
	ErrDuplicateNamespaceService = errors.New("net: duplicate namespace service")
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
	ReadyICMPv4Reply
	ReadyNTPResult
	ReadyMDNSResult
	ReadyMDNSAnnouncement
	ReadyDHCPv4Lease

	readinessMask = ReadyReadable | ReadyWritable | ReadyAccept | ReadyConnected | ReadyDNSResult | ReadyICMPv4Reply | ReadyNTPResult | ReadyMDNSResult | ReadyMDNSAnnouncement | ReadyDHCPv4Lease | ReadyError | ReadyClosed
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
// resource wrapper so protocol operation packages can resolve narrow services.
type NamespaceCarrier interface {
	NamespaceBackend() Namespace
}

// ServiceKey identifies one protocol-local namespace service without making
// shared composition code import that protocol's facet package.
type ServiceKey string

// Service binds one exact protocol-local service to a composed namespace.
type Service struct {
	Key   ServiceKey
	Value any
}

// ServiceCarrier exposes immutable protocol-local services from one shared
// namespace owner. Values are asserted only by the selecting protocol package.
type ServiceCarrier interface {
	NamespaceService(ServiceKey) (any, bool)
}

// BaseCarrier exposes the one protocol-neutral ownership/service namespace
// beneath an immutable composition for trusted host-side link integration.
type BaseCarrier interface {
	NamespaceBase() Namespace
}

// InlineServiceCapacity keeps the complete planned selective protocol suite in
// one immutable allocation. Larger experimental compositions fall back to a
// map without changing lookup semantics.
const InlineServiceCapacity = 16

// ComposeNamespace publishes one immutable namespace over base. The base owns
// readiness, bounded service, and close; selected protocol adapters remain
// reachable only through their exact service keys.
func ComposeNamespace(base Namespace, services ...Service) (Namespace, error) {
	if base == nil {
		return nil, ErrInvalidNamespaceComposition
	}
	composed := &composedNamespace{base: base}
	if len(services) <= InlineServiceCapacity {
		for i, service := range services {
			if service.Key == "" || service.Value == nil {
				return nil, ErrInvalidNamespaceComposition
			}
			for previous := 0; previous < i; previous++ {
				if composed.inline[previous].Key == service.Key {
					return nil, ErrDuplicateNamespaceService
				}
			}
			composed.inline[i] = service
		}
		composed.inlineCount = uint8(len(services))
		return composed, nil
	}
	values := make(map[ServiceKey]any, len(services))
	for _, service := range services {
		if service.Key == "" || service.Value == nil {
			return nil, ErrInvalidNamespaceComposition
		}
		if _, exists := values[service.Key]; exists {
			return nil, ErrDuplicateNamespaceService
		}
		values[service.Key] = service.Value
	}
	composed.services = values
	return composed, nil
}

// ResolveNamespaceService unwraps the quota-owned namespace resource and
// resolves key when the namespace is composed. Historical direct facet values
// remain usable by focused operation tests and backend-neutral fakes.
// ResolveNamespaceBase unwraps quota ownership and immutable composition to
// the one protocol-neutral base namespace.
func ResolveNamespaceBase(value any) Namespace {
	if carrier, ok := value.(NamespaceCarrier); ok {
		value = carrier.NamespaceBackend()
	}
	if carrier, ok := value.(BaseCarrier); ok {
		return carrier.NamespaceBase()
	}
	base, _ := value.(Namespace)
	return base
}

func ResolveNamespaceService(value any, key ServiceKey) any {
	if carrier, ok := value.(NamespaceCarrier); ok {
		value = carrier.NamespaceBackend()
	}
	if carrier, ok := value.(ServiceCarrier); ok {
		service, exists := carrier.NamespaceService(key)
		if !exists {
			return nil
		}
		return service
	}
	return value
}

// composedNamespace is immutable after construction. Adapter cleanup is
// installed on base during assembly, so closing the base tears down every
// selected service exactly once in deterministic backend order.
type composedNamespace struct {
	base        Namespace
	inlineCount uint8
	inline      [InlineServiceCapacity]Service
	services    map[ServiceKey]any
}

func (n *composedNamespace) NamespaceBase() Namespace {
	if n == nil {
		return nil
	}
	return n.base
}

func (n *composedNamespace) NamespaceService(key ServiceKey) (any, bool) {
	if n == nil {
		return nil, false
	}
	if n.services != nil {
		value, ok := n.services[key]
		return value, ok
	}
	for i := 0; i < int(n.inlineCount); i++ {
		if n.inline[i].Key == key {
			return n.inline[i].Value, true
		}
	}
	return nil, false
}

func (n *composedNamespace) Readiness() Readiness {
	if n == nil || n.base == nil {
		return ReadyClosed
	}
	return n.base.Readiness()
}

func (n *composedNamespace) TryService(budget ServiceBudget) (ServiceReport, Progress, error) {
	if n == nil || n.base == nil {
		return ServiceReport{}, 0, ErrInvalidNamespaceComposition
	}
	return n.base.TryService(budget)
}

func (n *composedNamespace) Close() error {
	if n == nil || n.base == nil {
		return nil
	}
	return n.base.Close()
}

// ServiceBudget bounds one manual backend service attempt in every dimension.
// Bytes limits packet bytes reported or consumed during that attempt. Egress
// implementations may conservatively require one full configured frame of
// capacity before probing pending output, so shorter byte budgets fail closed as
// would-block without consuming work.
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
