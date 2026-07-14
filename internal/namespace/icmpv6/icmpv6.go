// Package icmpv6 defines the narrow backend-neutral ICMPv6 echo and Neighbor
// Discovery facet. Router discovery, redirects, DAD, SLAAC, and raw ICMPv6
// packet access are deliberately outside this contract.
package icmpv6

import (
	"net/netip"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey identifies the independently selected ICMPv6/NDP service.
const ServiceKey nscore.ServiceKey = "icmpv6"

// Operation identifies an API operation implemented by the pinned immediate
// ICMPv6 client. Values beyond NeighborRemove are named unsupported operations
// so capability reporting cannot accidentally imply broader NDP support.
type Operation uint8

const (
	OperationEcho Operation = iota + 1
	OperationNeighborResolve
	OperationNeighborLookup
	OperationNeighborSeed
	OperationNeighborRemove
	OperationRouterDiscovery
	OperationRedirect
	OperationDAD
	OperationSLAAC
	OperationRawPacket
)

// Operations is a finite supported-operation bitset.
type Operations uint32

const (
	SupportsEcho Operations = 1 << iota
	SupportsNeighborResolve
	SupportsNeighborLookup
	SupportsNeighborSeed
	SupportsNeighborRemove

	SupportedOperations = SupportsEcho | SupportsNeighborResolve | SupportsNeighborLookup | SupportsNeighborSeed | SupportsNeighborRemove
)

// Supports reports whether operation is part of the truthful pinned subset.
func (operations Operations) Supports(operation Operation) bool {
	var bit Operations
	switch operation {
	case OperationEcho:
		bit = SupportsEcho
	case OperationNeighborResolve:
		bit = SupportsNeighborResolve
	case OperationNeighborLookup:
		bit = SupportsNeighborLookup
	case OperationNeighborSeed:
		bit = SupportsNeighborSeed
	case OperationNeighborRemove:
		bit = SupportsNeighborRemove
	default:
		return false
	}
	return operations&bit != 0
}

// Namespace starts bounded echo and neighbor-resolution resources and exposes
// finite cache operations. Implementations must copy every call-scoped slice.
type Namespace interface {
	Operations() Operations
	TryEcho(EchoRequest) (nscore.Resource, nscore.Progress, error)
	TryResolve(NeighborRequest) (nscore.Resource, nscore.Progress, error)
	LookupNeighbor(NeighborRequest) (Neighbor, bool, error)
	SeedNeighbor(Neighbor) error
	RemoveNeighbor(NeighborRequest) error
}

// EchoRequest selects one unicast IPv6 destination and an immediately copied
// payload. ScopeID is mandatory exactly for link-local unicast.
type EchoRequest struct {
	Destination netip.Addr
	ScopeID     uint32
	Payload     []byte
}

// Valid reports structural validity independently of authority.
func (request EchoRequest) Valid() bool {
	return validUnicast(request.Destination, request.ScopeID)
}

// EchoResult describes one exact correlated echo reply.
type EchoResult struct {
	Source       netip.Addr
	ScopeID      uint32
	Identifier   uint16
	Sequence     uint16
	Copied       int
	PayloadBytes int
}

// Valid reports whether result is representable for a destination buffer.
func (result EchoResult) Valid(size int) bool {
	return size >= 0 && validUnicast(result.Source, result.ScopeID) && result.Copied >= 0 &&
		result.Copied <= size && result.PayloadBytes >= result.Copied
}

// Next is one nonblocking result state shared by echo and resolution resources.
type Next uint8

const (
	NextReady Next = iota + 1
	NextWouldBlock
)

// Echo owns one bounded copied exchange.
type Echo interface {
	nscore.Resource
	TryResult([]byte) (EchoResult, Next, error)
	Cancel() error
}

// NeighborRequest identifies one exact IPv6 cache key.
type NeighborRequest struct {
	Address netip.Addr
	ScopeID uint32
}

// Valid reports whether the key is one exact unicast neighbor.
func (request NeighborRequest) Valid() bool {
	return validUnicast(request.Address, request.ScopeID)
}

// Neighbor is one copied IPv6-to-Ethernet cache entry.
type Neighbor struct {
	Address netip.Addr
	ScopeID uint32
	MAC     [6]byte
}

// Valid reports whether the entry has a unicast IPv6 key and unicast nonzero
// Ethernet address.
func (neighbor Neighbor) Valid() bool {
	return validUnicast(neighbor.Address, neighbor.ScopeID) && validUnicastMAC(neighbor.MAC)
}

// Resolution owns one finite pending Neighbor Solicitation and exact result.
type Resolution interface {
	nscore.Resource
	TryResult() (Neighbor, Next, error)
	Cancel() error
}

func validUnicast(address netip.Addr, scopeID uint32) bool {
	if !address.IsValid() || !address.Is6() || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return false
	}
	if address.IsLinkLocalUnicast() {
		return scopeID != 0
	}
	return scopeID == 0
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) && mac[0]&1 == 0
}
