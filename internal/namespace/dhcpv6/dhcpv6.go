// Package dhcpv6 defines the bounded backend-neutral DHCPv6 client subset
// implemented by the pinned lneto revision. The contract exposes only the
// Solicit -> Advertise -> Request -> Reply acquisition exchange and copied
// configuration observations. It does not imply general UDP6, identity
// mutation, renewal scheduling, relay, server, or raw packet access.
package dhcpv6

import (
	"net/netip"

	"github.com/wago-org/net/internal/dnsname"
	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey identifies the independently selected DHCPv6 service.
const ServiceKey nscore.ServiceKey = "dhcpv6"

const (
	ClientPort uint16 = 546
	ServerPort uint16 = 547

	MaxServerDUIDBytes       = 128
	MaxNameBytes             = 253
	MaxDNSServers            = 4
	MaxDomainSearch          = 6
	MaxNTPServers            = 4
	MaxNTPMulticastServers   = 2
	MaxNTPServerNames        = 4
	MaxDelegatedPrefixes     = 4
	FixedResultRetainedBytes = 3456
)

// Operation names both the supported acquisition and operations deliberately
// excluded because the pinned state machine does not provide a complete safe
// externally startable lifecycle for them.
type Operation uint8

const (
	OperationAcquire Operation = iota + 1
	OperationRenew
	OperationRebind
	OperationRelease
	OperationDecline
	OperationConfirm
	OperationInformationRequest
	OperationReconfigure
	OperationRapidCommit
	OperationRelayAgent
	OperationServer
	OperationApplyIdentity
	OperationRawPacket
)

// Operations is a finite truthful supported-operation bitset.
type Operations uint32

const (
	SupportsAcquire     Operations = 1 << iota
	SupportedOperations            = SupportsAcquire
)

func (operations Operations) Supports(operation Operation) bool {
	return operation == OperationAcquire && operations&SupportsAcquire != 0
}

// Namespace starts at most its configured finite number of acquisition
// resources. Implementations copy all retained values before returning.
type Namespace interface {
	Operations() Operations
	TryAcquire() (nscore.Resource, nscore.Progress, error)
}

// Name is one canonical lowercase DNS name stored entirely inline.
type Name struct {
	Length uint16
	Bytes  [MaxNameBytes]byte
}

func NewName(value string) (Name, bool) {
	normalized, ok := dnsname.Normalize(value)
	if !ok || normalized != value {
		return Name{}, false
	}
	return NewNameBytes([]byte(value))
}

// NewNameBytes copies one already-canonical DNS name into inline storage
// without converting it to a heap-backed string.
func NewNameBytes(value []byte) (Name, bool) {
	if len(value) > MaxNameBytes || !dnsname.ValidCanonicalBytes(value) {
		return Name{}, false
	}
	var result Name
	result.Length = uint16(len(value))
	copy(result.Bytes[:], value)
	return result, true
}

func (name Name) String() string { return string(name.Bytes[:name.Length]) }

func (name Name) Valid() bool {
	if name.Length == 0 || int(name.Length) > len(name.Bytes) || !dnsname.ValidCanonicalBytes(name.Bytes[:name.Length]) {
		return false
	}
	for _, b := range name.Bytes[name.Length:] {
		if b != 0 {
			return false
		}
	}
	return true
}

// DelegatedPrefix is one copied IA_PD observation. It is not applied to a
// namespace and carries no SLAAC, DAD, route, or lifetime scheduler semantics.
type DelegatedPrefix struct {
	Prefix            netip.Prefix
	PreferredLifetime uint32
	ValidLifetime     uint32
}

func (prefix DelegatedPrefix) Valid() bool {
	return prefix.Prefix.IsValid() && prefix.Prefix.Addr().Is6() && !prefix.Prefix.Addr().Is4In6() &&
		prefix.Prefix.Addr().Zone() == "" && prefix.Prefix.Bits() > 0 && prefix.Prefix == prefix.Prefix.Masked() &&
		prefix.ValidLifetime > 0 && prefix.PreferredLifetime <= prefix.ValidLifetime
}

// Configuration is one completely copied accepted Reply. Every repeated option
// has fixed inline capacity. Assigned addresses and delegated prefixes remain
// observations only.
type Configuration struct {
	TransactionID uint32
	IAID          [4]byte

	AssignedAddr  netip.Addr
	ServerAddr    netip.Addr
	ServerScopeID uint32

	ServerDUIDLength uint16
	ServerDUID       [MaxServerDUIDBytes]byte

	RenewalSeconds           uint32
	RebindingSeconds         uint32
	PreferredLifetimeSeconds uint32
	ValidLifetimeSeconds     uint32
	PrefixRenewalSeconds     uint32
	PrefixRebindingSeconds   uint32

	DNSCount   uint8
	DNSServers [MaxDNSServers]netip.Addr

	DomainCount  uint8
	DomainSearch [MaxDomainSearch]Name

	NTPCount   uint8
	NTPServers [MaxNTPServers]netip.Addr

	NTPMulticastCount   uint8
	NTPMulticastServers [MaxNTPMulticastServers]netip.Addr

	NTPNameCount   uint8
	NTPServerNames [MaxNTPServerNames]Name

	PrefixCount       uint8
	DelegatedPrefixes [MaxDelegatedPrefixes]DelegatedPrefix
}

func (configuration *Configuration) Valid() bool {
	if configuration == nil {
		return false
	}
	if configuration.TransactionID == 0 || configuration.TransactionID > 0x00ff_ffff || configuration.IAID == ([4]byte{}) ||
		!validUnicast(configuration.AssignedAddr, 0) || !validUnicast(configuration.ServerAddr, configuration.ServerScopeID) ||
		configuration.ServerDUIDLength == 0 || int(configuration.ServerDUIDLength) > len(configuration.ServerDUID) ||
		configuration.ValidLifetimeSeconds == 0 || configuration.PreferredLifetimeSeconds > configuration.ValidLifetimeSeconds ||
		!validTimers(configuration.RenewalSeconds, configuration.RebindingSeconds, configuration.ValidLifetimeSeconds) ||
		configuration.DNSCount > MaxDNSServers || configuration.DomainCount > MaxDomainSearch ||
		configuration.NTPCount > MaxNTPServers || configuration.NTPMulticastCount > MaxNTPMulticastServers ||
		configuration.NTPNameCount > MaxNTPServerNames || configuration.PrefixCount > MaxDelegatedPrefixes {
		return false
	}
	for _, b := range configuration.ServerDUID[configuration.ServerDUIDLength:] {
		if b != 0 {
			return false
		}
	}
	for i, address := range configuration.DNSServers {
		if i < int(configuration.DNSCount) {
			if !validUnicast(address, 0) {
				return false
			}
		} else if address.IsValid() {
			return false
		}
	}
	for i, name := range configuration.DomainSearch {
		if i < int(configuration.DomainCount) {
			if !name.Valid() {
				return false
			}
		} else if name != (Name{}) {
			return false
		}
	}
	for i, address := range configuration.NTPServers {
		if i < int(configuration.NTPCount) {
			if !validUnicast(address, 0) {
				return false
			}
		} else if address.IsValid() {
			return false
		}
	}
	for i, address := range configuration.NTPMulticastServers {
		if i < int(configuration.NTPMulticastCount) {
			if !validMulticast(address) {
				return false
			}
		} else if address.IsValid() {
			return false
		}
	}
	for i, name := range configuration.NTPServerNames {
		if i < int(configuration.NTPNameCount) {
			if !name.Valid() {
				return false
			}
		} else if name != (Name{}) {
			return false
		}
	}
	for i, prefix := range configuration.DelegatedPrefixes {
		if i < int(configuration.PrefixCount) {
			if !prefix.Valid() {
				return false
			}
		} else if prefix != (DelegatedPrefix{}) {
			return false
		}
	}
	return validTimers(configuration.PrefixRenewalSeconds, configuration.PrefixRebindingSeconds, maxPrefixLifetime(configuration))
}

func validTimers(t1, t2, lifetime uint32) bool {
	return (t1 == 0 || t1 <= lifetime) && (t2 == 0 || t2 <= lifetime) && (t1 == 0 || t2 == 0 || t1 <= t2)
}

func maxPrefixLifetime(configuration *Configuration) uint32 {
	var maximum uint32
	for i := 0; i < int(configuration.PrefixCount); i++ {
		if configuration.DelegatedPrefixes[i].ValidLifetime > maximum {
			maximum = configuration.DelegatedPrefixes[i].ValidLifetime
		}
	}
	if maximum == 0 {
		return ^uint32(0)
	}
	return maximum
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

func validMulticast(address netip.Addr) bool {
	return address.IsValid() && address.Is6() && !address.Is4In6() && address.Zone() == "" && address.IsMulticast()
}

// ResultState is one immediate nonblocking acquisition result state.
type ResultState uint8

const (
	ResultReady ResultState = iota + 1
	ResultWouldBlock
)

// Resource owns one bounded initial DHCPv6 acquisition. Cancellation and Close
// are local deterministic operations; no unsupported wire Release is implied.
type Resource interface {
	nscore.Resource
	TryResult() (Configuration, ResultState, error)
	Cancel() error
}
