// Package ipv6 defines the backend-neutral configured IPv6 namespace facet.
// It exposes only checked configuration and transport-family availability;
// raw IPv6 packets remain internal backend infrastructure.
package ipv6

import (
	"net/netip"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey identifies the independently selected IPv6 namespace service.
const ServiceKey nscore.ServiceKey = "ipv6"

// Transport flags describe only paths implemented by the pinned backend. A
// caller must still select and hold the corresponding transport capability.
type Transports uint32

const (
	TransportTCPConnect Transports = 1 << iota
	TransportTCPListen

	transportMask = TransportTCPConnect | TransportTCPListen
)

// Configuration is the finite, immutable IPv6 contribution to one namespace.
// Prefix is informational routing identity for the configured single interface;
// the pinned stack does not expose a guest route table.
type Configuration struct {
	Address             netip.Addr
	PrefixBits          uint8
	ScopeID             uint32
	MTU                 uint16
	MaxExtensionHeaders uint8
	Transports          Transports
}

// Valid reports whether the configuration is representable by the pinned
// immediate stack. IPv4-mapped, unspecified, loopback, multicast, and zoned
// values are rejected. Extension headers are unsupported, so the exact bound is
// zero. A numeric scope is accepted only for link-local unicast.
func (c Configuration) Valid() bool {
	if !validStaticAddress(c.Address, c.ScopeID) || c.PrefixBits == 0 || c.PrefixBits > 128 || c.MTU < 1280 ||
		c.MaxExtensionHeaders != 0 || c.Transports == 0 || c.Transports&^transportMask != 0 {
		return false
	}
	prefix := netip.PrefixFrom(c.Address, int(c.PrefixBits)).Masked()
	return prefix.IsValid() && prefix.Contains(c.Address)
}

// Prefix returns the canonical configured prefix.
func (c Configuration) Prefix() netip.Prefix {
	if !c.Valid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(c.Address, int(c.PrefixBits)).Masked()
}

// SupportsEndpoint reports whether endpoint metadata can be represented by the
// configured single-interface pinned stack. Flow labels are not implemented.
func (c Configuration) SupportsEndpoint(endpoint nscore.Endpoint) bool {
	if !c.Valid() || !endpoint.Valid() || !endpoint.Address.Is6() || endpoint.Address.Is4In6() || endpoint.Address.IsUnspecified() ||
		endpoint.Address.IsLoopback() || endpoint.Address.IsMulticast() || endpoint.FlowInfo != 0 {
		return false
	}
	if endpoint.Address.IsLinkLocalUnicast() {
		return endpoint.ScopeID != 0 && endpoint.ScopeID == c.ScopeID
	}
	return endpoint.ScopeID == 0
}

// Namespace exposes immutable IPv6 namespace configuration. Bounded packet
// service and deterministic close remain owned by the shared core namespace.
type Namespace interface {
	Configuration() Configuration
}

func validStaticAddress(address netip.Addr, scopeID uint32) bool {
	if !address.IsValid() || !address.Is6() || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return false
	}
	if address.IsLinkLocalUnicast() {
		return scopeID != 0
	}
	return scopeID == 0
}
