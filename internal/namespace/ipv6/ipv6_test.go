package ipv6

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

func TestConfigurationValidationAndPrefix(t *testing.T) {
	global := Configuration{
		Address: netip.MustParseAddr("2001:db8:42::7"), PrefixBits: 64, MTU: 1500,
		Transports: TransportTCPConnect | TransportTCPListen,
	}
	if !global.Valid() || global.Prefix() != netip.MustParsePrefix("2001:db8:42::/64") {
		t.Fatalf("global configuration invalid: %+v prefix=%v", global, global.Prefix())
	}
	linkLocal := global
	linkLocal.Address = netip.MustParseAddr("fe80::7")
	linkLocal.PrefixBits = 64
	linkLocal.ScopeID = 3
	if !linkLocal.Valid() {
		t.Fatalf("link-local configuration invalid: %+v", linkLocal)
	}
	for name, mutate := range map[string]func(*Configuration){
		"unspecified":       func(c *Configuration) { c.Address = netip.IPv6Unspecified() },
		"loopback":          func(c *Configuration) { c.Address = netip.IPv6Loopback() },
		"multicast":         func(c *Configuration) { c.Address = netip.MustParseAddr("ff02::1") },
		"mapped":            func(c *Configuration) { c.Address = netip.MustParseAddr("::ffff:192.0.2.1") },
		"global scope":      func(c *Configuration) { c.ScopeID = 1 },
		"link scope absent": func(c *Configuration) { c.Address = netip.MustParseAddr("fe80::1") },
		"zero prefix":       func(c *Configuration) { c.PrefixBits = 0 },
		"small mtu":         func(c *Configuration) { c.MTU = 1279 },
		"extension headers": func(c *Configuration) { c.MaxExtensionHeaders = 1 },
		"unknown transport": func(c *Configuration) { c.Transports |= 1 << 31 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := global
			mutate(&invalid)
			if name == "link scope absent" {
				invalid.ScopeID = 0
			}
			if invalid.Valid() {
				t.Fatalf("accepted invalid configuration: %+v", invalid)
			}
		})
	}
}

func TestSupportsEndpointRequiresExactScopeAndZeroFlow(t *testing.T) {
	configuration := Configuration{
		Address: netip.MustParseAddr("fe80::1"), PrefixBits: 64, ScopeID: 9, MTU: 1280,
		Transports: TransportTCPConnect | TransportTCPListen,
	}
	for _, endpoint := range []nscore.Endpoint{
		{Address: netip.MustParseAddr("fe80::2"), Port: 443, ScopeID: 9},
		{Address: netip.MustParseAddr("2001:db8::2"), Port: 443},
	} {
		if !configuration.SupportsEndpoint(endpoint) {
			t.Fatalf("endpoint not supported: %+v", endpoint)
		}
	}
	for _, endpoint := range []nscore.Endpoint{
		{Address: netip.MustParseAddr("fe80::2"), Port: 443},
		{Address: netip.MustParseAddr("fe80::2"), Port: 443, ScopeID: 8},
		{Address: netip.MustParseAddr("2001:db8::2"), Port: 443, FlowInfo: 1},
		{Address: netip.MustParseAddr("ff02::1"), Port: 443, ScopeID: 9},
		{Address: netip.MustParseAddr("192.0.2.1"), Port: 443},
	} {
		if configuration.SupportsEndpoint(endpoint) {
			t.Fatalf("unsupported endpoint accepted: %+v", endpoint)
		}
	}
}
