package dhcpv4

import (
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
)

func TestAdvancedOptionsComposeRegistrationWithoutImplicitAuthority(t *testing.T) {
	addition := wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportDHCPv4},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("255.255.255.255/32")},
	}}}
	registration := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range []Option{ApplyLeaseIdentity(), WithPolicy(addition), WithoutDefaultAuthority()} {
		if err := option.applyDHCPv4(&registration); err != nil {
			t.Fatal(err)
		}
	}
	addition.Rules[0].Prefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	if !registration.config.ApplyLease || registration.defaultAuthority || len(registration.authorityAdditions.Rules) != 1 ||
		registration.authorityAdditions.Rules[0].Prefixes[0] != netip.MustParsePrefix("255.255.255.255/32") {
		t.Fatalf("registration = %+v", registration)
	}
	if err := Register(wagonet.New(), ApplyLeaseIdentity(), WithPolicy(registration.authorityAdditions), WithoutDefaultAuthority()); err != nil {
		t.Fatalf("Register advanced options = %v", err)
	}
}
