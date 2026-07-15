package icmpv6

import (
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
)

func TestDestinationOptionsComposeAndCopyWithoutDefaultAuthority(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("2001:db8:86::/64")}
	registration := registration{config: DefaultConfig(), defaultAuthority: true}
	options := []Option{
		AllowDestinations(prefixes...), AllowAll(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv6},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:86::1/128")},
		}}}),
		WithoutDefaultAuthority(),
	}
	for _, option := range options {
		if err := option.applyICMPv6(&registration); err != nil {
			t.Fatal(err)
		}
	}
	prefixes[0] = netip.MustParsePrefix("::/0")
	if registration.defaultAuthority || len(registration.authorityAdditions.Rules) != 3 ||
		registration.authorityAdditions.Rules[0].Prefixes[0] != netip.MustParsePrefix("2001:db8:86::/64") {
		t.Fatalf("registration authority = %+v", registration.authorityAdditions)
	}
	if err := Register(wagonet.New(), options...); err != nil {
		t.Fatalf("Register destination options = %v", err)
	}
}
