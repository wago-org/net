package dhcpv6

import (
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
)

func TestAdvancedOptionsComposeDisabledRegistrationWithoutImplicitAuthority(t *testing.T) {
	addition := wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportDHCPv6},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("ff02::1:2/128")},
	}}}
	registration := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range []Option{WithConfig(Config{}), WithPolicy(addition), WithoutDefaultAuthority()} {
		if err := option.applyDHCPv6(&registration); err != nil {
			t.Fatal(err)
		}
	}
	addition.Rules[0].Prefixes[0] = netip.MustParsePrefix("::/0")
	if registration.config != (Config{}) || registration.defaultAuthority || len(registration.authorityAdditions.Rules) != 1 ||
		registration.authorityAdditions.Rules[0].Prefixes[0] != netip.MustParsePrefix("ff02::1:2/128") {
		t.Fatalf("registration = %+v", registration)
	}
	if err := Register(wagonet.New(), WithConfig(Config{}), WithPolicy(registration.authorityAdditions), WithoutDefaultAuthority()); err != nil {
		t.Fatalf("Register disabled advanced options = %v", err)
	}
}
