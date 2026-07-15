package ipv6

import (
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/policy"
)

func TestOptionsCopyPolicyAndRespectExplicitAuthoritySuppression(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::55")
	prefixes := []netip.Prefix{netip.PrefixFrom(address, 128)}
	input := wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportIPv6},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound}, Prefixes: prefixes,
	}}}
	config := registration{defaultAuthority: true}
	for _, option := range []Option{WithConfig(DefaultConfig(address, 64, 0)), WithPolicy(input), WithoutDefaultAuthority()} {
		if err := option.applyIPv6(&config); err != nil {
			t.Fatal(err)
		}
	}
	input.Rules[0].Prefixes[0] = netip.MustParsePrefix("2001:db8::99/128")
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckAddress(policy.OperationIPv6Enable, address) {
		t.Fatal("copied explicit IPv6 authority was not retained")
	}
	if compiled.CheckAddress(policy.OperationIPv6Enable, netip.MustParseAddr("2001:db8::99")) {
		t.Fatal("policy input mutation changed registered authority")
	}
	if config.config.Address != address || config.defaultAuthority {
		t.Fatalf("registration = %+v", config)
	}
}
