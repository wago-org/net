package icmpv4

import (
	"testing"

	wagonet "github.com/wago-org/net"
)

func TestSpecialAddressOptionsComposeWithoutDefaultAuthority(t *testing.T) {
	registration := registration{config: DefaultConfig(), defaultAuthority: true}
	options := []Option{
		AllowLoopback(), AllowMulticast(), AllowBroadcast(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound},
		}}}),
		WithoutDefaultAuthority(),
	}
	for _, option := range options {
		if err := option.applyICMPv4(&registration); err != nil {
			t.Fatal(err)
		}
	}
	if registration.defaultAuthority || len(registration.authorityAdditions.Rules) != 1 ||
		len(registration.authorityAdditions.LoopbackTransports) != 1 || len(registration.authorityAdditions.MulticastTransports) != 1 ||
		len(registration.authorityAdditions.BroadcastTransports) != 1 {
		t.Fatalf("registration authority = %+v", registration.authorityAdditions)
	}
	if err := Register(wagonet.New(), options...); err != nil {
		t.Fatalf("Register special address options = %v", err)
	}
}
