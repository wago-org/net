package dns

import (
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/policy"
)

func TestSuffixAuthorityRequiresExplicitGrantAfterDefaultSuppression(t *testing.T) {
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowSuffixes("Example.COM."),
	} {
		if err := option.applyDNS(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, name := range []string{"example.com", "www.example.com"} {
		if !compiled.CheckDNS(policy.OperationDNSResolve, name) {
			t.Fatalf("explicit suffix denied %q", name)
		}
	}
	if compiled.CheckDNS(policy.OperationDNSResolve, "example.net") {
		t.Fatal("name outside the explicit suffix was allowed")
	}
}

func TestAllowAllStillHonorsRawDenyRules(t *testing.T) {
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowAll(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportDNS},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, DNSSuffixes: []string{"blocked.example"},
		}}}),
	} {
		if err := option.applyDNS(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !compiled.CheckDNS(policy.OperationDNSResolve, "allowed.example") {
		t.Fatal("AllowAll did not grant a valid DNS name")
	}
	if compiled.CheckDNS(policy.OperationDNSResolve, "www.blocked.example") {
		t.Fatal("raw suffix deny did not override AllowAll")
	}
}
