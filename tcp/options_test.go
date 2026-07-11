package tcp

import (
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/policy"
)

func TestAuthorityOptionsKeepListenersAndSpecialClassesExplicit(t *testing.T) {
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowListeners(wagonet.PolicyPortRange{First: 80, Last: 80}, wagonet.PolicyPortRange{First: 8080, Last: 8080}),
		AllowWildcardBind(),
		AllowPrivilegedBind(),
	} {
		if err := option.applyTCP(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !compiled.CheckEndpoint(policy.OperationTCPListen, netip.IPv4Unspecified(), 80) {
		t.Fatal("explicit wildcard privileged listener was denied")
	}
	if !compiled.CheckEndpoint(policy.OperationTCPListen, netip.MustParseAddr("192.0.2.10"), 8080) {
		t.Fatal("explicit nonprivileged listener was denied")
	}
	if compiled.CheckEndpoint(policy.OperationTCPListen, netip.MustParseAddr("192.0.2.10"), 8081) {
		t.Fatal("listener outside the explicit port ranges was allowed")
	}
	if compiled.CheckEndpoint(policy.OperationTCPConnect, netip.MustParseAddr("192.0.2.20"), 443) {
		t.Fatal("default outbound authority survived suppression")
	}
}

func TestAllowAllStillHonorsRawDenyRules(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.77/32")
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowAll(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportTCP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{denied},
		}}}),
	} {
		if err := option.applyTCP(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !compiled.CheckEndpoint(policy.OperationTCPConnect, netip.MustParseAddr("127.0.0.1"), 443) {
		t.Fatal("AllowAll did not grant loopback TCP")
	}
	if compiled.CheckEndpoint(policy.OperationTCPConnect, denied.Addr(), 443) {
		t.Fatal("raw deny did not override AllowAll")
	}
}
