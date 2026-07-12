package tcp

import (
	"errors"
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
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportUDP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound}, Ports: []wagonet.PolicyPortRange{{First: 80, Last: 80}},
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
	if compiled.CheckEndpoint(policy.OperationUDPBind, netip.IPv4Unspecified(), 80) {
		t.Fatal("TCP wildcard/privileged grants widened UDP authority")
	}
}

func TestAllowListenersRejectsEmptyInputAndAllPortsHelperStaysExplicit(t *testing.T) {
	if err := AllowListeners().applyTCP(&registration{}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("empty listener helper = %v", err)
	}
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowAllListenerPorts(),
		AllowWildcardBind(),
	} {
		if err := option.applyTCP(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !compiled.CheckEndpoint(policy.OperationTCPListen, netip.IPv4Unspecified(), 1024) {
		t.Fatal("all-port helper denied nonprivileged wildcard listener")
	}
	if !compiled.CheckEndpoint(policy.OperationTCPListen, netip.MustParseAddr("192.0.2.10"), 65535) {
		t.Fatal("all-port helper denied highest nonprivileged listener")
	}
	if compiled.CheckEndpoint(policy.OperationTCPListen, netip.MustParseAddr("192.0.2.10"), 443) {
		t.Fatal("all-port helper widened authority to privileged listeners")
	}
	if compiled.CheckEndpoint(policy.OperationTCPConnect, netip.MustParseAddr("192.0.2.20"), 443) {
		t.Fatal("all-port helper restored default outbound authority")
	}
}

func TestAllowAllStillHonorsRawDenyRules(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.77/32")
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowAll(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{
			{Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportTCP}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{denied}},
			{Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportUDP}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}},
		}}),
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
	if compiled.CheckEndpoint(policy.OperationUDPSend, netip.MustParseAddr("127.0.0.1"), 53) {
		t.Fatal("TCP AllowAll widened UDP loopback authority")
	}
}
