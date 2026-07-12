package udp

import (
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/policy"
)

func TestAuthorityOptionsKeepServerAndSpecialClassesExplicit(t *testing.T) {
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowServer(wagonet.PolicyPortRange{First: 53, Last: 53}),
		AllowWildcardBind(),
		AllowPrivilegedBind(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{
			{Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportUDP}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}},
			{Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportTCP}, Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound, wagonet.PolicyOutbound}},
		}}),
		AllowMulticast(),
		AllowBroadcast(),
	} {
		if err := option.applyUDP(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !compiled.CheckEndpoint(policy.OperationUDPBind, netip.IPv4Unspecified(), 53) {
		t.Fatal("explicit wildcard privileged server bind was denied")
	}
	if compiled.CheckEndpoint(policy.OperationUDPBind, netip.IPv4Unspecified(), 5353) {
		t.Fatal("server bind outside the explicit port range was allowed")
	}
	if !compiled.CheckEndpoint(policy.OperationUDPSend, netip.MustParseAddr("224.0.0.1"), 53) {
		t.Fatal("explicit multicast grant was denied")
	}
	if !compiled.CheckEndpoint(policy.OperationUDPSend, netip.MustParseAddr("255.255.255.255"), 53) {
		t.Fatal("explicit broadcast grant was denied")
	}
	if compiled.CheckEndpoint(policy.OperationUDPSend, netip.MustParseAddr("127.0.0.1"), 53) {
		t.Fatal("loopback was allowed without its explicit grant")
	}
	if compiled.CheckEndpoint(policy.OperationTCPConnect, netip.MustParseAddr("224.0.0.1"), 443) {
		t.Fatal("UDP multicast grant widened TCP authority")
	}
	if compiled.CheckEndpoint(policy.OperationTCPListen, netip.IPv4Unspecified(), 80) {
		t.Fatal("UDP wildcard/privileged grants widened TCP authority")
	}
}

func TestDefaultAuthorityPermitsAllocationButNotExplicitEphemeralBind(t *testing.T) {
	compiled, err := policy.Compile(registration{defaultAuthority: true}.authority())
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckEndpoint(policy.OperationUDPBind, netip.IPv4Unspecified(), 0) {
		t.Fatal("default ephemeral allocation request was denied")
	}
	if compiled.CheckEndpoint(policy.OperationUDPBind, netip.IPv4Unspecified(), 49152) {
		t.Fatal("default allocation authority widened to explicit ephemeral bind")
	}
}

func TestAllowAllStillHonorsRawDenyRules(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.77/32")
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithoutDefaultAuthority(),
		AllowAll(),
		WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportUDP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{denied},
		}}}),
	} {
		if err := option.applyUDP(&config); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !compiled.CheckEndpoint(policy.OperationUDPSend, netip.MustParseAddr("127.0.0.1"), 53) {
		t.Fatal("AllowAll did not grant loopback UDP")
	}
	if compiled.CheckEndpoint(policy.OperationUDPSend, denied.Addr(), 53) {
		t.Fatal("raw deny did not override AllowAll")
	}
}
