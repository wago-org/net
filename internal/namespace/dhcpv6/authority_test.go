package dhcpv6_test

import (
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/policy"
)

func TestDHCPv6AuthorityIsProtocolLocalAndDenyWins(t *testing.T) {
	multicast := netip.MustParseAddr("ff02::1:2")
	compiled, err := policy.Compile(policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(multicast, 128)}, Ports: []policy.PortRange{{First: 547, Last: 547}}},
			{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(multicast, 128)}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionOutbound}},
		},
		MulticastTransports: []policy.Transport{policy.TransportDHCPv6},
	})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.CheckEndpoint(policy.OperationDHCPv6ClientSend, multicast, 547) {
		t.Fatal("caller deny did not win")
	}
	if compiled.CheckEndpoint(policy.OperationDHCPv6ClientSend, netip.MustParseAddr("2001:db8::1"), 547) {
		t.Fatal("ordinary UDP authority widened DHCPv6")
	}
}
