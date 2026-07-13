package dhcpv4_test

import (
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/policy"
)

func TestDHCPv4AuthorityIsProtocolLocalAndDenyWins(t *testing.T) {
	broadcast := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	compiled, err := policy.Compile(policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(broadcast, 32)}, Ports: []policy.PortRange{{First: 67, Last: 67}}},
			{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(broadcast, 32)}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionOutbound}},
		},
		BroadcastTransports: []policy.Transport{policy.TransportDHCPv4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.CheckEndpoint(policy.OperationDHCPv4ClientSend, broadcast, 67) {
		t.Fatal("caller deny did not win")
	}
	if compiled.CheckEndpoint(policy.OperationDHCPv4ClientSend, netip.MustParseAddr("192.0.2.1"), 67) {
		t.Fatal("ordinary UDP authority widened DHCPv4")
	}
}
