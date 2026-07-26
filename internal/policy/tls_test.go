package policy

import (
	"net/netip"
	"testing"
)

func TestTLSAuthorityIsDistinctAndHonorsRawTCPDeny(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.9/32")
	compiled, err := Compile(Config{Rules: []Rule{
		{Action: ActionAllow, Transports: []Transport{TransportTLS}, Directions: []Direction{DirectionOutbound}},
		{Action: ActionDeny, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{denied}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	allowed := netip.MustParseAddr("192.0.2.8")
	if !compiled.CheckEndpoint(OperationTLSConnect, allowed, 443) {
		t.Fatal("TLS authority denied ordinary endpoint")
	}
	if compiled.CheckEndpoint(OperationTCPConnect, allowed, 443) {
		t.Fatal("TLS authority implied raw TCP")
	}
	if compiled.CheckEndpoint(OperationTLSConnect, denied.Addr(), 443) {
		t.Fatal("raw TCP deny failed to constrain private TLS transport")
	}
}

func TestTLSServerAuthorityIsDistinctAndHonorsRawTCPDeny(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.9/32")
	compiled, err := Compile(Config{Rules: []Rule{
		{Action: ActionAllow, Transports: []Transport{TransportTLS}, Directions: []Direction{DirectionInbound}},
		{Action: ActionDeny, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionInbound}, Prefixes: []netip.Prefix{denied}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	allowed := netip.MustParseAddr("192.0.2.8")
	if !compiled.CheckEndpoint(OperationTLSListen, allowed, 8443) {
		t.Fatal("TLS server authority denied ordinary endpoint")
	}
	if compiled.CheckEndpoint(OperationTCPListen, allowed, 8443) {
		t.Fatal("TLS server authority implied raw TCP listen")
	}
	if compiled.CheckEndpoint(OperationTLSListen, denied.Addr(), 8443) {
		t.Fatal("raw TCP inbound deny failed to constrain private TLS listener")
	}
}

func TestPrivateTCPTransportRequiresProtocolAuthorityAndHonorsRawDeny(t *testing.T) {
	denied := netip.MustParseAddr("192.0.2.9")
	compiled, err := Compile(Config{Rules: []Rule{{
		Action: ActionDeny, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound},
		Prefixes: []netip.Prefix{netip.PrefixFrom(denied, 32)}, Ports: []PortRange{{First: 53, Last: 53}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.AllowsPrivateTCPTransport(DirectionOutbound, netip.MustParseAddr("192.0.2.8"), 53) {
		t.Fatal("unmatched private transport was treated as requiring raw-TCP allow authority")
	}
	if compiled.AllowsPrivateTCPTransport(DirectionOutbound, denied, 53) {
		t.Fatal("raw-TCP deny did not constrain private transport")
	}
	for _, invalid := range []struct {
		direction Direction
		address   netip.Addr
		port      uint16
	}{
		{Direction(99), netip.MustParseAddr("192.0.2.8"), 53},
		{DirectionOutbound, netip.Addr{}, 53},
		{DirectionOutbound, netip.IPv4Unspecified(), 53},
		{DirectionOutbound, netip.MustParseAddr("::ffff:192.0.2.8"), 53},
		{DirectionOutbound, netip.MustParseAddr("192.0.2.8"), 0},
	} {
		if compiled.AllowsPrivateTCPTransport(invalid.direction, invalid.address, invalid.port) {
			t.Fatalf("invalid private transport allowed: %+v", invalid)
		}
	}
}

func TestTLSSpecialClassesRemainTLSScoped(t *testing.T) {
	compiled, err := Compile(Config{
		Rules:              []Rule{{Action: ActionAllow, Transports: []Transport{TransportTLS}, Directions: []Direction{DirectionOutbound}}},
		LoopbackTransports: []Transport{TransportTLS},
	})
	if err != nil {
		t.Fatal(err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	if !compiled.CheckEndpoint(OperationTLSConnect, loopback, 443) {
		t.Fatal("explicit TLS loopback grant denied")
	}
	if compiled.CheckEndpoint(OperationTCPConnect, loopback, 443) {
		t.Fatal("TLS loopback grant widened raw TCP")
	}
}
