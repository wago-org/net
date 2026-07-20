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
