package policy

import (
	"net/netip"
	"testing"
)

func mustPrefix(value string) netip.Prefix { return netip.MustParsePrefix(value) }
func mustAddr(value string) netip.Addr     { return netip.MustParseAddr(value) }

func TestPolicyDenyPrecedenceIsOrderIndependent(t *testing.T) {
	allow := Rule{
		Action:     ActionAllow,
		Transports: []Transport{TransportTCP},
		Directions: []Direction{DirectionOutbound},
		Prefixes:   []netip.Prefix{mustPrefix("192.0.2.0/24")},
		Ports:      []PortRange{{First: 443, Last: 443}},
	}
	deny := Rule{
		Action:     ActionDeny,
		Transports: []Transport{TransportTCP},
		Directions: []Direction{DirectionOutbound},
		Prefixes:   []netip.Prefix{mustPrefix("192.0.2.9/32")},
	}
	for _, rules := range [][]Rule{{allow, deny}, {deny, allow}} {
		policy, err := Compile(Config{Rules: rules})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if !policy.CheckEndpoint(OperationTCPConnect, mustAddr("192.0.2.8"), 443) {
			t.Fatal("ordinary allowed endpoint denied")
		}
		if policy.CheckEndpoint(OperationTCPConnect, mustAddr("192.0.2.9"), 443) {
			t.Fatal("specific deny did not override allow")
		}
		if policy.CheckEndpoint(OperationTCPConnect, mustAddr("192.0.2.8"), 80) {
			t.Fatal("unmatched port defaulted to allow")
		}
	}
}

func TestPolicyNormalizesAndCopiesRules(t *testing.T) {
	prefixes := []netip.Prefix{mustPrefix("2001:db8::1234/32"), mustPrefix("2001:db8::/32")}
	suffixes := []string{"Example.COM.", "example.com"}
	config := Config{Rules: []Rule{
		{Action: ActionAllow, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound}, Prefixes: prefixes, Ports: []PortRange{{443, 443}}},
		{Action: ActionAllow, Transports: []Transport{TransportDNS}, Directions: []Direction{DirectionOutbound}, DNSSuffixes: suffixes},
	}}
	policy, err := Compile(config)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	prefixes[0] = mustPrefix("::1/128")
	suffixes[0] = "attacker.invalid"
	config.Rules[0].Action = ActionDeny

	if !policy.CheckEndpoint(OperationTCPConnect, mustAddr("2001:db8::99"), 443) {
		t.Fatal("masked copied prefix did not match")
	}
	if !policy.CheckDNS(OperationDNSResolve, "API.Example.COM.") {
		t.Fatal("normalized DNS suffix did not match")
	}
	if policy.CheckDNS(OperationDNSResolve, "notexample.com") {
		t.Fatal("suffix matched without a label boundary")
	}
}

func TestPolicyPrivilegedClassesAndWildcardsDefaultDeny(t *testing.T) {
	allowAllEndpoints := Rule{Action: ActionAllow, Prefixes: []netip.Prefix{mustPrefix("0.0.0.0/0"), mustPrefix("::/0")}}
	policy, err := Compile(Config{Rules: []Rule{allowAllEndpoints}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	checks := []struct {
		name      string
		operation Operation
		address   string
		port      uint16
	}{
		{"wildcard bind v4", OperationUDPBind, "0.0.0.0", 8080},
		{"wildcard bind v6", OperationTCPListen, "::", 8080},
		{"wildcard outbound", OperationTCPConnect, "0.0.0.0", 8080},
		{"loopback", OperationTCPConnect, "127.0.0.1", 8080},
		{"multicast", OperationUDPSend, "224.0.0.1", 8080},
		{"limited broadcast", OperationUDPSend, "255.255.255.255", 8080},
		{"privileged local port", OperationTCPListen, "192.0.2.1", 443},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if policy.CheckEndpoint(tc.operation, mustAddr(tc.address), tc.port) {
				t.Fatal("privileged endpoint allowed by zero-value gates")
			}
		})
	}
	if !policy.CheckEndpoint(OperationTCPConnect, mustAddr("192.0.2.1"), 443) {
		t.Fatal("ordinary outbound destination port was treated as a privileged local bind")
	}

	privileged, err := Compile(Config{
		Rules:               []Rule{allowAllEndpoints},
		AllowWildcardBind:   true,
		AllowLoopback:       true,
		AllowMulticast:      true,
		AllowBroadcast:      true,
		AllowPrivilegedBind: true,
	})
	if err != nil {
		t.Fatalf("Compile privileged: %v", err)
	}
	for _, tc := range checks {
		if tc.name == "wildcard outbound" {
			if privileged.CheckEndpoint(tc.operation, mustAddr(tc.address), tc.port) {
				t.Fatal("unspecified outbound address must always be denied")
			}
			continue
		}
		if !privileged.CheckEndpoint(tc.operation, mustAddr(tc.address), tc.port) {
			t.Fatalf("explicitly enabled endpoint denied: %s", tc.name)
		}
	}
}

func TestPolicyRejectsMappedAddressesAndMalformedSelectors(t *testing.T) {
	policy, err := Compile(Config{Rules: []Rule{{Action: ActionAllow, Prefixes: []netip.Prefix{mustPrefix("0.0.0.0/0")}}}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if policy.CheckEndpoint(OperationUDPSend, mustAddr("::ffff:192.0.2.1"), 8080) {
		t.Fatal("IPv4-mapped IPv6 query bypassed IPv4 policy")
	}
	if _, err := Compile(Config{Rules: []Rule{{Action: ActionAllow, Prefixes: []netip.Prefix{mustPrefix("::ffff:192.0.2.0/120")}}}}); err == nil {
		t.Fatal("IPv4-mapped IPv6 rule accepted")
	}
	bad := []Rule{
		{},
		{Action: Action(99)},
		{Action: ActionAllow, Transports: []Transport{99}},
		{Action: ActionAllow, Directions: []Direction{99}},
		{Action: ActionAllow, Ports: []PortRange{{First: 2, Last: 1}}},
		{Action: ActionAllow, DNSSuffixes: []string{"*.example.com"}},
	}
	for i, rule := range bad {
		if _, err := Compile(Config{Rules: []Rule{rule}}); err == nil {
			t.Fatalf("bad rule %d accepted", i)
		}
	}
}

func TestPolicyAuthorityChangingOperationsUseTransportAndDirection(t *testing.T) {
	policy, err := Compile(Config{Rules: []Rule{
		{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionInbound}, Prefixes: []netip.Prefix{mustPrefix("192.0.2.0/24")}, Ports: []PortRange{{8080, 8080}}},
		{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("198.51.100.0/24")}, Ports: []PortRange{{9000, 9000}}},
		{Action: ActionAllow, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionInbound}, Prefixes: []netip.Prefix{mustPrefix("192.0.2.0/24")}, Ports: []PortRange{{8080, 8080}}},
		{Action: ActionAllow, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("203.0.113.0/24")}, Ports: []PortRange{{8443, 8443}}},
		{Action: ActionAllow, Transports: []Transport{TransportDNS}, Directions: []Direction{DirectionOutbound}, DNSSuffixes: []string{"example.com"}},
	}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	allowed := []bool{
		policy.CheckEndpoint(OperationUDPBind, mustAddr("192.0.2.1"), 8080),
		policy.CheckEndpoint(OperationUDPSend, mustAddr("198.51.100.1"), 9000),
		policy.CheckEndpoint(OperationTCPListen, mustAddr("192.0.2.1"), 8080),
		policy.CheckEndpoint(OperationTCPConnect, mustAddr("203.0.113.1"), 8443),
		policy.CheckDNS(OperationDNSResolve, "api.example.com"),
	}
	for i, ok := range allowed {
		if !ok {
			t.Fatalf("authority check %d denied", i)
		}
	}
	if policy.CheckEndpoint(OperationTCPConnect, mustAddr("198.51.100.1"), 9000) {
		t.Fatal("UDP outbound rule granted TCP connect")
	}
	if policy.CheckEndpoint(OperationTCPListen, mustAddr("203.0.113.1"), 8443) {
		t.Fatal("outbound rule granted inbound listen")
	}
	if policy.CheckDNS(OperationTCPConnect, "example.com") || policy.CheckEndpoint(OperationDNSResolve, mustAddr("192.0.2.1"), 8080) {
		t.Fatal("operation accepted by the wrong authority checker")
	}
}

func TestPolicyDNSWildcardAndMalformedNamesFailClosed(t *testing.T) {
	policy, err := Compile(Config{Rules: []Rule{{Action: ActionAllow, Transports: []Transport{TransportDNS}}}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, name := range []string{"", ".", "*.example.com", "bad..example", "-bad.example", "192.0.2.1", "éxample.com"} {
		if policy.CheckDNS(OperationDNSResolve, name) {
			t.Fatalf("malformed/wildcard DNS name %q allowed", name)
		}
	}
	if !policy.CheckDNS(OperationDNSResolve, "valid.example") {
		t.Fatal("valid name denied by all-DNS rule")
	}
}

func FuzzPolicyQueries(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1}, uint16(443), "api.example.com", uint8(OperationTCPConnect))
	f.Add([]byte{0, 0, 0, 0}, uint16(0), "*.invalid", uint8(OperationUDPBind))
	f.Fuzz(func(t *testing.T, rawAddress []byte, port uint16, name string, rawOperation uint8) {
		policy, err := Compile(Config{Rules: []Rule{
			{Action: ActionAllow, Prefixes: []netip.Prefix{mustPrefix("0.0.0.0/0"), mustPrefix("::/0")}},
			{Action: ActionAllow, Transports: []Transport{TransportDNS}, DNSSuffixes: []string{"example.com"}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		var address netip.Addr
		switch len(rawAddress) {
		case 4:
			address = netip.AddrFrom4([4]byte(rawAddress))
		case 16:
			address = netip.AddrFrom16([16]byte(rawAddress))
		}
		operation := Operation(rawOperation)
		_ = policy.CheckEndpoint(operation, address, port)
		_ = policy.CheckDNS(operation, name)
	})
}
