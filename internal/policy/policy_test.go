package policy

import (
	"net/netip"
	"testing"
)

func mustPrefix(value string) netip.Prefix { return netip.MustParsePrefix(value) }
func mustAddr(value string) netip.Addr     { return netip.MustParseAddr(value) }

func TestMergeCopiesRulesAndPreservesDenyPrecedence(t *testing.T) {
	allow := Config{Rules: []Rule{{
		Action: ActionAllow, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound},
	}}, AllowLoopback: true}
	denyPrefix := netip.MustParsePrefix("192.0.2.0/24")
	deny := Config{Rules: []Rule{{
		Action: ActionDeny, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{denyPrefix},
	}}}
	merged := Merge(deny, allow)
	allow.Rules[0].Transports[0] = TransportUDP
	deny.Rules[0].Prefixes[0] = netip.MustParsePrefix("198.51.100.0/24")

	compiled, err := Compile(merged)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.CheckEndpoint(OperationTCPConnect, netip.MustParseAddr("192.0.2.10"), 443) {
		t.Fatal("caller deny lost to composed allow")
	}
	if !compiled.CheckEndpoint(OperationTCPConnect, netip.MustParseAddr("203.0.113.10"), 443) {
		t.Fatal("composed allow missing")
	}
	if !compiled.CheckEndpoint(OperationTCPConnect, netip.MustParseAddr("127.0.0.1"), 443) {
		t.Fatal("special-class grant did not compose")
	}
}

func TestTransportScopedSpecialClassesDoNotCrossProtocols(t *testing.T) {
	compiled, err := Compile(Config{
		Rules: []Rule{
			{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionOutbound}},
			{Action: ActionAllow, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound}},
		},
		LoopbackTransports:  []Transport{TransportUDP},
		MulticastTransports: []Transport{TransportUDP},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckEndpoint(OperationUDPSend, mustAddr("127.0.0.1"), 53) {
		t.Fatal("scoped UDP loopback grant was denied")
	}
	if compiled.CheckEndpoint(OperationTCPConnect, mustAddr("127.0.0.1"), 443) {
		t.Fatal("scoped UDP loopback grant widened TCP authority")
	}
	if !compiled.CheckEndpoint(OperationUDPSend, mustAddr("224.0.0.1"), 53) {
		t.Fatal("scoped UDP multicast grant was denied")
	}
}

func TestPortAllocationPreservesAllocationAuthorityAndConcreteDenies(t *testing.T) {
	compiled, err := Compile(Config{
		Rules: []Rule{
			{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionInbound}, Ports: []PortRange{{First: 0, Last: 0}}},
			{Action: ActionDeny, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionInbound}, Ports: []PortRange{{First: 49152, Last: 49152}}},
		},
		WildcardBindTransports: []Transport{TransportUDP},
	})
	if err != nil {
		t.Fatal(err)
	}
	wildcard := mustAddr("0.0.0.0")
	if !compiled.CheckEndpoint(OperationUDPBind, wildcard, 0) {
		t.Fatal("ephemeral allocation request was denied")
	}
	if compiled.CheckEndpoint(OperationUDPBind, wildcard, 49153) {
		t.Fatal("placeholder authority became explicit ephemeral-port authority")
	}
	if compiled.CheckPortAllocation(OperationUDPBind, wildcard, 0) {
		t.Fatal("zero concrete port was treated as an allocation result")
	}
	if compiled.CheckPortAllocation(OperationUDPBind, wildcard, 49152) {
		t.Fatal("concrete ephemeral-port deny was bypassed")
	}
	if !compiled.CheckPortAllocation(OperationUDPBind, wildcard, 49153) {
		t.Fatal("non-denied concrete ephemeral allocation was rejected")
	}
}

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
	if _, err := Compile(Config{LoopbackTransports: []Transport{99}}); err == nil {
		t.Fatal("invalid scoped special-class transport accepted")
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

func TestNTPAuthorityIsProtocolLocalPortAwareAndDenyWins(t *testing.T) {
	compiled, err := Compile(Config{
		Rules: []Rule{
			{Action: ActionAllow, Transports: []Transport{TransportNTP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("192.0.2.0/24")}, Ports: []PortRange{{First: 123, Last: 123}}},
			{Action: ActionDeny, Transports: []Transport{TransportNTP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("192.0.2.9/32")}},
			{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionOutbound}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckEndpoint(OperationNTPSync, mustAddr("192.0.2.8"), 123) {
		t.Fatal("authorized NTP server denied")
	}
	if compiled.CheckEndpoint(OperationNTPSync, mustAddr("192.0.2.8"), 124) {
		t.Fatal("NTP authority widened beyond server port 123")
	}
	if compiled.CheckEndpoint(OperationNTPSync, mustAddr("192.0.2.9"), 123) {
		t.Fatal("NTP deny did not win")
	}
	if compiled.CheckEndpoint(OperationUDPSend, mustAddr("192.0.2.8"), 123) == false {
		t.Fatal("independent UDP authority unexpectedly denied")
	}
	udpOnly, err := Compile(Config{Rules: []Rule{{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionOutbound}}}})
	if err != nil {
		t.Fatal(err)
	}
	if udpOnly.CheckEndpoint(OperationNTPSync, mustAddr("192.0.2.8"), 123) {
		t.Fatal("general UDP authority widened NTP")
	}
}

func TestMDNSAuthorityIsProtocolLocalMulticastAndDenyWins(t *testing.T) {
	multicast := mustAddr("224.0.0.251")
	compiled, err := Compile(Config{
		Rules: []Rule{
			{Action: ActionAllow, Transports: []Transport{TransportMDNS}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("224.0.0.251/32")}, Ports: []PortRange{{First: 5353, Last: 5353}}},
			{Action: ActionAllow, Transports: []Transport{TransportMDNS}, Directions: []Direction{DirectionOutbound}, DNSSuffixes: []string{"local"}},
			{Action: ActionAllow, Transports: []Transport{TransportMDNS}, Directions: []Direction{DirectionInbound}, DNSSuffixes: []string{"local"}},
			{Action: ActionDeny, Transports: []Transport{TransportMDNS}, Directions: []Direction{DirectionOutbound}, DNSSuffixes: []string{"secret.local"}},
			{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionOutbound}},
		},
		MulticastTransports: []Transport{TransportMDNS},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckEndpoint(OperationMDNSSend, multicast, 5353) {
		t.Fatal("exact mDNS multicast endpoint denied")
	}
	if compiled.CheckEndpoint(OperationMDNSSend, multicast, 5354) || compiled.CheckEndpoint(OperationUDPSend, multicast, 5353) {
		t.Fatal("mDNS authority crossed port or transport boundary")
	}
	if !compiled.CheckDNS(OperationMDNSQuery, "printer.local") || !compiled.CheckDNS(OperationMDNSRespond, "printer.local") {
		t.Fatal("local query/response name denied")
	}
	if compiled.CheckDNS(OperationMDNSQuery, "secret.local") {
		t.Fatal("caller mDNS deny did not win")
	}
	udpOnly, err := Compile(Config{Rules: []Rule{{Action: ActionAllow, Transports: []Transport{TransportUDP}, Directions: []Direction{DirectionOutbound}}}, AllowMulticast: true})
	if err != nil {
		t.Fatal(err)
	}
	if udpOnly.CheckEndpoint(OperationMDNSSend, multicast, 5353) || udpOnly.CheckDNS(OperationMDNSQuery, "printer.local") {
		t.Fatal("general UDP authority widened mDNS")
	}
}

func TestICMPv6AuthorityIsProtocolLocalAndDenyWins(t *testing.T) {
	allowed := mustAddr("2001:db8:64::8")
	denied := mustAddr("2001:db8:64::9")
	compiled, err := Compile(Config{Rules: []Rule{
		{Action: ActionAllow, Transports: []Transport{TransportICMPv6}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("2001:db8:64::/64")}},
		{Action: ActionDeny, Transports: []Transport{TransportICMPv6}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(denied, 128)}},
		{Action: ActionAllow, Transports: []Transport{TransportIPv6}, Directions: []Direction{DirectionInbound}, Prefixes: []netip.Prefix{mustPrefix("2001:db8:64::/64")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []Operation{OperationICMPv6Echo, OperationICMPv6Resolve, OperationICMPv6Lookup, OperationICMPv6Seed, OperationICMPv6Remove} {
		if !compiled.CheckAddress(operation, allowed) {
			t.Fatalf("outbound operation %d did not receive ICMPv6 grant", operation)
		}
		if compiled.CheckAddress(operation, denied) {
			t.Fatalf("outbound operation %d ignored caller deny", operation)
		}
	}
	if compiled.CheckAddress(OperationICMPv6Respond, allowed) || compiled.CheckAddress(OperationICMPv6Advertise, allowed) {
		t.Fatal("outbound-only authority widened automatic inbound responses")
	}
	if compiled.CheckAddress(OperationICMPv4Echo, allowed) {
		t.Fatal("ICMPv6 authority widened ICMPv4")
	}
}

func TestIPv6EnableAuthorityIsProtocolLocalAndDenyWins(t *testing.T) {
	configured := mustAddr("2001:db8:42::7")
	compiled, err := Compile(Config{Rules: []Rule{
		{Action: ActionAllow, Transports: []Transport{TransportIPv6}, Directions: []Direction{DirectionInbound}, Prefixes: []netip.Prefix{mustPrefix("2001:db8:42::/64")}},
		{Action: ActionDeny, Transports: []Transport{TransportIPv6}, Directions: []Direction{DirectionInbound}, Prefixes: []netip.Prefix{mustPrefix("2001:db8:42::7/128")}},
		{Action: ActionAllow, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionInbound}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.CheckAddress(OperationIPv6Enable, configured) {
		t.Fatal("caller IPv6 deny did not win over the broader grant")
	}
	if compiled.CheckAddress(OperationIPv6Enable, mustAddr("2001:db8:43::7")) {
		t.Fatal("unmatched IPv6 namespace address was allowed")
	}
	if !compiled.CheckEndpoint(OperationTCPListen, configured, 8080) {
		t.Fatal("IPv6 namespace authority unexpectedly changed TCP authority")
	}
}

func TestICMPv4AddressAuthorityIsTransportScopedAndPortless(t *testing.T) {
	compiled, err := Compile(Config{
		Rules: []Rule{
			{Action: ActionAllow, Transports: []Transport{TransportICMPv4}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("192.0.2.0/24"), mustPrefix("127.0.0.0/8")}},
			{Action: ActionAllow, Transports: []Transport{TransportICMPv4}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("198.51.100.0/24")}, Ports: []PortRange{{First: 0, Last: 0}}},
		},
		LoopbackTransports: []Transport{TransportICMPv4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckAddress(OperationICMPv4Echo, mustAddr("192.0.2.10")) {
		t.Fatal("ordinary ICMPv4 echo destination denied")
	}
	if compiled.CheckAddress(OperationICMPv4Echo, mustAddr("198.51.100.10")) {
		t.Fatal("port-constrained rule matched a portless ICMPv4 operation")
	}
	if !compiled.CheckAddress(OperationICMPv4Echo, mustAddr("127.0.0.1")) {
		t.Fatal("transport-scoped ICMPv4 loopback grant denied")
	}
	if compiled.CheckAddress(OperationICMPv4Echo, mustAddr("203.0.113.10")) {
		t.Fatal("unmatched ICMPv4 destination defaulted to allow")
	}
	if compiled.CheckAddress(OperationTCPConnect, mustAddr("192.0.2.10")) {
		t.Fatal("endpoint operation was accepted by the address-only checker")
	}
	if compiled.CheckEndpoint(OperationICMPv4Echo, mustAddr("192.0.2.10"), 0) {
		t.Fatal("address-only operation was accepted by the endpoint checker")
	}
}

func TestLinkLocal4AuthorityIsProtocolLocalAndDenyWins(t *testing.T) {
	compiled, err := Compile(Config{Rules: []Rule{
		{Action: ActionAllow, Transports: []Transport{TransportLinkLocal4}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("169.254.0.0/16")}},
		{Action: ActionDeny, Transports: []Transport{TransportLinkLocal4}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{mustPrefix("169.254.42.7/32")}},
		{Action: ActionAllow, Transports: []Transport{TransportICMPv4}, Directions: []Direction{DirectionOutbound}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckAddress(OperationLinkLocal4Claim, mustAddr("169.254.1.1")) || !compiled.CheckAddress(OperationLinkLocal4Defend, mustAddr("169.254.1.1")) {
		t.Fatal("authorized link-local claim/defense denied")
	}
	if compiled.CheckAddress(OperationLinkLocal4Claim, mustAddr("169.254.42.7")) {
		t.Fatal("link-local deny did not win")
	}
	if compiled.CheckAddress(OperationLinkLocal4Claim, mustAddr("192.0.2.1")) {
		t.Fatal("link-local authority widened outside APIPA")
	}
	icmpOnly, err := Compile(Config{Rules: []Rule{{Action: ActionAllow, Transports: []Transport{TransportICMPv4}, Directions: []Direction{DirectionOutbound}}}})
	if err != nil {
		t.Fatal(err)
	}
	if icmpOnly.CheckAddress(OperationLinkLocal4Claim, mustAddr("169.254.1.1")) {
		t.Fatal("ICMPv4 authority widened link-local")
	}
}

func TestPolicyCanonicalDNSCheckDoesNotAllocate(t *testing.T) {
	compiled, err := Compile(Config{Rules: []Rule{{Action: ActionAllow, Transports: []Transport{TransportDNS}, DNSSuffixes: []string{"example.com"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		if !compiled.CheckDNS(OperationDNSResolve, "service.api.example.com") {
			t.Fatal("canonical DNS name denied")
		}
	}); allocs != 0 {
		t.Fatalf("canonical DNS policy check allocated %v times", allocs)
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
