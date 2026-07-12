package policy

import (
	"fmt"
	"net/netip"
	"testing"
)

var (
	benchmarkBool   bool
	benchmarkConfig Config
	benchmarkPolicy *Policy
)

func benchmarkPolicyConfig() Config {
	return Config{
		AllowWildcardBind: true,
		Rules: []Rule{
			{Action: ActionDeny, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Ports: []PortRange{{First: 1, Last: 1023}}},
			{Action: ActionAllow, Transports: []Transport{TransportUDP, TransportTCP}, Directions: []Direction{DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}, Ports: []PortRange{{First: 53, Last: 53}, {First: 443, Last: 443}, {First: 8000, Last: 9000}}},
			{Action: ActionAllow, Transports: []Transport{TransportDNS}, Directions: []Direction{DirectionOutbound}, DNSSuffixes: []string{"example.com", "internal.example.com"}},
		},
	}
}

func BenchmarkMerge(b *testing.B) {
	first := benchmarkPolicyConfig()
	second := Config{AllowLoopback: true, Rules: []Rule{{Action: ActionDeny, Transports: []Transport{TransportUDP}, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}}}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkConfig = Merge(first, second)
	}
}

func BenchmarkCompile(b *testing.B) {
	config := benchmarkPolicyConfig()
	b.ReportAllocs()
	for b.Loop() {
		var err error
		benchmarkPolicy, err = Compile(config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPolicyCheckEndpoint(b *testing.B) {
	compiled, err := Compile(benchmarkPolicyConfig())
	if err != nil {
		b.Fatal(err)
	}
	address := netip.MustParseAddr("192.0.2.42")
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = compiled.CheckEndpoint(OperationTCPConnect, address, 443)
	}
}

func BenchmarkPolicyCheckEndpointScaling(b *testing.B) {
	address := netip.MustParseAddr("192.0.2.42")
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	for _, count := range []int{1, 16, 256} {
		b.Run(fmt.Sprintf("rules=%d", count), func(b *testing.B) {
			config := Config{Rules: make([]Rule, count)}
			for i := range config.Rules {
				config.Rules[i] = Rule{
					Action: ActionAllow, Transports: []Transport{TransportTCP}, Directions: []Direction{DirectionOutbound},
					Prefixes: []netip.Prefix{prefix}, Ports: []PortRange{{First: 443, Last: 443}},
				}
			}
			compiled, err := Compile(config)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkBool = compiled.CheckEndpoint(OperationTCPConnect, address, 443)
			}
		})
	}
}

func BenchmarkPolicyCheckDNS(b *testing.B) {
	compiled, err := Compile(benchmarkPolicyConfig())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = compiled.CheckDNS(OperationDNSResolve, "service.internal.example.com")
	}
}
