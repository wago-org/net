package dhcpv6

import (
	"net/netip"
	"testing"

	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
)

var benchmarkEncodeOK bool

func BenchmarkEncodeConfigurationV1(b *testing.B) {
	memory := make([]byte, ConfigurationV1Size)
	name, _ := dhcpns.NewName("example.com")
	configuration := dhcpns.Configuration{
		TransactionID:            0x123456,
		IAID:                     [4]byte{2, 0, 0, 1},
		AssignedAddr:             netip.MustParseAddr("2001:db8::10"),
		ServerAddr:               netip.MustParseAddr("fe80::1"),
		ServerScopeID:            7,
		ServerDUIDLength:         10,
		PreferredLifetimeSeconds: 1800,
		ValidLifetimeSeconds:     3600,
		DNSCount:                 1,
		DNSServers:               [dhcpns.MaxDNSServers]netip.Addr{netip.MustParseAddr("2001:db8::53")},
		DomainCount:              1,
		DomainSearch:             [dhcpns.MaxDomainSearch]dhcpns.Name{name},
	}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 3, 4, 5, 6, 7})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkEncodeOK = EncodeConfigurationV1(memory, 0, &configuration)
		if !benchmarkEncodeOK {
			b.Fatal("encode failed")
		}
	}
}
