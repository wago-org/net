package dhcpv6

import (
	"net/netip"
	"testing"
)

var (
	benchmarkValid bool
	benchmarkName  Name
)

func BenchmarkNewName(b *testing.B) {
	for b.Loop() {
		var ok bool
		benchmarkName, ok = NewName("service.example.com")
		if !ok {
			b.Fatal("name")
		}
	}
}

func BenchmarkNameValid(b *testing.B) {
	name, ok := NewName("service.example.com")
	if !ok {
		b.Fatal("name")
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkValid = name.Valid()
	}
}

func BenchmarkConfigurationValid(b *testing.B) {
	name, _ := NewName("example.com")
	configuration := Configuration{
		TransactionID:            0x123456,
		IAID:                     [4]byte{2, 0, 0, 1},
		AssignedAddr:             netip.MustParseAddr("2001:db8::10"),
		ServerAddr:               netip.MustParseAddr("fe80::1"),
		ServerScopeID:            7,
		ServerDUIDLength:         10,
		PreferredLifetimeSeconds: 1800,
		ValidLifetimeSeconds:     3600,
		DomainCount:              1,
		DomainSearch:             [MaxDomainSearch]Name{name},
	}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 3, 4, 5, 6, 7})
	b.ReportAllocs()
	for b.Loop() {
		benchmarkValid = configuration.Valid()
	}
}
