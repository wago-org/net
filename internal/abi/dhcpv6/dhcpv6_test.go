package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
)

func TestConfigurationEncodingIsCheckedAndAtomic(t *testing.T) {
	memory := make([]byte, ConfigurationV1Size+16)
	name, _ := dhcpns.NewName("example.com")
	configuration := dhcpns.Configuration{TransactionID: 0x123456, IAID: [4]byte{2, 0, 0, 1}, AssignedAddr: netip.MustParseAddr("2001:db8::10"), ServerAddr: netip.MustParseAddr("fe80::1"), ServerScopeID: 7, ServerDUIDLength: 10, PreferredLifetimeSeconds: 1800, ValidLifetimeSeconds: 3600, DNSCount: 1, DNSServers: [dhcpns.MaxDNSServers]netip.Addr{netip.MustParseAddr("2001:db8::53")}, DomainCount: 1, DomainSearch: [dhcpns.MaxDomainSearch]dhcpns.Name{name}}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 3, 4, 5, 6, 7})
	if !EncodeConfigurationV1(memory, 8, &configuration) {
		t.Fatal("encode")
	}
	if binary.LittleEndian.Uint32(memory[8:12]) != 0x123456 || binary.LittleEndian.Uint32(memory[8+offsetDNSCount:8+offsetDNSCount+4]) != 1 {
		t.Fatal("layout mismatch")
	}
	valid := configuration
	before := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size))
	copy(memory[8:], before)
	configuration.ServerDUIDLength = 0
	if EncodeConfigurationV1(memory, 8, &configuration) || !bytes.Equal(before, memory[8:8+ConfigurationV1Size]) {
		t.Fatal("invalid configuration mutated output")
	}
	outOfBoundsBefore := append([]byte(nil), memory...)
	if EncodeConfigurationV1(memory, uint32(len(memory)-1), &valid) || !bytes.Equal(memory, outOfBoundsBefore) {
		t.Fatal("out-of-bounds encode mutated output")
	}
	if EncodeConfigurationV1(memory, 8, nil) || !bytes.Equal(memory, outOfBoundsBefore) {
		t.Fatal("nil configuration mutated output")
	}
}

func TestConfigurationEncodingCoversEveryFixedSection(t *testing.T) {
	configuration := completeConfiguration()
	if !configuration.Valid() {
		t.Fatal("test configuration is invalid")
	}
	memory := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size)+32)
	if !EncodeConfigurationV1(memory, 16, &configuration) {
		t.Fatal("encode")
	}
	if !bytes.Equal(memory[:16], bytes.Repeat([]byte{0xa5}, 16)) || !bytes.Equal(memory[16+ConfigurationV1Size:], bytes.Repeat([]byte{0xa5}, 16)) {
		t.Fatal("encode mutated bytes outside the fixed output")
	}
	assertConfigurationEncoding(t, memory, 16, &configuration)
}

func TestConfigurationEncodingRejectsMalformedValuesAtomically(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*dhcpns.Configuration)
	}{
		{name: "transaction", mutate: func(c *dhcpns.Configuration) { c.TransactionID = 0 }},
		{name: "iaid", mutate: func(c *dhcpns.Configuration) { c.IAID = [4]byte{} }},
		{name: "assigned", mutate: func(c *dhcpns.Configuration) { c.AssignedAddr = netip.Addr{} }},
		{name: "server scope", mutate: func(c *dhcpns.Configuration) { c.ServerScopeID = 0 }},
		{name: "duid length", mutate: func(c *dhcpns.Configuration) { c.ServerDUIDLength = 0 }},
		{name: "duid trailing", mutate: func(c *dhcpns.Configuration) { c.ServerDUID[dhcpns.MaxServerDUIDBytes-1] = 1 }},
		{name: "preferred lifetime", mutate: func(c *dhcpns.Configuration) { c.PreferredLifetimeSeconds = c.ValidLifetimeSeconds + 1 }},
		{name: "dns count", mutate: func(c *dhcpns.Configuration) { c.DNSCount = dhcpns.MaxDNSServers + 1 }},
		{name: "dns inactive", mutate: func(c *dhcpns.Configuration) { c.DNSCount = 1 }},
		{name: "domain count", mutate: func(c *dhcpns.Configuration) { c.DomainCount = dhcpns.MaxDomainSearch + 1 }},
		{name: "domain inactive", mutate: func(c *dhcpns.Configuration) { c.DomainCount = 1 }},
		{name: "ntp count", mutate: func(c *dhcpns.Configuration) { c.NTPCount = dhcpns.MaxNTPServers + 1 }},
		{name: "ntp inactive", mutate: func(c *dhcpns.Configuration) { c.NTPCount = 1 }},
		{name: "multicast count", mutate: func(c *dhcpns.Configuration) { c.NTPMulticastCount = dhcpns.MaxNTPMulticastServers + 1 }},
		{name: "name count", mutate: func(c *dhcpns.Configuration) { c.NTPNameCount = dhcpns.MaxNTPServerNames + 1 }},
		{name: "name inactive", mutate: func(c *dhcpns.Configuration) { c.NTPNameCount = 1 }},
		{name: "prefix count", mutate: func(c *dhcpns.Configuration) { c.PrefixCount = dhcpns.MaxDelegatedPrefixes + 1 }},
		{name: "prefix inactive", mutate: func(c *dhcpns.Configuration) { c.PrefixCount = 1 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			configuration := completeConfiguration()
			test.mutate(&configuration)
			memory := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size)+16)
			before := append([]byte(nil), memory...)
			if EncodeConfigurationV1(memory, 8, &configuration) {
				t.Fatal("malformed configuration encoded")
			}
			if !bytes.Equal(memory, before) {
				t.Fatal("failed encode mutated output")
			}
		})
	}

	configuration := completeConfiguration()
	for _, ptr := range []uint32{17, ^uint32(0), ^uint32(0) - ConfigurationV1Size + 1} {
		memory := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size)+16)
		before := append([]byte(nil), memory...)
		if EncodeConfigurationV1(memory, ptr, &configuration) || !bytes.Equal(memory, before) {
			t.Fatalf("out-of-range pointer %d mutated output", ptr)
		}
	}
}

func FuzzEncodeConfigurationV1Atomic(f *testing.F) {
	f.Add(uint32(8), uint8(0), uint32(0x123456))
	f.Add(^uint32(0), uint8(1), uint32(0))
	f.Add(uint32(0), uint8(7), uint32(dhcpns.MaxDNSServers+1))
	f.Fuzz(func(t *testing.T, ptr uint32, selector uint8, value uint32) {
		configuration := completeConfiguration()
		switch selector % 14 {
		case 0:
			configuration.TransactionID = value
		case 1:
			configuration.ServerDUIDLength = uint16(value)
		case 2:
			configuration.RenewalSeconds = value
		case 3:
			configuration.RebindingSeconds = value
		case 4:
			configuration.PreferredLifetimeSeconds = value
		case 5:
			configuration.ValidLifetimeSeconds = value
		case 6:
			configuration.DNSCount = uint8(value)
		case 7:
			configuration.DomainCount = uint8(value)
		case 8:
			configuration.NTPCount = uint8(value)
		case 9:
			configuration.NTPMulticastCount = uint8(value)
		case 10:
			configuration.NTPNameCount = uint8(value)
		case 11:
			configuration.PrefixCount = uint8(value)
		case 12:
			configuration.PrefixRenewalSeconds = value
		case 13:
			configuration.PrefixRebindingSeconds = value
		}
		memory := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size)+16)
		before := append([]byte(nil), memory...)
		encoded := EncodeConfigurationV1(memory, ptr, &configuration)
		if !encoded {
			if !bytes.Equal(memory, before) {
				t.Fatal("failed encode mutated output")
			}
			return
		}
		if !configuration.Valid() || uint64(ptr)+uint64(ConfigurationV1Size) > uint64(len(memory)) {
			t.Fatal("encode succeeded without valid complete range")
		}
		if !bytes.Equal(memory[:int(ptr)], before[:int(ptr)]) || !bytes.Equal(memory[int(ptr+ConfigurationV1Size):], before[int(ptr+ConfigurationV1Size):]) {
			t.Fatal("successful encode mutated bytes outside output")
		}
		assertConfigurationEncoding(t, memory, ptr, &configuration)
	})
}

func completeConfiguration() dhcpns.Configuration {
	domain0, _ := dhcpns.NewName("example.com")
	domain1, _ := dhcpns.NewName("lab.example.com")
	ntpName0, _ := dhcpns.NewName("time.example.com")
	ntpName1, _ := dhcpns.NewName("clock.example.com")
	configuration := dhcpns.Configuration{
		TransactionID: 0x123456, IAID: [4]byte{2, 0, 0, 1},
		AssignedAddr: netip.MustParseAddr("2001:db8::10"), ServerAddr: netip.MustParseAddr("fe80::1"), ServerScopeID: 7,
		ServerDUIDLength: 10,
		RenewalSeconds:   900, RebindingSeconds: 1800, PreferredLifetimeSeconds: 1800, ValidLifetimeSeconds: 3600,
		PrefixRenewalSeconds: 1200, PrefixRebindingSeconds: 2400,
		DNSCount: 2, DNSServers: [dhcpns.MaxDNSServers]netip.Addr{netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("2001:db8::54")},
		DomainCount: 2, DomainSearch: [dhcpns.MaxDomainSearch]dhcpns.Name{domain0, domain1},
		NTPCount: 2, NTPServers: [dhcpns.MaxNTPServers]netip.Addr{netip.MustParseAddr("2001:db8::123"), netip.MustParseAddr("2001:db8::124")},
		NTPMulticastCount: 1, NTPMulticastServers: [dhcpns.MaxNTPMulticastServers]netip.Addr{netip.MustParseAddr("ff05::101")},
		NTPNameCount: 2, NTPServerNames: [dhcpns.MaxNTPServerNames]dhcpns.Name{ntpName0, ntpName1},
		PrefixCount: 2, DelegatedPrefixes: [dhcpns.MaxDelegatedPrefixes]dhcpns.DelegatedPrefix{
			{Prefix: netip.MustParsePrefix("2001:db8:100::/48"), PreferredLifetime: 3600, ValidLifetime: 7200},
			{Prefix: netip.MustParsePrefix("2001:db8:200::/56"), PreferredLifetime: 5400, ValidLifetime: 10800},
		},
	}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 3, 4, 5, 6, 7})
	return configuration
}

func assertConfigurationEncoding(t testing.TB, memory []byte, ptr uint32, configuration *dhcpns.Configuration) {
	t.Helper()
	output := memory[ptr : ptr+ConfigurationV1Size]
	if binary.LittleEndian.Uint32(output[offsetTransaction:offsetTransaction+4]) != configuration.TransactionID || [4]byte(output[offsetIAID:offsetIAID+4]) != configuration.IAID {
		t.Fatal("transaction or IAID layout mismatch")
	}
	assigned, ok := abicore.DecodeEndpointV1(output, offsetAssigned)
	if !ok || assigned != (nscore.Endpoint{Address: configuration.AssignedAddr}) {
		t.Fatalf("assigned endpoint = %+v, %v", assigned, ok)
	}
	server, ok := abicore.DecodeEndpointV1(output, offsetServer)
	if !ok || server != (nscore.Endpoint{Address: configuration.ServerAddr, ScopeID: configuration.ServerScopeID}) {
		t.Fatalf("server endpoint = %+v, %v", server, ok)
	}
	if !bytes.Equal(output[offsetReserved:offsetRenewal], make([]byte, offsetRenewal-offsetReserved)) {
		t.Fatal("header reserved field is nonzero")
	}
	counts := []struct {
		offset uint32
		want   uint32
	}{
		{offsetServerDUIDLength, uint32(configuration.ServerDUIDLength)},
		{offsetDNSCount, uint32(configuration.DNSCount)},
		{offsetDomainCount, uint32(configuration.DomainCount)},
		{offsetNTPCount, uint32(configuration.NTPCount)},
		{offsetNTPMulticastCount, uint32(configuration.NTPMulticastCount)},
		{offsetNTPNameCount, uint32(configuration.NTPNameCount)},
		{offsetPrefixCount, uint32(configuration.PrefixCount)},
	}
	for _, count := range counts {
		if got := binary.LittleEndian.Uint32(output[count.offset : count.offset+4]); got != count.want {
			t.Fatalf("count at %d = %d, want %d", count.offset, got, count.want)
		}
	}
	if !bytes.Equal(output[offsetServerDUID:offsetServerDUID+dhcpns.MaxServerDUIDBytes], configuration.ServerDUID[:]) {
		t.Fatal("server DUID layout mismatch")
	}
	for i := 0; i < int(configuration.DNSCount); i++ {
		endpoint, ok := abicore.DecodeEndpointV1(output, offsetDNS+uint32(i)*abicore.AddressV1Size)
		if !ok || endpoint != (nscore.Endpoint{Address: configuration.DNSServers[i]}) {
			t.Fatalf("DNS endpoint %d = %+v, %v", i, endpoint, ok)
		}
	}
	for i := 0; i < int(configuration.DomainCount); i++ {
		assertNameEncoding(t, output, offsetDomains+uint32(i)*NameV1Size, configuration.DomainSearch[i])
	}
	for i := 0; i < int(configuration.NTPCount); i++ {
		endpoint, ok := abicore.DecodeEndpointV1(output, offsetNTP+uint32(i)*abicore.AddressV1Size)
		if !ok || endpoint != (nscore.Endpoint{Address: configuration.NTPServers[i]}) {
			t.Fatalf("NTP endpoint %d = %+v, %v", i, endpoint, ok)
		}
	}
	for i := 0; i < int(configuration.NTPMulticastCount); i++ {
		endpoint, ok := abicore.DecodeEndpointV1(output, offsetNTPMulticast+uint32(i)*abicore.AddressV1Size)
		if !ok || endpoint != (nscore.Endpoint{Address: configuration.NTPMulticastServers[i]}) {
			t.Fatalf("multicast NTP endpoint %d = %+v, %v", i, endpoint, ok)
		}
	}
	for i := 0; i < int(configuration.NTPNameCount); i++ {
		assertNameEncoding(t, output, offsetNTPNames+uint32(i)*NameV1Size, configuration.NTPServerNames[i])
	}
	for i := 0; i < int(configuration.PrefixCount); i++ {
		offset := offsetPrefixes + uint32(i)*PrefixV1Size
		endpoint, ok := abicore.DecodeEndpointV1(output, offset)
		prefix := configuration.DelegatedPrefixes[i]
		if !ok || endpoint != (nscore.Endpoint{Address: prefix.Prefix.Addr()}) || binary.LittleEndian.Uint32(output[offset+32:offset+36]) != uint32(prefix.Prefix.Bits()) || binary.LittleEndian.Uint32(output[offset+36:offset+40]) != prefix.PreferredLifetime || binary.LittleEndian.Uint32(output[offset+40:offset+44]) != prefix.ValidLifetime || !bytes.Equal(output[offset+44:offset+48], []byte{0, 0, 0, 0}) {
			t.Fatalf("prefix %d layout mismatch", i)
		}
	}
}

func assertNameEncoding(t testing.TB, output []byte, offset uint32, name dhcpns.Name) {
	t.Helper()
	encoded := output[offset : offset+NameV1Size]
	if binary.LittleEndian.Uint16(encoded[:2]) != name.Length || !bytes.Equal(encoded[2:4], []byte{0, 0}) || !bytes.Equal(encoded[4:4+dhcpns.MaxNameBytes], name.Bytes[:]) || !bytes.Equal(encoded[4+dhcpns.MaxNameBytes:], []byte{0, 0, 0}) {
		t.Fatalf("name layout mismatch at %d", offset)
	}
}

func TestOperationsEncodingRejectsUnknownBits(t *testing.T) {
	memory := make([]byte, 8)
	if !EncodeOperationsV1(memory, 0, dhcpns.SupportedOperations) || binary.LittleEndian.Uint32(memory[:4]) != 1 {
		t.Fatal("operations")
	}
	if EncodeOperationsV1(memory, 0, 1<<31) {
		t.Fatal("unknown operations encoded")
	}
}
