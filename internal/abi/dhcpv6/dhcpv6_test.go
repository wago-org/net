package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
)

func TestConfigurationEncodingIsCheckedAndAtomic(t *testing.T) {
	memory := make([]byte, ConfigurationV1Size+16)
	name, _ := dhcpns.NewName("example.com")
	configuration := dhcpns.Configuration{TransactionID: 0x123456, IAID: [4]byte{2, 0, 0, 1}, AssignedAddr: netip.MustParseAddr("2001:db8::10"), ServerAddr: netip.MustParseAddr("fe80::1"), ServerScopeID: 7, ServerDUIDLength: 10, PreferredLifetimeSeconds: 1800, ValidLifetimeSeconds: 3600, DNSCount: 1, DNSServers: [dhcpns.MaxDNSServers]netip.Addr{netip.MustParseAddr("2001:db8::53")}, DomainCount: 1, DomainSearch: [dhcpns.MaxDomainSearch]dhcpns.Name{name}}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 3, 4, 5, 6, 7})
	if !EncodeConfigurationV1(memory, 8, configuration) {
		t.Fatal("encode")
	}
	if binary.LittleEndian.Uint32(memory[8:12]) != 0x123456 || binary.LittleEndian.Uint32(memory[8+offsetDNSCount:8+offsetDNSCount+4]) != 1 {
		t.Fatal("layout mismatch")
	}
	before := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size))
	copy(memory[8:], before)
	configuration.ServerDUIDLength = 0
	if EncodeConfigurationV1(memory, 8, configuration) || !bytes.Equal(before, memory[8:8+ConfigurationV1Size]) {
		t.Fatal("invalid configuration mutated output")
	}
	if EncodeConfigurationV1(memory, uint32(len(memory)-1), dhcpns.Configuration{}) {
		t.Fatal("out-of-bounds encode")
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
