package ipv6

import (
	"encoding/binary"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
)

func TestEncodeConfigurationV1AtomicLayout(t *testing.T) {
	configuration := ipv6ns.Configuration{
		Address: netip.MustParseAddr("fe80::7"), PrefixBits: 64, ScopeID: 3, MTU: 1280,
		Transports: ipv6ns.TransportTCPConnect | ipv6ns.TransportTCPListen,
	}
	memory := make([]byte, ConfigurationV1Size+2)
	memory[0], memory[len(memory)-1] = 0xaa, 0xbb
	if !EncodeConfigurationV1(memory, 1, configuration) {
		t.Fatal("encode failed")
	}
	if memory[0] != 0xaa || memory[len(memory)-1] != 0xbb {
		t.Fatal("encode mutated outside output")
	}
	endpoint, ok := abicore.DecodeEndpointV1(memory, 1)
	if !ok || endpoint.Address != configuration.Address || endpoint.ScopeID != 3 || endpoint.Port != 0 || endpoint.FlowInfo != 0 {
		t.Fatalf("endpoint = %+v ok=%v", endpoint, ok)
	}
	encoded := memory[1 : 1+ConfigurationV1Size]
	if got := binary.LittleEndian.Uint32(encoded[32:36]); got != 64 {
		t.Fatalf("prefix bits = %d", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[36:40]); got != ConfigurationFlagEnabled|ConfigurationFlagLinkLocal {
		t.Fatalf("flags = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[40:44]); got != uint32(configuration.Transports) {
		t.Fatalf("transports = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[44:48]); got != 1280 {
		t.Fatalf("MTU = %d", got)
	}
	for i, value := range encoded[48:] {
		if value != 0 {
			t.Fatalf("reserved/max-extension byte %d = %d", i, value)
		}
	}
}

func TestEncodeConfigurationV1RejectsInvalidWithoutMutation(t *testing.T) {
	memory := make([]byte, ConfigurationV1Size)
	for i := range memory {
		memory[i] = 0x5a
	}
	before := append([]byte(nil), memory...)
	invalid := ipv6ns.Configuration{Address: netip.MustParseAddr("2001:db8::1"), PrefixBits: 64, MTU: 1500}
	if EncodeConfigurationV1(memory, 0, invalid) {
		t.Fatal("invalid configuration encoded")
	}
	if string(memory) != string(before) {
		t.Fatal("failed encode mutated output")
	}
	valid := invalid
	valid.Transports = ipv6ns.TransportTCPConnect
	if EncodeConfigurationV1(memory, 1, valid) {
		t.Fatal("out-of-bounds configuration encoded")
	}
	if string(memory) != string(before) {
		t.Fatal("range failure mutated output")
	}
}
