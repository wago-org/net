package ipv6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
)

func TestEncodeConfigurationV1CompleteAtomicLayout(t *testing.T) {
	configuration := completeConfiguration()
	memory := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size)+16)
	if !EncodeConfigurationV1(memory, 8, configuration) {
		t.Fatal("encode failed")
	}
	if !bytes.Equal(memory[:8], bytes.Repeat([]byte{0xa5}, 8)) || !bytes.Equal(memory[8+ConfigurationV1Size:], bytes.Repeat([]byte{0xa5}, 8)) {
		t.Fatal("encode mutated outside output")
	}
	assertConfigurationV1(t, memory, 8, configuration)
}

func TestEncodeConfigurationV1RejectsMalformedAndOverflowingOutputAtomically(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*ipv6ns.Configuration)
	}{
		{name: "address", mutate: func(c *ipv6ns.Configuration) { c.Address = netip.Addr{} }},
		{name: "prefix", mutate: func(c *ipv6ns.Configuration) { c.PrefixBits = 0 }},
		{name: "scope", mutate: func(c *ipv6ns.Configuration) { c.ScopeID = 0 }},
		{name: "mtu", mutate: func(c *ipv6ns.Configuration) { c.MTU = 1279 }},
		{name: "extension headers", mutate: func(c *ipv6ns.Configuration) { c.MaxExtensionHeaders = 1 }},
		{name: "transports empty", mutate: func(c *ipv6ns.Configuration) { c.Transports = 0 }},
		{name: "transports unknown", mutate: func(c *ipv6ns.Configuration) { c.Transports |= 1 << 31 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			configuration := completeConfiguration()
			test.mutate(&configuration)
			memory := bytes.Repeat([]byte{0x5a}, int(ConfigurationV1Size)+16)
			before := append([]byte(nil), memory...)
			if EncodeConfigurationV1(memory, 8, configuration) || !bytes.Equal(memory, before) {
				t.Fatal("invalid configuration mutated output")
			}
		})
	}

	configuration := completeConfiguration()
	for _, ptr := range []uint32{17, ^uint32(0), ^uint32(0) - ConfigurationV1Size + 1} {
		memory := bytes.Repeat([]byte{0x5a}, int(ConfigurationV1Size)+16)
		before := append([]byte(nil), memory...)
		if EncodeConfigurationV1(memory, ptr, configuration) || !bytes.Equal(memory, before) {
			t.Fatalf("out-of-range pointer %d mutated output", ptr)
		}
	}
}

func FuzzEncodeConfigurationV1Atomic(f *testing.F) {
	f.Add(uint32(8), uint8(0), uint32(64))
	f.Add(^uint32(0), uint8(4), uint32(1))
	f.Add(uint32(0), uint8(6), uint32(1<<31))
	f.Fuzz(func(t *testing.T, ptr uint32, selector uint8, value uint32) {
		configuration := completeConfiguration()
		switch selector % 7 {
		case 0:
			configuration.PrefixBits = uint8(value)
		case 1:
			configuration.ScopeID = value
		case 2:
			configuration.MTU = uint16(value)
		case 3:
			configuration.MaxExtensionHeaders = uint8(value)
		case 4:
			configuration.Transports = ipv6ns.Transports(value)
		case 5:
			configuration.Address = netip.Addr{}
		case 6:
			configuration.Address = netip.MustParseAddr("2001:db8::7")
		}
		memory := bytes.Repeat([]byte{0xa5}, int(ConfigurationV1Size)+16)
		before := append([]byte(nil), memory...)
		encoded := EncodeConfigurationV1(memory, ptr, configuration)
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
		assertConfigurationV1(t, memory, ptr, configuration)
	})
}

func completeConfiguration() ipv6ns.Configuration {
	return ipv6ns.Configuration{
		Address: netip.MustParseAddr("fe80::7"), PrefixBits: 64, ScopeID: 3, MTU: 1280,
		Transports: ipv6ns.TransportTCPConnect | ipv6ns.TransportTCPListen,
	}
}

func assertConfigurationV1(t testing.TB, memory []byte, ptr uint32, configuration ipv6ns.Configuration) {
	t.Helper()
	encoded := memory[ptr : ptr+ConfigurationV1Size]
	endpoint, ok := abicore.DecodeEndpointV1(encoded, 0)
	if !ok || endpoint != (nscore.Endpoint{Address: configuration.Address, ScopeID: configuration.ScopeID}) {
		t.Fatalf("endpoint = %+v ok=%v", endpoint, ok)
	}
	if encoded[0] != byte(abicore.AddressFamilyIPv6) || encoded[1] != 0 || binary.LittleEndian.Uint16(encoded[2:4]) != 0 || binary.LittleEndian.Uint32(encoded[4:8]) != configuration.ScopeID || !bytes.Equal(encoded[8:24], configuration.Address.AsSlice()) || binary.LittleEndian.Uint32(encoded[24:28]) != 0 || binary.LittleEndian.Uint32(encoded[28:32]) != 0 {
		t.Fatal("endpoint fixed layout mismatch")
	}
	flags := ConfigurationFlagEnabled
	if configuration.Address.IsLinkLocalUnicast() {
		flags |= ConfigurationFlagLinkLocal
	}
	if binary.LittleEndian.Uint32(encoded[32:36]) != uint32(configuration.PrefixBits) || binary.LittleEndian.Uint32(encoded[36:40]) != flags || binary.LittleEndian.Uint32(encoded[40:44]) != uint32(configuration.Transports) || binary.LittleEndian.Uint32(encoded[44:48]) != uint32(configuration.MTU) || binary.LittleEndian.Uint32(encoded[48:52]) != uint32(configuration.MaxExtensionHeaders) {
		t.Fatal("configuration fixed layout mismatch")
	}
	if !bytes.Equal(encoded[52:64], make([]byte, 12)) {
		t.Fatal("configuration reserved bytes are nonzero")
	}
}
