package net_test

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dhcpv4"
	"github.com/wago-org/net/dhcpv6"
	"github.com/wago-org/net/dns"
	"github.com/wago-org/net/icmpv4"
	"github.com/wago-org/net/icmpv6"
	"github.com/wago-org/net/ipv6"
	"github.com/wago-org/net/linklocal4"
	"github.com/wago-org/net/mdns"
	"github.com/wago-org/net/ntp"
	"github.com/wago-org/net/tcp"
	"github.com/wago-org/net/udp"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

type protocolSelection struct {
	name       string
	module     string
	capability wago.Capability
	imports    int
	register   func(*wagonet.Network) error
}

var publicProtocols = []protocolSelection{
	{name: "tcp", module: wagonet.TCPModule, capability: wagonet.CapTCP, imports: 11, register: func(network *wagonet.Network) error { return tcp.Register(network) }},
	{name: "udp", module: wagonet.UDPModule, capability: wagonet.CapUDP, imports: 6, register: func(network *wagonet.Network) error { return udp.Register(network) }},
	{name: "dns", module: wagonet.DNSModule, capability: wagonet.CapDNS, imports: 6, register: func(network *wagonet.Network) error { return dns.Register(network) }},
	{name: "icmpv4", module: wagonet.ICMPv4Module, capability: wagonet.CapICMPv4, imports: 6, register: func(network *wagonet.Network) error { return icmpv4.Register(network) }},
	{name: "ntp", module: wagonet.NTPModule, capability: wagonet.CapNTP, imports: 6, register: func(network *wagonet.Network) error { return ntp.Register(network) }},
	{name: "mdns", module: wagonet.MDNSModule, capability: wagonet.CapMDNS, imports: 10, register: func(network *wagonet.Network) error { return mdns.Register(network) }},
	{name: "dhcpv4", module: wagonet.DHCPv4Module, capability: wagonet.CapDHCPv4, imports: 7, register: func(network *wagonet.Network) error { return dhcpv4.Register(network) }},
	{name: "linklocal4", module: wagonet.LinkLocal4Module, capability: wagonet.CapLinkLocal4, imports: 7, register: func(network *wagonet.Network) error { return linklocal4.Register(network) }},
	{name: "ipv6", module: wagonet.IPv6Module, capability: wagonet.CapIPv6, imports: 3, register: func(network *wagonet.Network) error {
		return ipv6.Register(network, ipv6.WithConfig(ipv6.DefaultConfig(netip.MustParseAddr("2001:db8::1"), 64, 0)))
	}},
	{name: "icmpv6", module: wagonet.ICMPv6Module, capability: wagonet.CapICMPv6, imports: 14, register: func(network *wagonet.Network) error { return icmpv6.Register(network) }},
	{name: "dhcpv6", module: wagonet.DHCPv6Module, capability: wagonet.CapDHCPv6, imports: 7, register: func(network *wagonet.Network) error { return dhcpv6.Register(network) }},
}

func TestPublicSelectiveCompositionMatrix(t *testing.T) {
	combinations := 1 << len(publicProtocols)
	for mask := 0; mask < combinations; mask++ {
		mask := mask
		name := selectionName(mask)
		t.Run(name, func(t *testing.T) {
			network := wagonet.New()
			selected := make(map[string]bool, len(publicProtocols))
			wantImports := make(map[string]int)
			var wantCaps []wago.Capability
			if mask != 0 {
				wantImports[wagonet.Module] = 1
				wantCaps = append(wantCaps, wagonet.CapInfo)
			}
			for i, protocol := range publicProtocols {
				if mask&(1<<i) == 0 {
					continue
				}
				if err := protocol.register(network); err != nil {
					t.Fatalf("register %s: %v", protocol.name, err)
				}
				selected[protocol.name] = true
				wantImports[protocol.module] = protocol.imports
				wantCaps = append(wantCaps, protocol.capability)
			}
			slices.Sort(wantCaps)

			runtime := wago.NewRuntime()
			if err := runtime.Use(network); err != nil {
				t.Fatalf("Use: %v", err)
			}
			if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCaps) {
				t.Fatalf("Capabilities = %v, want %v", got, wantCaps)
			}
			gotImports := make(map[string]int)
			for _, spec := range runtime.ProvidedImports() {
				gotImports[spec.Module]++
			}
			if !reflect.DeepEqual(gotImports, wantImports) {
				t.Fatalf("import modules = %v, want %v", gotImports, wantImports)
			}
			for _, protocol := range publicProtocols {
				if !selected[protocol.name] {
					assertUnresolvedProtocolImport(t, runtime, protocol)
				}
			}
		})
	}
}

func selectionName(mask int) string {
	if mask == 0 {
		return "none"
	}
	names := make([]string, 0, len(publicProtocols))
	for i, protocol := range publicProtocols {
		if mask&(1<<i) != 0 {
			names = append(names, protocol.name)
		}
	}
	return strings.Join(names, "_")
}

func assertUnresolvedProtocolImport(t *testing.T, runtime *wago.Runtime, protocol protocolSelection) {
	t.Helper()
	module, err := runtime.Compile(publicNamespaceImportModule(protocol.module))
	if err == nil {
		var instance *wago.Instance
		instance, err = runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{protocol.capability}}))
		if instance != nil {
			_ = instance.Close()
		}
	}
	if err == nil {
		t.Fatalf("unregistered %s import unexpectedly resolved", protocol.module)
	}
}

func publicNamespaceImportModule(module string) []byte {
	entry := append(append(wasmtest.Name(module), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	return wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(entry)),
	)
}
