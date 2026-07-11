package net_test

import (
	"context"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
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
}

func TestPublicSelectiveCompositionMatrix(t *testing.T) {
	tests := []struct {
		name     string
		selected []string
		caps     []wago.Capability
		imports  map[string]int
	}{
		{name: "none", imports: map[string]int{}},
		{name: "tcp", selected: []string{"tcp"}, caps: []wago.Capability{wagonet.CapInfo, wagonet.CapTCP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11}},
		{name: "udp", selected: []string{"udp"}, caps: []wago.Capability{wagonet.CapInfo, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.UDPModule: 6}},
		{name: "dns", selected: []string{"dns"}, caps: []wago.Capability{wagonet.CapDNS, wagonet.CapInfo}, imports: map[string]int{wagonet.Module: 1, wagonet.DNSModule: 6}},
		{name: "tcp_udp", selected: []string{"tcp", "udp"}, caps: []wago.Capability{wagonet.CapInfo, wagonet.CapTCP, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.UDPModule: 6}},
		{name: "tcp_dns", selected: []string{"tcp", "dns"}, caps: []wago.Capability{wagonet.CapDNS, wagonet.CapInfo, wagonet.CapTCP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.DNSModule: 6}},
		{name: "udp_dns", selected: []string{"udp", "dns"}, caps: []wago.Capability{wagonet.CapDNS, wagonet.CapInfo, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.UDPModule: 6, wagonet.DNSModule: 6}},
		{name: "all", selected: []string{"tcp", "udp", "dns"}, caps: []wago.Capability{wagonet.CapDNS, wagonet.CapInfo, wagonet.CapTCP, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.UDPModule: 6, wagonet.DNSModule: 6}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network := wagonet.New()
			selected := make(map[string]bool, len(test.selected))
			for _, name := range test.selected {
				protocol := publicProtocol(t, name)
				if err := protocol.register(network); err != nil {
					t.Fatalf("register %s: %v", name, err)
				}
				selected[name] = true
			}

			runtime := wago.NewRuntime()
			if err := runtime.Use(network); err != nil {
				t.Fatalf("Use: %v", err)
			}
			if got := runtime.Capabilities(); !reflect.DeepEqual(got, test.caps) {
				t.Fatalf("Capabilities = %v, want %v", got, test.caps)
			}
			gotImports := make(map[string]int)
			for _, spec := range runtime.ProvidedImports() {
				gotImports[spec.Module]++
			}
			if !reflect.DeepEqual(gotImports, test.imports) {
				t.Fatalf("import modules = %v, want %v", gotImports, test.imports)
			}

			for _, protocol := range publicProtocols {
				if selected[protocol.name] {
					continue
				}
				assertUnresolvedProtocolImport(t, runtime, protocol)
			}
		})
	}
}

func publicProtocol(t *testing.T, name string) protocolSelection {
	t.Helper()
	for _, protocol := range publicProtocols {
		if protocol.name == name {
			return protocol
		}
	}
	t.Fatalf("unknown protocol %q", name)
	return protocolSelection{}
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
