package net

import (
	"context"
	"errors"
	"reflect"
	"testing"

	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestSelectiveProtocolRegistrationMatrix(t *testing.T) {
	tests := []struct {
		name         string
		protocols    string
		capabilities []wago.Capability
		imports      map[string]int
	}{
		{name: "none", capabilities: nil, imports: map[string]int{}},
		{name: "tcp", protocols: "t", capabilities: []wago.Capability{CapInfo, CapTCP}, imports: map[string]int{Module: 1, TCPModule: 11}},
		{name: "udp", protocols: "u", capabilities: []wago.Capability{CapInfo, CapUDP}, imports: map[string]int{Module: 1, UDPModule: 6}},
		{name: "dns", protocols: "d", capabilities: []wago.Capability{CapDNS, CapInfo}, imports: map[string]int{Module: 1, DNSModule: 6}},
		{name: "tcp_udp", protocols: "tu", capabilities: []wago.Capability{CapInfo, CapTCP, CapUDP}, imports: map[string]int{Module: 1, TCPModule: 11, UDPModule: 6}},
		{name: "tcp_dns", protocols: "td", capabilities: []wago.Capability{CapDNS, CapInfo, CapTCP}, imports: map[string]int{Module: 1, TCPModule: 11, DNSModule: 6}},
		{name: "udp_dns", protocols: "ud", capabilities: []wago.Capability{CapDNS, CapInfo, CapUDP}, imports: map[string]int{Module: 1, UDPModule: 6, DNSModule: 6}},
		{name: "all", protocols: "tud", capabilities: []wago.Capability{CapDNS, CapInfo, CapTCP, CapUDP}, imports: map[string]int{Module: 1, TCPModule: 11, UDPModule: 6, DNSModule: 6}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network := New()
			for _, protocol := range test.protocols {
				var err error
				switch protocol {
				case 't':
					err = network.registerTCPModule()
				case 'u':
					err = network.registerUDPModule()
				case 'd':
					err = network.registerDNSModule()
				}
				if err != nil {
					t.Fatalf("register %q: %v", protocol, err)
				}
			}

			runtime := wago.NewRuntime()
			if err := runtime.Use(network); err != nil {
				t.Fatalf("Use: %v", err)
			}
			if got := runtime.Capabilities(); !reflect.DeepEqual(got, test.capabilities) {
				t.Fatalf("Capabilities = %v, want %v", got, test.capabilities)
			}
			gotImports := make(map[string]int)
			for _, spec := range runtime.ProvidedImports() {
				gotImports[spec.Module]++
			}
			if !reflect.DeepEqual(gotImports, test.imports) {
				t.Fatalf("import modules = %v, want %v", gotImports, test.imports)
			}
		})
	}
}

func TestProtocolRegistrationFreezesAndRejectsDuplicates(t *testing.T) {
	network := New()
	if err := network.registerTCPModule(); err != nil {
		t.Fatalf("register TCP: %v", err)
	}
	if err := network.registerTCPModule(); !errors.Is(err, ErrProtocolAlreadyRegistered) {
		t.Fatalf("duplicate TCP registration = %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if err := network.registerUDPModule(); !errors.Is(err, ErrProtocolRegistrationFrozen) {
		t.Fatalf("registration after freeze = %v", err)
	}
}

func TestUnregisteredProtocolFailsOrdinaryImportResolution(t *testing.T) {
	network := New()
	if err := network.registerTCPModule(); err != nil {
		t.Fatalf("register TCP: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}

	tcpModule, err := runtime.Compile(namespaceImportModule(TCPModule))
	if err != nil {
		t.Fatalf("compile registered TCP import: %v", err)
	}
	tcpInstance, err := runtime.Instantiate(context.Background(), tcpModule, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{CapTCP}}))
	if err != nil {
		t.Fatalf("instantiate registered TCP import: %v", err)
	}
	_ = tcpInstance.Close()

	udpModule, err := runtime.Compile(namespaceImportModule(UDPModule))
	if err == nil {
		var instance *wago.Instance
		instance, err = runtime.Instantiate(context.Background(), udpModule, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{CapUDP}}))
		if instance != nil {
			_ = instance.Close()
		}
	}
	if err == nil {
		t.Fatal("unregistered UDP import unexpectedly resolved")
	}
}

func namespaceImportModule(module string) []byte {
	entry := append(append(wasmtest.Name(module), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	return wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(entry)),
	)
}
