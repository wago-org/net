package udp_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/udp"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestRegisterExposesOnlyUDPAndSharedCore(t *testing.T) {
	network := wagonet.New()
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}

	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	wantCapabilities := []wago.Capability{wagonet.CapInfo, wagonet.CapUDP}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("Capabilities = %v, want %v", got, wantCapabilities)
	}
	imports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	wantImports := map[string]int{wagonet.Module: 1, wagonet.UDPModule: 6}
	if !reflect.DeepEqual(imports, wantImports) {
		t.Fatalf("import modules = %v, want %v", imports, wantImports)
	}
	if _, ok := runtime.HostImports()[wagonet.TCPModule+".namespace_default"]; ok {
		t.Fatal("TCP import exposed by UDP-only registration")
	}
	if _, ok := runtime.HostImports()[wagonet.DNSModule+".namespace_default"]; ok {
		t.Fatal("DNS import exposed by UDP-only registration")
	}
}

func TestRegisterRejectsDuplicateInvalidOptionFrozenAndNilNetwork(t *testing.T) {
	if err := udp.Register(nil); err == nil {
		t.Fatal("nil network registration unexpectedly succeeded")
	}

	network := wagonet.New()
	if err := udp.Register(network, nil); !errors.Is(err, udp.ErrInvalidOption) {
		t.Fatalf("nil option = %v", err)
	}
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := udp.Register(network); !errors.Is(err, wagonet.ErrProtocolAlreadyRegistered) {
		t.Fatalf("duplicate registration = %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if err := udp.Register(network); !errors.Is(err, wagonet.ErrProtocolRegistrationFrozen) {
		t.Fatalf("registration after freeze = %v", err)
	}
}

func TestSelectiveUDPBindingUsesExactSharedInstanceState(t *testing.T) {
	network := wagonet.New()
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Compile empty module: %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()

	fn, ok := runtime.HostImports()[wagonet.UDPModule+".namespace_default"].(wago.HostFunc)
	if !ok {
		t.Fatal("selective UDP namespace binding missing")
	}
	host := exactHost{instance: instance, memory: make([]byte, wagonet.HandleV1Size)}
	results := []uint64{0}
	fn(host, []uint64{0}, results)
	if got := wagonet.Status(wago.AsI32(results[0])); got != wagonet.StatusNotSupported {
		t.Fatalf("namespace_default without configured namespace = %v", got)
	}
}

func TestUDPRegistrationLeavesTCPAndDNSImportsUnresolved(t *testing.T) {
	network := wagonet.New()
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}

	for _, test := range []struct {
		module     string
		capability wago.Capability
	}{
		{module: wagonet.TCPModule, capability: wagonet.CapTCP},
		{module: wagonet.DNSModule, capability: wagonet.CapDNS},
	} {
		module, err := runtime.Compile(namespaceImportModule(test.module))
		if err == nil {
			var instance *wago.Instance
			instance, err = runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{test.capability}}))
			if instance != nil {
				_ = instance.Close()
			}
		}
		if err == nil {
			t.Fatalf("unregistered %s import unexpectedly resolved", test.module)
		}
	}
}

type exactHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h exactHost) Memory() []byte           { return h.memory }
func (h exactHost) Instance() *wago.Instance { return h.instance }

func namespaceImportModule(module string) []byte {
	entry := append(append(wasmtest.Name(module), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	return wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(entry)),
	)
}
