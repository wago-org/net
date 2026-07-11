package register_test

import (
	"context"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	_ "github.com/wago-org/net/dns/register"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestDNSFactoryHasExactRuntimeSurface(t *testing.T) {
	extension, ok := wago.NewExtension("net-dns")
	if !ok {
		t.Fatal("DNS-only extension was not registered")
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use: %v", err)
	}
	wantCapabilities := []wago.Capability{wagonet.CapDNS, wagonet.CapInfo}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("capabilities = %v, want %v", got, wantCapabilities)
	}
	assertImportCounts(t, runtime, map[string]int{wagonet.Module: 1, wagonet.DNSModule: 6})
	assertUnresolved(t, runtime, wagonet.TCPModule, wagonet.CapTCP)
	assertUnresolved(t, runtime, wagonet.UDPModule, wagonet.CapUDP)
}

func assertImportCounts(t *testing.T, runtime *wago.Runtime, want map[string]int) {
	t.Helper()
	got := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		got[spec.Module]++
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("import modules = %v, want %v", got, want)
	}
}

func assertUnresolved(t *testing.T, runtime *wago.Runtime, moduleName string, capability wago.Capability) {
	t.Helper()
	module, err := runtime.Compile(namespaceImportModule(moduleName))
	if err == nil {
		var instance *wago.Instance
		instance, err = runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{capability}}))
		if instance != nil {
			_ = instance.Close()
		}
	}
	if err == nil {
		t.Fatalf("unregistered %s import unexpectedly resolved", moduleName)
	}
}

func namespaceImportModule(moduleName string) []byte {
	entry := append(append(wasmtest.Name(moduleName), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	return wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(entry)),
	)
}
