package register_test

import (
	"context"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	_ "github.com/wago-org/net/ipv6/register"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestIPv6FactoryHasExactRuntimeSurface(t *testing.T) {
	extension, ok := wago.NewExtension("net-ipv6")
	if !ok {
		t.Fatal("IPv6-only extension was not registered")
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if got, want := runtime.Capabilities(), []wago.Capability{wagonet.CapInfo, wagonet.CapIPv6}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	gotImports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		gotImports[spec.Module]++
	}
	if want := map[string]int{wagonet.Module: 1, wagonet.IPv6Module: 3}; !reflect.DeepEqual(gotImports, want) {
		t.Fatalf("imports = %v, want %v", gotImports, want)
	}
	module, err := runtime.Compile(namespaceImportModule(wagonet.TCPModule))
	if err == nil {
		instance, instantiateErr := runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{wagonet.CapTCP}}))
		if instance != nil {
			_ = instance.Close()
		}
		err = instantiateErr
	}
	if err == nil {
		t.Fatal("IPv6-only registration unexpectedly exposed TCP imports")
	}
}

func namespaceImportModule(moduleName string) []byte {
	entry := append(append(wasmtest.Name(moduleName), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	return wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(entry)),
	)
}
