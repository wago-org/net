package net

import (
	"context"
	"fmt"

	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/tests/wasmtest"
)

var testAuthorityModules = []string{
	Module, UDPModule, TCPModule, DNSModule, ICMPv4Module, NTPModule, MDNSModule,
	DHCPv4Module, LinkLocal4Module, IPv6Module, ICMPv6Module, DHCPv6Module, TLSModule,
}

func loadNetwork(runtime *wago.Runtime, network *Network) error {
	provider := Provider(ProviderSpec{
		ID: "example.com/wagonet/test", Name: "Networking test composition",
		Description: "Repository-local exact networking composition", Modules: testAuthorityModules,
		Factory: func() (*Network, error) { return network, nil },
	})
	digest, err := wago.DefinitionDigest(provider.Definition)
	if err != nil {
		return err
	}
	selection := wago.PluginSelection{
		ID: provider.Definition.ID, DefinitionDigest: digest, Direct: true,
		Dependencies: map[string]string{},
	}
	for _, authority := range provider.Definition.Authorities {
		selection.Grants = append(selection.Grants, wago.AuthorityGrant{Name: authority.Name, Scope: authority.Scope})
	}
	return runtime.LoadPlugins(context.Background(), wago.PluginSet{Providers: []wago.PluginProvider{provider}, Selections: []wago.PluginSelection{selection}})
}

func compileImportHarness(runtime *wago.Runtime, module string) (*wago.Module, error) {
	var specs []wago.ImportSpec
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == module {
			specs = append(specs, spec)
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no imports for module %q", module)
	}
	types, imports, exports := make([][]byte, 0, len(specs)), make([][]byte, 0, len(specs)), make([][]byte, 0, len(specs)+1)
	for i, spec := range specs {
		params, err := testWasmTypes(spec.Params)
		if err != nil {
			return nil, err
		}
		results, err := testWasmTypes(spec.Results)
		if err != nil {
			return nil, err
		}
		types = append(types, wasmtest.FuncType(params, results))
		entry := append(append(wasmtest.Name(spec.Module), wasmtest.Name(spec.Name)...), 0x00)
		entry = append(entry, wasmtest.ULEB(uint32(i))...)
		imports = append(imports, entry)
		export := append(wasmtest.Name(spec.Name), 0x00)
		exports = append(exports, append(export, wasmtest.ULEB(uint32(i))...))
	}
	exports = append(exports, append(wasmtest.Name("memory"), 0x02, 0x00))
	return runtime.Compile(wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(types...)), wasmtest.Section(2, wasmtest.Vec(imports...)),
		wasmtest.Section(5, wasmtest.Vec([]byte{0x00, 0x01})), wasmtest.Section(7, wasmtest.Vec(exports...)),
	))
}

func testWasmTypes(types []wago.ValType) ([]wasm.ValType, error) {
	out := make([]wasm.ValType, len(types))
	for i, value := range types {
		switch value {
		case wago.ValI32:
			out[i] = wasm.I32
		case wago.ValI64:
			out[i] = wasm.I64
		case wago.ValF32:
			out[i] = wasm.F32
		case wago.ValF64:
			out[i] = wasm.F64
		default:
			return nil, fmt.Errorf("unsupported test value type %v", value)
		}
	}
	return out, nil
}

func emptyModule(t interface {
	Helper()
	Fatal(...any)
}, runtime *wago.Runtime) *wago.Module {
	t.Helper()
	module, err := runtime.Compile(wasmtest.Module())
	if err != nil {
		t.Fatal(err)
	}
	return module
}
