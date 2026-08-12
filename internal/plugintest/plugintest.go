// Package plugintest contains repository-internal vNext plugin test helpers.
package plugintest

import (
	"context"
	"fmt"

	wagonet "github.com/wago-org/net"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/tests/wasmtest"
)

var allModules = []string{
	wagonet.Module, wagonet.UDPModule, wagonet.TCPModule, wagonet.DNSModule,
	wagonet.ICMPv4Module, wagonet.NTPModule, wagonet.MDNSModule,
	wagonet.DHCPv4Module, wagonet.LinkLocal4Module, wagonet.IPv6Module,
	wagonet.ICMPv6Module, wagonet.DHCPv6Module, wagonet.TLSModule,
}

// LoadNetwork loads one already-composed network through the same reviewed
// authority and explicit-provider path used in production.
func LoadNetwork(runtime *wago.Runtime, network *wagonet.Network) error {
	provider := wagonet.Provider(wagonet.ProviderSpec{
		ID: "example.com/wagonet/test", Name: "Networking test composition",
		Description: "Repository-local exact networking composition",
		Modules:     allModules,
		Factory:     func() (*wagonet.Network, error) { return network, nil },
	})
	return runtime.LoadPlugins(context.Background(), Set(provider))
}

// Set selects providers with their exact definition digests and requested grants.
func Set(providers ...wago.PluginProvider) wago.PluginSet {
	set := wago.PluginSet{Providers: providers}
	for _, provider := range providers {
		digest, err := wago.DefinitionDigest(provider.Definition)
		if err != nil {
			panic(err)
		}
		selection := wago.PluginSelection{
			ID: provider.Definition.ID, DefinitionDigest: digest, Direct: true,
			Dependencies: map[string]string{},
		}
		for _, requirement := range provider.Definition.Requires {
			selection.Dependencies[requirement.ID] = requirement.Version
		}
		for _, authority := range provider.Definition.Authorities {
			selection.Grants = append(selection.Grants, wago.AuthorityGrant{Name: authority.Name, Scope: authority.Scope})
		}
		set.Selections = append(set.Selections, selection)
	}
	return set
}

func HasImport(runtime *wago.Runtime, module, name string) bool {
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == module && spec.Name == name {
			return true
		}
	}
	return false
}

// CompileImportHarness compiles one-memory guest that re-exports every host
// function provided in module. Tests exercise the real guest-call path instead
// of reaching into Runtime for callable imports.
func CompileImportHarness(runtime *wago.Runtime, module string) (*wago.Module, error) {
	var specs []wago.ImportSpec
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == module {
			specs = append(specs, spec)
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("plugintest: no imports for module %q", module)
	}
	types := make([][]byte, 0, len(specs))
	imports := make([][]byte, 0, len(specs))
	exports := make([][]byte, 0, len(specs)+1)
	for i, spec := range specs {
		params, err := wasmTypes(spec.Params)
		if err != nil {
			return nil, err
		}
		results, err := wasmTypes(spec.Results)
		if err != nil {
			return nil, err
		}
		types = append(types, wasmtest.FuncType(params, results))
		entry := append(append(wasmtest.Name(spec.Module), wasmtest.Name(spec.Name)...), 0x00)
		entry = append(entry, wasmtest.ULEB(uint32(i))...)
		imports = append(imports, entry)
		export := append(wasmtest.Name(spec.Name), 0x00)
		export = append(export, wasmtest.ULEB(uint32(i))...)
		exports = append(exports, export)
	}
	memoryExport := append(wasmtest.Name("memory"), 0x02, 0x00)
	exports = append(exports, memoryExport)
	source := wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(types...)),
		wasmtest.Section(2, wasmtest.Vec(imports...)),
		wasmtest.Section(5, wasmtest.Vec([]byte{0x00, 0x01})),
		wasmtest.Section(7, wasmtest.Vec(exports...)),
	)
	return runtime.Compile(source)
}

func wasmTypes(types []wago.ValType) ([]wasm.ValType, error) {
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
			return nil, fmt.Errorf("plugintest: unsupported harness value type %v", value)
		}
	}
	return out, nil
}
