package plugin

import wago "github.com/wago-org/wago"

// HostFunc is the private raw-slot form used inside the networking plugin.
// Public registration adapts it to Wago's callback-scoped HostCall API.
type HostFunc func(wago.HostModule, []uint64, []uint64)

// Binding is one checked guest import contributed by a protocol module.
type Binding struct {
	Name       string
	Func       HostFunc
	Params     []wago.ValType
	Results    []wago.ValType
	Capability wago.Capability
	Docs       string
}

// RegisterBindings installs a complete protocol binding table without exposing
// root-package implementation details to the protocol package.
func RegisterBindings(module *ImportModule, bindings []Binding) {
	for _, binding := range bindings {
		module.Func(binding.Name, binding.Func).
			Params(binding.Params...).
			Results(binding.Results...).
			Capability(binding.Capability).
			Docs(binding.Docs)
	}
}

// ImportModule keeps protocol packages grouped by namespace internally while
// registering through Wago's flat public API.
type ImportModule struct {
	imports *wago.HostImportRegistrar
	name    string
}

func (m *ImportModule) Func(name string, fn HostFunc) *wago.ImportFuncBuilder {
	if m == nil || m.imports == nil {
		return new(wago.ImportFuncBuilder)
	}
	return m.imports.HostFunc(m.name, name, func(caller wago.Caller, call wago.HostCall) {
		fn(caller, call.ParamSlots(), call.ResultSlots())
	})
}
