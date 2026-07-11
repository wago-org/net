package plugin

import wago "github.com/wago-org/wago"

// Binding is one checked guest import contributed by a protocol module.
type Binding struct {
	Name       string
	Func       wago.HostFunc
	Params     []wago.ValType
	Results    []wago.ValType
	Capability wago.Capability
	Docs       string
}

// RegisterBindings installs a complete protocol binding table without exposing
// root-package implementation details to the protocol package.
func RegisterBindings(module *wago.ImportModuleBuilder, bindings []Binding) {
	for _, binding := range bindings {
		module.Func(binding.Name, binding.Func).
			Params(binding.Params...).
			Results(binding.Results...).
			Capability(binding.Capability).
			Docs(binding.Docs)
	}
}
