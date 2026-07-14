// Package ipv6 owns the checked configured IPv6 guest import table.
package ipv6

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	ipv6abi "github.com/wago-org/net/internal/abi/ipv6"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	ipv6instance "github.com/wago-org/net/internal/instance/ipv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	Module                     = "wago_net_ipv6"
	Capability wago.Capability = "net.ipv6"
)

func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleIPv6, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("inspect and service one bounded configured IPv6 namespace"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(m wago.HostModule, p, r []uint64) { NamespaceDefault(host, m, p, r) }, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured namespace"},
		{Name: "configuration", Func: func(m wago.HostModule, p, r []uint64) { Configuration(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy the immutable configured IPv6 identity and supported transport-family flags"},
		{Name: "poll", Func: func(m wago.HostModule, p, r []uint64) { guest.Poll(host, m, p, r) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded IPv6 namespace service pass"},
	}
}

func NamespaceDefault(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory, out := guest.Memory(module), uint32(params[0])
	if !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: abicore.HandleV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle := state.NamespaceHandle()
	if handle == 0 {
		guest.SetStatus(results, guest.StatusNotSupported)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Configuration(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory, out := guest.Memory(module), uint32(params[1])
	if !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: ipv6abi.ConfigurationV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	configuration, err := ipv6instance.Configuration(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if !ipv6abi.EncodeConfigurationV1(memory, out, configuration) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
