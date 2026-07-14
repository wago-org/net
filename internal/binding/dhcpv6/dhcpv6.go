// Package dhcpv6 owns the checked DHCPv6 guest import table.
package dhcpv6

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	dhcpabi "github.com/wago-org/net/internal/abi/dhcpv6"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	dhcpinstance "github.com/wago-org/net/internal/instance/dhcpv6"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	Module                     = "wago_net_dhcpv6"
	Capability wago.Capability = "net.dhcpv6"
)

func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleDHCPv6, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use the bounded checked initial DHCPv6 client acquisition subset"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(m wago.HostModule, p, r []uint64) { NamespaceDefault(host, m, p, r) }, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the configured DHCPv6 namespace"},
		{Name: "operations", Func: func(m wago.HostModule, p, r []uint64) { Operations(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy the truthful supported-operation bitset"},
		{Name: "start", Func: func(m wago.HostModule, p, r []uint64) { Start(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start acquire or return NOT_SUPPORTED for named unsupported operations"},
		{Name: "result", Func: func(m wago.HostModule, p, r []uint64) { Result(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "atomically copy one accepted DHCPv6 configuration observation"},
		{Name: "cancel", Func: func(m wago.HostModule, p, r []uint64) { Cancel(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished DHCPv6 acquisition"},
		{Name: "close", Func: func(m wago.HostModule, p, r []uint64) { Close(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact DHCPv6 resource"},
		{Name: "poll", Func: func(m wago.HostModule, p, r []uint64) { guest.Poll(host, m, p, r) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded DHCPv6 readiness/service pass"},
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

func Operations(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory, out := guest.Memory(module), uint32(params[1])
	if !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: dhcpabi.OperationsV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	operations, err := dhcpinstance.Operations(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if !dhcpabi.EncodeOperationsV1(memory, out, operations) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Start(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory, out := guest.Memory(module), uint32(params[2])
	if !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: abicore.HandleV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	operationValue := uint32(params[1])
	if params[1] != uint64(operationValue) || operationValue < uint32(dhcpns.OperationAcquire) || operationValue > uint32(dhcpns.OperationRawPacket) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	operation := dhcpns.Operation(operationValue)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := dhcpinstance.Start(state, resource.Handle(params[0]), operation)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if (status != guest.StatusOK && status != guest.StatusInProgress) || !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindDHCPv6Lease)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, status)
}

func Result(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory, out := guest.Memory(module), uint32(params[1])
	if !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: dhcpabi.ConfigurationV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	configuration, result, err := dhcpinstance.Result(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if result == dhcpns.ResultWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if result != dhcpns.ResultReady || !dhcpabi.EncodeConfigurationV1(memory, out, &configuration) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Cancel(host plugin.Host, module wago.HostModule, params, results []uint64) {
	oneHandle(host, module, params, results, dhcpinstance.Cancel)
}
func Close(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindDHCPv6Lease)))
}
func oneHandle(host plugin.Host, module wago.HostModule, params, results []uint64, operation func(*instance.State, resource.Handle) error) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(operation(state, resource.Handle(params[0]))))
}
func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
