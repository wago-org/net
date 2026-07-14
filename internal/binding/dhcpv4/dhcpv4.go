// Package dhcpv4 owns the checked DHCPv4 guest import table.
package dhcpv4

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	dhcpabi "github.com/wago-org/net/internal/abi/dhcpv4"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	dhcpinstance "github.com/wago-org/net/internal/instance/dhcpv4"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	Module                     = "wago_net_dhcpv4"
	Capability wago.Capability = "net.dhcpv4"
)

func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleDHCPv4, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use bounded DHCPv4 client leases and explicitly configured finite server service"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(m wago.HostModule, p, r []uint64) { NamespaceDefault(host, m, p, r) }, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured DHCPv4 namespace"},
		{Name: "acquire", Func: func(m wago.HostModule, p, r []uint64) { Acquire(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one bounded immediate DHCPv4 DORA transaction"},
		{Name: "result", Func: func(m wago.HostModule, p, r []uint64) { Result(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy one accepted finite DHCPv4 lease"},
		{Name: "cancel", Func: func(m wago.HostModule, p, r []uint64) { Cancel(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished DHCPv4 transaction"},
		{Name: "release", Func: func(m wago.HostModule, p, r []uint64) { Release(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "locally release and roll back one applied DHCPv4 identity"},
		{Name: "close", Func: func(m wago.HostModule, p, r []uint64) { Close(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact DHCPv4 lease resource"},
		{Name: "poll", Func: func(m wago.HostModule, p, r []uint64) { guest.Poll(host, m, p, r) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded DHCPv4 readiness and service pass"},
	}
}

func NamespaceDefault(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out, ok := abicore.NarrowUint32(params[0])
	if !ok || !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: abicore.HandleV1Size}) {
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

func Acquire(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	requestPtr, requestOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !requestOK || !outOK || !dhcpabi.CheckRequestV1(memory, requestPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := dhcpabi.DecodeRequestV1(memory, requestPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := dhcpinstance.Acquire(state, resource.Handle(params[0]), request)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		_ = state.CloseHandle(handle, resource.KindDHCPv4Lease)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindDHCPv4Lease)
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
	memory := guest.Memory(module)
	out, ok := abicore.NarrowUint32(params[1])
	if !ok || !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: dhcpabi.LeaseV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	lease, result, err := dhcpinstance.Result(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if result == dhcpns.ResultWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if result != dhcpns.ResultReady || !dhcpabi.EncodeLeaseV1(memory, out, lease) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Cancel(host plugin.Host, module wago.HostModule, params, results []uint64) {
	withHandle(host, module, params, results, dhcpinstance.Cancel)
}
func Release(host plugin.Host, module wago.HostModule, params, results []uint64) {
	withHandle(host, module, params, results, dhcpinstance.Release)
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
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindDHCPv4Lease)))
}

func withHandle(host plugin.Host, module wago.HostModule, params, results []uint64, operation func(*instance.State, resource.Handle) error) {
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
