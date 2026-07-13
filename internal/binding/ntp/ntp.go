// Package ntp owns the checked NTP guest import table and host functions.
package ntp

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	ntpabi "github.com/wago-org/net/internal/abi/ntp"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	ntpinstance "github.com/wago-org/net/internal/instance/ntp"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	// Module is the NTP WebAssembly import module.
	Module = "wago_net_ntp"
	// Capability gates the complete checked NTP surface.
	Capability wago.Capability = "net.ntp"
)

// Descriptor returns the opaque NTP module installed by the public facade.
func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleNTP, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked bounded NTP synchronizations with explicit host clock authority"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

// Bindings returns the complete checked NTP operation table.
func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(module wago.HostModule, params, results []uint64) {
			NamespaceDefault(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured NTP namespace"},
		{Name: "sync", Func: func(module wago.HostModule, params, results []uint64) { Sync(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one checked bounded two-exchange NTP synchronization"},
		{Name: "result", Func: func(module wago.HostModule, params, results []uint64) { Result(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy one completed NTP sample without blocking or adjusting the system clock"},
		{Name: "cancel", Func: func(module wago.HostModule, params, results []uint64) { Cancel(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished NTP synchronization"},
		{Name: "close", Func: func(module wago.HostModule, params, results []uint64) { Close(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact live NTP synchronization handle"},
		{Name: "poll", Func: func(module wago.HostModule, params, results []uint64) { Poll(host, module, params, results) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded NTP readiness and service pass"},
	}
}

func NamespaceDefault(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out := uint32(params[0])
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

func Sync(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out := uint32(params[1])
	if !ntpabi.CheckSyncV1(memory, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := ntpinstance.Sync(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		if handle != 0 {
			_ = state.CloseHandle(handle, resource.KindNTPSync)
		}
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindNTPSync)
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
	out := uint32(params[1])
	if !ntpabi.CheckResultV1(memory, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	sample, next, err := ntpinstance.Result(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if next == ntpns.NextWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if next != ntpns.NextReady || !ntpabi.EncodeSampleV1(memory, out, sample) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Cancel(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(ntpinstance.Cancel(state, resource.Handle(params[0]))))
}

func Poll(host plugin.Host, module wago.HostModule, params, results []uint64) {
	guest.Poll(host, module, params, results)
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
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindNTPSync)))
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
