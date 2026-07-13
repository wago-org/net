// Package icmpv4 owns the checked ICMPv4 guest import table and host functions.
package icmpv4

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	icmpabi "github.com/wago-org/net/internal/abi/icmpv4"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	icmpinstance "github.com/wago-org/net/internal/instance/icmpv4"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	// Module is the ICMPv4 WebAssembly import module.
	Module = "wago_net_icmpv4"
	// Capability gates the complete checked ICMPv4 surface.
	Capability wago.Capability = "net.icmpv4"
)

// Descriptor returns the opaque ICMPv4 module installed by the public facade.
func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleICMPv4, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked bounded ICMPv4 echo exchanges for the exact calling instance"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

// Bindings returns the complete checked ICMPv4 operation table.
func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(module wago.HostModule, params, results []uint64) {
			NamespaceDefault(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured ICMPv4 namespace"},
		{Name: "echo", Func: func(module wago.HostModule, params, results []uint64) { Echo(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one checked bounded ICMPv4 echo exchange"},
		{Name: "result", Func: func(module wago.HostModule, params, results []uint64) { Result(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy one completed ICMPv4 echo reply without blocking"},
		{Name: "cancel", Func: func(module wago.HostModule, params, results []uint64) { Cancel(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished ICMPv4 exchange"},
		{Name: "close", Func: func(module wago.HostModule, params, results []uint64) { Close(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact live ICMPv4 exchange handle"},
		{Name: "poll", Func: func(module wago.HostModule, params, results []uint64) { Poll(host, module, params, results) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded ICMPv4 readiness and service pass"},
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

func Echo(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	requestPtr, out := uint32(params[1]), uint32(params[2])
	if !icmpabi.CheckEchoV1(memory, requestPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := icmpabi.DecodeEchoRequestV1(memory, requestPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := icmpinstance.Echo(state, resource.Handle(params[0]), request)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		if handle != 0 {
			_ = state.CloseHandle(handle, resource.KindICMPv4Echo)
		}
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindICMPv4Echo)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, status)
}

func Result(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	payloadPtr, payloadLen, resultPtr := uint32(params[1]), uint32(params[2]), uint32(params[3])
	if !icmpabi.CheckResultV1(memory, payloadPtr, payloadLen, resultPtr) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	payload, _ := abicore.Slice(memory, payloadPtr, payloadLen)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	result, next, err := icmpinstance.Result(state, resource.Handle(params[0]), payload)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if next == icmpns.NextWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if next != icmpns.NextReady || !icmpabi.EncodeEchoResultV1(memory, resultPtr, result, len(payload)) {
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
	guest.SetStatus(results, guest.FromError(icmpinstance.Cancel(state, resource.Handle(params[0]))))
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
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindICMPv4Echo)))
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
