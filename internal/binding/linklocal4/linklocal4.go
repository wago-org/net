// Package linklocal4 owns the checked IPv4 link-local guest import table.
package linklocal4

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	linklocalabi "github.com/wago-org/net/internal/abi/linklocal4"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	linklocalinstance "github.com/wago-org/net/internal/instance/linklocal4"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	Module                     = "wago_net_linklocal4"
	Capability wago.Capability = "net.linklocal4"
)

func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleLinkLocal4, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use bounded IPv4 link-local/APIPA claim-and-defend operations"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(m wago.HostModule, p, r []uint64) { NamespaceDefault(host, m, p, r) }, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured IPv4 link-local namespace"},
		{Name: "claim", Func: func(m wago.HostModule, p, r []uint64) { Claim(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one bounded RFC 3927 claim-and-defend operation"},
		{Name: "result", Func: func(m wago.HostModule, p, r []uint64) { Result(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy the current claimed link-local identity"},
		{Name: "cancel", Func: func(m wago.HostModule, p, r []uint64) { Cancel(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished link-local claim"},
		{Name: "release", Func: func(m wago.HostModule, p, r []uint64) { Release(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "release and roll back one claimed link-local identity"},
		{Name: "close", Func: func(m wago.HostModule, p, r []uint64) { Close(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact link-local claim resource"},
		{Name: "poll", Func: func(m wago.HostModule, p, r []uint64) { guest.Poll(host, m, p, r) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded link-local readiness and service pass"},
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

func Claim(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	requestPtr, requestOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !requestOK || !outOK || !linklocalabi.CheckRequestV1(memory, requestPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := linklocalabi.DecodeRequestV1(memory, requestPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := linklocalinstance.Claim(state, resource.Handle(params[0]), request)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		_ = state.CloseHandle(handle, resource.KindLinkLocal4Claim)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindLinkLocal4Claim)
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
	if !ok || !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: linklocalabi.ResultV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	value, resultState, err := linklocalinstance.Result(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if resultState == linklocalns.ResultWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if resultState != linklocalns.ResultReady || !linklocalabi.EncodeResultV1(memory, out, value) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Cancel(host plugin.Host, module wago.HostModule, params, results []uint64) {
	withHandle(host, module, params, results, linklocalinstance.Cancel)
}

func Release(host plugin.Host, module wago.HostModule, params, results []uint64) {
	withHandle(host, module, params, results, linklocalinstance.Release)
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
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindLinkLocal4Claim)))
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
