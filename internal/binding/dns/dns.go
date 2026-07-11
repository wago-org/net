// Package dns owns the checked DNS guest import table and host functions.
package dns

import (
	"github.com/wago-org/net/internal/abi"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	dnsinstance "github.com/wago-org/net/internal/instance/dns"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	// Module is the DNS WebAssembly import module.
	Module = "wago_net_dns"
	// Capability gates the complete checked DNS surface.
	Capability wago.Capability = "net.dns"
)

// Descriptor returns the opaque DNS module installed by the public dns facade
// and the bounded aggregate compatibility path.
func Descriptor() plugin.Module {
	return plugin.NewModule(plugin.ModuleDNS, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked bounded DNS queries for the exact calling instance"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	})
}

// Bindings returns the complete checked DNS operation table.
func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(module wago.HostModule, params, results []uint64) {
			NamespaceDefault(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured DNS namespace"},
		{Name: "resolve", Func: func(module wago.HostModule, params, results []uint64) {
			Resolve(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one checked bounded DNS query"},
		{Name: "next", Func: func(module wago.HostModule, params, results []uint64) {
			Next(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy the next bounded DNS record without blocking"},
		{Name: "cancel", Func: func(module wago.HostModule, params, results []uint64) {
			Cancel(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished DNS query"},
		{Name: "close", Func: func(module wago.HostModule, params, results []uint64) {
			Close(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact live DNS query handle"},
		{Name: "poll", Func: func(module wago.HostModule, params, results []uint64) {
			Poll(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded DNS readiness and service pass"},
	}
}

// NamespaceDefault implements the checked DNS namespace discovery import.
func NamespaceDefault(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out := uint32(params[0])
	if !abi.CheckRanges(memory, false, abi.Range{Ptr: out, Length: abi.HandleV1Size}) {
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
	if !abi.EncodeHandleV1(memory, out, handle) {
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

// Resolve implements the checked bounded DNS query creation import.
func Resolve(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	queryPtr, out := uint32(params[1]), uint32(params[2])
	if !abi.CheckDNSResolveV1(memory, queryPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := abi.DecodeDNSQueryV1(memory, queryPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := dnsinstance.Resolve(state, resource.Handle(params[0]), request)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		if handle != 0 {
			_ = state.CloseHandle(handle, resource.KindDNSQuery)
		}
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	if !abi.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindDNSQuery)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, status)
}

// Next implements the checked nonblocking DNS record iteration import.
func Next(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out := uint32(params[1])
	if !abi.CheckRanges(memory, false, abi.Range{Ptr: out, Length: abi.DNSRecordV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	record, next, err := dnsinstance.Next(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromDNSNext(next)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	if !abi.EncodeDNSRecordV1(memory, out, record) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

// Cancel implements the checked DNS query cancellation import.
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
	guest.SetStatus(results, guest.FromError(dnsinstance.Cancel(state, resource.Handle(params[0]))))
}

// Poll implements the shared checked bounded readiness import.
func Poll(host plugin.Host, module wago.HostModule, params, results []uint64) {
	guest.Poll(host, module, params, results)
}

// Close implements the kind-checked DNS query close import.
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
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindDNSQuery)))
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
