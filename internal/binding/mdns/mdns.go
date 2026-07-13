// Package mdns owns the checked multicast DNS guest import table.
package mdns

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	mdnsabi "github.com/wago-org/net/internal/abi/mdns"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	mdnsinstance "github.com/wago-org/net/internal/instance/mdns"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	Module                     = "wago_net_mdns"
	Capability wago.Capability = "net.mdns"
)

func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleMDNS, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked bounded multicast DNS queries, configured responses, and announcements"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(m wago.HostModule, p, r []uint64) { NamespaceDefault(host, m, p, r) }, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured mDNS namespace"},
		{Name: "query", Func: func(m wago.HostModule, p, r []uint64) { Query(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one bounded multicast DNS query"},
		{Name: "next", Func: func(m wago.HostModule, p, r []uint64) { Next(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy the next bounded multicast DNS record"},
		{Name: "cancel_query", Func: func(m wago.HostModule, p, r []uint64) { CancelQuery(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished multicast DNS query"},
		{Name: "close_query", Func: func(m wago.HostModule, p, r []uint64) { CloseQuery(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact multicast DNS query"},
		{Name: "announce", Func: func(m wago.HostModule, p, r []uint64) { Announce(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one finite announcement for a configured service"},
		{Name: "finish_announcement", Func: func(m wago.HostModule, p, r []uint64) { FinishAnnouncement(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "check one announcement without blocking"},
		{Name: "cancel_announcement", Func: func(m wago.HostModule, p, r []uint64) { CancelAnnouncement(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished announcement"},
		{Name: "close_announcement", Func: func(m wago.HostModule, p, r []uint64) { CloseAnnouncement(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact announcement"},
		{Name: "poll", Func: func(m wago.HostModule, p, r []uint64) { guest.Poll(host, m, p, r) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded mDNS readiness and service pass"},
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

func Query(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	requestPtr, out := uint32(params[1]), uint32(params[2])
	if !mdnsabi.CheckQueryV1(memory, requestPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := mdnsabi.DecodeQueryV1(memory, requestPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := mdnsinstance.Query(state, resource.Handle(params[0]), request)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		_ = state.CloseHandle(handle, resource.KindMDNSQuery)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindMDNSQuery)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, status)
}

func Next(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory, out := guest.Memory(module), uint32(params[1])
	if !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: mdnsabi.RecordV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	record, next, err := mdnsinstance.Next(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = statusFromNext(next)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	if !mdnsabi.EncodeRecordV1(memory, out, record) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Announce(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	requestPtr, out := uint32(params[1]), uint32(params[2])
	if !mdnsabi.CheckAnnouncementV1(memory, requestPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	service, ok := mdnsabi.DecodeAnnouncementV1(memory, requestPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := mdnsinstance.Announce(state, resource.Handle(params[0]), service)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		_ = state.CloseHandle(handle, resource.KindMDNSAnnouncement)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindMDNSAnnouncement)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, status)
}

func FinishAnnouncement(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	next, err := mdnsinstance.FinishAnnouncement(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if next == mdnsns.NextReady {
		guest.SetStatus(results, guest.StatusOK)
	} else if next == mdnsns.NextWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
	} else {
		guest.SetStatus(results, guest.StatusOther)
	}
}

func CancelQuery(host plugin.Host, module wago.HostModule, params, results []uint64) {
	withHandle(host, module, params, results, mdnsinstance.CancelQuery)
}

func CancelAnnouncement(host plugin.Host, module wago.HostModule, params, results []uint64) {
	withHandle(host, module, params, results, mdnsinstance.CancelAnnouncement)
}

func CloseQuery(host plugin.Host, module wago.HostModule, params, results []uint64) {
	closeHandle(host, module, params, results, resource.KindMDNSQuery)
}

func CloseAnnouncement(host plugin.Host, module wago.HostModule, params, results []uint64) {
	closeHandle(host, module, params, results, resource.KindMDNSAnnouncement)
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

func closeHandle(host plugin.Host, module wago.HostModule, params, results []uint64, kind resource.Kind) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), kind)))
}

func statusFromNext(next mdnsns.Next) guest.Status {
	switch next {
	case mdnsns.NextReady:
		return guest.StatusOK
	case mdnsns.NextWouldBlock:
		return guest.StatusAgain
	case mdnsns.NextEOF:
		return guest.StatusEOF
	default:
		return guest.StatusOther
	}
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
