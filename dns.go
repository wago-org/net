package net

import (
	"github.com/wago-org/net/internal/abi"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

// dnsBindings is the complete checked DNS table, kept deliberately unregistered
// until registered end-to-end integration and inspection signoff are complete.
func (e *Extension) dnsBindings() []binding {
	return []binding{
		{
			name: "namespace_default", fn: e.dnsNamespaceDefault,
			params: []wago.ValType{wago.ValI32}, results: []wago.ValType{wago.ValI32},
			capability: CapDNS, docs: "discover the calling instance's configured DNS namespace",
		},
		{
			name: "resolve", fn: e.dnsResolve,
			params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, results: []wago.ValType{wago.ValI32},
			capability: CapDNS, docs: "start one checked bounded DNS query",
		},
		{
			name: "next", fn: e.dnsNext,
			params: []wago.ValType{wago.ValI64, wago.ValI32}, results: []wago.ValType{wago.ValI32},
			capability: CapDNS, docs: "copy the next bounded DNS record without blocking",
		},
		{
			name: "cancel", fn: e.dnsCancel,
			params: []wago.ValType{wago.ValI64}, results: []wago.ValType{wago.ValI32},
			capability: CapDNS, docs: "cancel one unfinished DNS query",
		},
		{
			name: "close", fn: e.dnsClose,
			params: []wago.ValType{wago.ValI64}, results: []wago.ValType{wago.ValI32},
			capability: CapDNS, docs: "close one exact live DNS query handle",
		},
		{
			name: "poll", fn: e.dnsPoll,
			params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, results: []wago.ValType{wago.ValI32},
			capability: CapDNS, docs: "perform one quota-accounted bounded DNS readiness and service pass",
		},
	}
}

func (e *Extension) dnsNamespaceDefault(module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	out := uint32(params[0])
	if !abi.CheckRanges(memory, false, abi.Range{Ptr: out, Length: abi.HandleV1Size}) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	handle := state.NamespaceHandle()
	if handle == 0 {
		setStatus(results, StatusNotSupported)
		return
	}
	if !abi.EncodeHandleV1(memory, out, handle) {
		setStatus(results, StatusOther)
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) dnsResolve(module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	queryPtr, out := uint32(params[1]), uint32(params[2])
	if !abi.CheckDNSResolveV1(memory, queryPtr, out) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	request, ok := abi.DecodeDNSQueryV1(memory, queryPtr)
	if !ok {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	handle, progress, err := state.ResolveDNS(resource.Handle(params[0]), request)
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	status = statusFromProgress(progress)
	if status != StatusOK && status != StatusInProgress {
		if handle != 0 {
			_ = state.CloseHandle(handle, resource.KindDNSQuery)
		}
		setStatus(results, StatusOther)
		return
	}
	if !abi.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindDNSQuery)
		setStatus(results, StatusOther)
		return
	}
	setStatus(results, status)
}

func (e *Extension) dnsNext(module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	out := uint32(params[1])
	if !abi.CheckRanges(memory, false, abi.Range{Ptr: out, Length: abi.DNSRecordV1Size}) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	record, next, err := state.NextDNS(resource.Handle(params[0]))
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	status = statusFromDNSNext(next)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	if !abi.EncodeDNSRecordV1(memory, out, record) {
		setStatus(results, StatusIO)
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) dnsCancel(module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	setStatus(results, statusFromError(state.CancelDNS(resource.Handle(params[0]))))
}

func (e *Extension) dnsClose(module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	setStatus(results, statusFromError(state.CloseHandle(resource.Handle(params[0]), resource.KindDNSQuery)))
}

func (e *Extension) dnsPoll(module wago.HostModule, params, results []uint64) {
	e.poll(module, params, results)
}
