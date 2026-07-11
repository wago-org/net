package net

import (
	"github.com/wago-org/net/internal/abi"
	"github.com/wago-org/net/internal/instance"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

func (e *Extension) udpBindings() []binding {
	return []binding{
		{
			name:       "namespace_default",
			fn:         e.udpNamespaceDefault,
			params:     []wago.ValType{wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapUDP,
			docs:       "discover the calling instance's configured networking namespace",
		},
		{
			name:       "bind",
			fn:         e.udpBind,
			params:     []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapUDP,
			docs:       "bind a nonblocking UDP socket to a checked local endpoint",
		},
		{
			name:       "send",
			fn:         e.udpSend,
			params:     []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapUDP,
			docs:       "try to enqueue one complete UDP datagram without blocking",
		},
		{
			name:       "receive",
			fn:         e.udpReceive,
			params:     []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapUDP,
			docs:       "try to receive one UDP datagram with explicit truncation metadata",
		},
		{
			name:       "close",
			fn:         e.udpClose,
			params:     []wago.ValType{wago.ValI64},
			results:    []wago.ValType{wago.ValI32},
			capability: CapUDP,
			docs:       "close one exact live UDP socket handle",
		},
	}
}

func (e *Extension) udpNamespaceDefault(module wago.HostModule, params, results []uint64) {
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

func (e *Extension) udpBind(module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	local, ok := abi.DecodeEndpointV1(memory, uint32(params[1]))
	out := uint32(params[2])
	if !ok || !abi.CheckRanges(memory, false, abi.Range{Ptr: out, Length: abi.HandleV1Size}) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	handle, progress, err := state.BindUDP(resource.Handle(params[0]), local)
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	status = statusFromProgress(progress)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	if !abi.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindUDPSocket)
		setStatus(results, StatusOther)
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) udpSend(module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	payload, ok := abi.Slice(memory, uint32(params[1]), uint32(params[2]))
	if !ok {
		setStatus(results, StatusInvalidArgument)
		return
	}
	remote, ok := abi.DecodeEndpointV1(memory, uint32(params[3]))
	if !ok {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	progress, err := state.SendUDP(resource.Handle(params[0]), payload, remote)
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	setStatus(results, statusFromProgress(progress))
}

func (e *Extension) udpReceive(module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	payloadPtr, payloadLength := uint32(params[1]), uint32(params[2])
	resultPtr := uint32(params[3])
	if !abi.CheckRanges(memory, true,
		abi.Range{Ptr: payloadPtr, Length: payloadLength},
		abi.Range{Ptr: resultPtr, Length: abi.UDPReceiveResultV1Size},
	) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	payload, _ := abi.Slice(memory, payloadPtr, payloadLength)
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	result, err := state.ReceiveUDP(resource.Handle(params[0]), payload)
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	if !result.Ready {
		setStatus(results, StatusAgain)
		return
	}
	if !abi.EncodeUDPReceiveResultV1(memory, resultPtr, result, len(payload)) {
		setStatus(results, StatusIO)
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) udpClose(module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	setStatus(results, statusFromError(state.CloseHandle(resource.Handle(params[0]), resource.KindUDPSocket)))
}

func (e *Extension) udpState(module wago.HostModule) (*instance.State, Status) {
	if e == nil || module == nil {
		return nil, StatusInvalidState
	}
	manager := e.instanceManager()
	if manager == nil {
		return nil, StatusInvalidState
	}
	state, ok := manager.FromHost(module)
	if !ok || state == nil {
		return nil, StatusInvalidState
	}
	return state, StatusOK
}

func moduleMemory(module wago.HostModule) []byte {
	if module == nil {
		return nil
	}
	return module.Memory()
}

func setStatus(results []uint64, status Status) {
	if len(results) != 0 {
		results[0] = wago.I32(int32(status))
	}
}
