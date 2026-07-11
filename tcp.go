package net

import (
	"github.com/wago-org/net/internal/abi"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

// tcpBindings is deliberately unregistered until every TCP operation has a
// checked host binding. Keeping the functions in one binding table lets tests
// harden the TinyGo-compatible slot shapes before the capability is advertised.
func (e *Extension) tcpBindings() []binding {
	return []binding{
		{
			name:       "namespace_default",
			fn:         e.tcpNamespaceDefault,
			params:     []wago.ValType{wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "discover the calling instance's configured TCP namespace",
		},
		{
			name:       "listen",
			fn:         e.tcpListen,
			params:     []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "create one checked nonblocking TCP listener",
		},
		{
			name:       "connect",
			fn:         e.tcpConnect,
			params:     []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "start one checked nonblocking TCP connection",
		},
		{
			name:       "finish_connect",
			fn:         e.tcpFinishConnect,
			params:     []wago.ValType{wago.ValI64},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "perform one nonblocking TCP connection-completion check",
		},
		{
			name:       "accept",
			fn:         e.tcpAccept,
			params:     []wago.ValType{wago.ValI64, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "accept one fully established TCP stream without blocking",
		},
		{
			name:       "read",
			fn:         e.tcpRead,
			params:     []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "perform one checked partial nonblocking TCP read",
		},
		{
			name:       "write",
			fn:         e.tcpWrite,
			params:     []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "perform one checked partial nonblocking TCP write",
		},
		{
			name:       "shutdown_write",
			fn:         e.tcpShutdownWrite,
			params:     []wago.ValType{wago.ValI64},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "initiate a nonblocking TCP write-half close",
		},
		{
			name:       "close_listener",
			fn:         e.tcpCloseListener,
			params:     []wago.ValType{wago.ValI64},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "close one exact live TCP listener handle",
		},
		{
			name:       "close_stream",
			fn:         e.tcpCloseStream,
			params:     []wago.ValType{wago.ValI64},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "close one exact live TCP stream handle",
		},
		{
			name:       "poll",
			fn:         e.tcpPoll,
			params:     []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32},
			results:    []wago.ValType{wago.ValI32},
			capability: CapTCP,
			docs:       "perform one quota-accounted bounded TCP readiness and namespace-service pass",
		},
	}
}

func (e *Extension) tcpNamespaceDefault(module wago.HostModule, params, results []uint64) {
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

func (e *Extension) tcpListen(module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	endpointPtr, out := uint32(params[1]), uint32(params[2])
	if !abi.CheckTCPListenV1(memory, endpointPtr, out) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	local, ok := abi.DecodeEndpointV1(memory, endpointPtr)
	if !ok {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	handle, progress, err := state.ListenTCP(resource.Handle(params[0]), local)
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
		_ = state.CloseHandle(handle, resource.KindTCPListener)
		setStatus(results, StatusOther)
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) tcpConnect(module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	endpointPtr, out := uint32(params[1]), uint32(params[2])
	if !abi.CheckTCPCreateV1(memory, endpointPtr, out) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	remote, ok := abi.DecodeEndpointV1(memory, endpointPtr)
	if !ok {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	handle, progress, err := state.ConnectTCP(resource.Handle(params[0]), remote)
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	status = statusFromProgress(progress)
	if status != StatusOK && status != StatusInProgress {
		_ = state.CloseHandle(handle, resource.KindTCPStream)
		setStatus(results, StatusOther)
		return
	}
	local, actualRemote, err := state.TCPStreamEndpoints(handle)
	if err != nil || !abi.EncodeTCPStreamV1(memory, out, handle, local, actualRemote) {
		_ = state.CloseHandle(handle, resource.KindTCPStream)
		if err != nil {
			setStatus(results, statusFromError(err))
		} else {
			setStatus(results, StatusOther)
		}
		return
	}
	setStatus(results, status)
}

func (e *Extension) tcpFinishConnect(module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	progress, err := state.FinishTCPConnect(resource.Handle(params[0]))
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	setStatus(results, statusFromProgress(progress))
}

func (e *Extension) tcpAccept(module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	out := uint32(params[1])
	if !abi.CheckRanges(memory, false, abi.Range{Ptr: out, Length: abi.TCPStreamV1Size}) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	handle, progress, err := state.AcceptTCP(resource.Handle(params[0]))
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	status = statusFromProgress(progress)
	if status == StatusAgain {
		setStatus(results, status)
		return
	}
	if status != StatusOK {
		if handle != 0 {
			_ = state.CloseHandle(handle, resource.KindTCPStream)
		}
		setStatus(results, StatusOther)
		return
	}
	local, remote, err := state.TCPStreamEndpoints(handle)
	if err != nil || !abi.EncodeTCPStreamV1(memory, out, handle, local, remote) {
		_ = state.CloseHandle(handle, resource.KindTCPStream)
		if err != nil {
			setStatus(results, statusFromError(err))
		} else {
			setStatus(results, StatusOther)
		}
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) tcpRead(module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	payloadPtr, payloadLength, resultPtr := uint32(params[1]), uint32(params[2]), uint32(params[3])
	if !abi.CheckTCPIOV1(memory, payloadPtr, payloadLength, resultPtr) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	payload, _ := abi.Slice(memory, payloadPtr, payloadLength)
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	result, err := state.ReadTCP(resource.Handle(params[0]), payload)
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	status = statusFromIOResult(result, len(payload))
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	if !abi.EncodeTCPIOResultV1(memory, resultPtr, result, len(payload)) {
		setStatus(results, StatusIO)
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) tcpWrite(module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	memory := moduleMemory(module)
	payloadPtr, payloadLength, resultPtr := uint32(params[1]), uint32(params[2]), uint32(params[3])
	if !abi.CheckTCPIOV1(memory, payloadPtr, payloadLength, resultPtr) {
		setStatus(results, StatusInvalidArgument)
		return
	}
	payload, _ := abi.Slice(memory, payloadPtr, payloadLength)
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	result, err := state.WriteTCP(resource.Handle(params[0]), payload)
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	status = statusFromIOResult(result, len(payload))
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	if !abi.EncodeTCPIOResultV1(memory, resultPtr, result, len(payload)) {
		setStatus(results, StatusIO)
		return
	}
	setStatus(results, StatusOK)
}

func (e *Extension) tcpShutdownWrite(module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	progress, err := state.ShutdownTCPWrite(resource.Handle(params[0]))
	if err != nil {
		setStatus(results, statusFromError(err))
		return
	}
	setStatus(results, statusFromProgress(progress))
}

func (e *Extension) tcpCloseListener(module wago.HostModule, params, results []uint64) {
	e.tcpClose(module, params, results, resource.KindTCPListener)
}

func (e *Extension) tcpCloseStream(module wago.HostModule, params, results []uint64) {
	e.tcpClose(module, params, results, resource.KindTCPStream)
}

func (e *Extension) tcpClose(module wago.HostModule, params, results []uint64, kind resource.Kind) {
	if len(params) != 1 || len(results) != 1 {
		setStatus(results, StatusInvalidArgument)
		return
	}
	state, status := e.udpState(module)
	if status != StatusOK {
		setStatus(results, status)
		return
	}
	setStatus(results, statusFromError(state.CloseHandle(resource.Handle(params[0]), kind)))
}

func (e *Extension) tcpPoll(module wago.HostModule, params, results []uint64) {
	e.poll(module, params, results)
}
