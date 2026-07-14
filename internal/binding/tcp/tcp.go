// Package tcp owns the checked TCP guest import table and host functions.
package tcp

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	tcpabi "github.com/wago-org/net/internal/abi/tcp"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	tcpinstance "github.com/wago-org/net/internal/instance/tcp"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	// Module is the TCP WebAssembly import module.
	Module = "wago_net_tcp"
	// Capability gates the complete checked TCP surface.
	Capability wago.Capability = "net.tcp"
)

// Descriptor returns the opaque TCP module installed by the public tcp facade
// and the bounded aggregate compatibility path.
func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleTCP, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked nonblocking TCP networking for the exact calling instance"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

// Bindings returns the complete checked TCP operation table.
func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(module wago.HostModule, params, results []uint64) {
			namespaceDefault(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured TCP namespace"},
		{Name: "listen", Func: func(module wago.HostModule, params, results []uint64) { listen(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "create one checked nonblocking TCP listener"},
		{Name: "connect", Func: func(module wago.HostModule, params, results []uint64) { connect(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one checked nonblocking TCP connection"},
		{Name: "finish_connect", Func: func(module wago.HostModule, params, results []uint64) { finishConnect(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one nonblocking TCP connection-completion check"},
		{Name: "accept", Func: func(module wago.HostModule, params, results []uint64) { accept(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "accept one fully established TCP stream without blocking"},
		{Name: "read", Func: func(module wago.HostModule, params, results []uint64) { read(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one checked partial nonblocking TCP read"},
		{Name: "write", Func: func(module wago.HostModule, params, results []uint64) { write(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one checked partial nonblocking TCP write"},
		{Name: "shutdown_write", Func: func(module wago.HostModule, params, results []uint64) { shutdownWrite(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "initiate a nonblocking TCP write-half close"},
		{Name: "close_listener", Func: func(module wago.HostModule, params, results []uint64) {
			closeHandle(host, module, params, results, resource.KindTCPListener)
		}, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact live TCP listener handle"},
		{Name: "close_stream", Func: func(module wago.HostModule, params, results []uint64) {
			closeHandle(host, module, params, results, resource.KindTCPStream)
		}, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact live TCP stream handle"},
		{Name: "poll", Func: func(module wago.HostModule, params, results []uint64) { guest.Poll(host, module, params, results) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded TCP readiness and namespace-service pass"},
	}
}

func namespaceDefault(host plugin.Host, module wago.HostModule, params, results []uint64) {
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

func listen(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	endpointPtr, endpointOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !endpointOK || !outOK || !tcpabi.CheckListenV1(memory, endpointPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	local, ok := abicore.DecodeEndpointV1(memory, endpointPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := tcpinstance.Listen(state, resource.Handle(params[0]), local)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	if !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindTCPListener)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func connect(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	endpointPtr, endpointOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !endpointOK || !outOK || !tcpabi.CheckCreateV1(memory, endpointPtr, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	remote, ok := abicore.DecodeEndpointV1(memory, endpointPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := tcpinstance.Connect(state, resource.Handle(params[0]), remote)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		_ = state.CloseHandle(handle, resource.KindTCPStream)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	local, actualRemote, err := tcpinstance.Endpoints(state, handle)
	if err != nil || !tcpabi.EncodeStreamV1(memory, out, handle, local, actualRemote) {
		_ = state.CloseHandle(handle, resource.KindTCPStream)
		if err != nil {
			guest.SetStatus(results, guest.FromError(err))
		} else {
			guest.SetStatus(results, guest.StatusOther)
		}
		return
	}
	guest.SetStatus(results, status)
}

func finishConnect(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	progress, err := tcpinstance.FinishConnect(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	guest.SetStatus(results, guest.FromProgress(progress))
}

func accept(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out, ok := abicore.NarrowUint32(params[1])
	if !ok || !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: tcpabi.StreamV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := tcpinstance.Accept(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status == guest.StatusAgain {
		guest.SetStatus(results, status)
		return
	}
	if status != guest.StatusOK {
		if handle != 0 {
			_ = state.CloseHandle(handle, resource.KindTCPStream)
		}
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	local, remote, err := tcpinstance.Endpoints(state, handle)
	if err != nil || !tcpabi.EncodeStreamV1(memory, out, handle, local, remote) {
		_ = state.CloseHandle(handle, resource.KindTCPStream)
		if err != nil {
			guest.SetStatus(results, guest.FromError(err))
		} else {
			guest.SetStatus(results, guest.StatusOther)
		}
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func read(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	payloadPtr, payloadOK := abicore.NarrowUint32(params[1])
	payloadLength, lengthOK := abicore.NarrowUint32(params[2])
	resultPtr, resultOK := abicore.NarrowUint32(params[3])
	if !payloadOK || !lengthOK || !resultOK || !tcpabi.CheckIOV1(memory, payloadPtr, payloadLength, resultPtr) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	payload, _ := abicore.Slice(memory, payloadPtr, payloadLength)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	result, err := tcpinstance.Read(state, resource.Handle(params[0]), payload)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromIOResult(result, len(payload))
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	if !tcpabi.EncodeIOResultV1(memory, resultPtr, result, len(payload)) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func write(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	payloadPtr, payloadOK := abicore.NarrowUint32(params[1])
	payloadLength, lengthOK := abicore.NarrowUint32(params[2])
	resultPtr, resultOK := abicore.NarrowUint32(params[3])
	if !payloadOK || !lengthOK || !resultOK || !tcpabi.CheckIOV1(memory, payloadPtr, payloadLength, resultPtr) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	payload, _ := abicore.Slice(memory, payloadPtr, payloadLength)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	result, err := tcpinstance.Write(state, resource.Handle(params[0]), payload)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromIOResult(result, len(payload))
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	if !tcpabi.EncodeIOResultV1(memory, resultPtr, result, len(payload)) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func shutdownWrite(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	progress, err := tcpinstance.ShutdownWrite(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	guest.SetStatus(results, guest.FromProgress(progress))
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

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
