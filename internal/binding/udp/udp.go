// Package udp owns the checked UDP guest import table and host functions.
package udp

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	udpabi "github.com/wago-org/net/internal/abi/udp"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	udpinstance "github.com/wago-org/net/internal/instance/udp"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	// Module is the UDP WebAssembly import module.
	Module = "wago_net_udp"
	// Capability gates the complete checked UDP surface.
	Capability wago.Capability = "net.udp"
)

// Descriptor returns the opaque UDP module installed by the public udp facade
// and the bounded aggregate compatibility path.
func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleUDP, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked nonblocking UDP networking for the exact calling instance"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

// Bindings returns the complete checked UDP operation table.
func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(module wago.HostModule, params, results []uint64) {
			namespaceDefault(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's configured networking namespace"},
		{Name: "bind", Func: func(module wago.HostModule, params, results []uint64) { bind(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "bind a nonblocking UDP socket to a checked local endpoint"},
		{Name: "send", Func: func(module wago.HostModule, params, results []uint64) { send(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "try to enqueue one complete UDP datagram without blocking"},
		{Name: "receive", Func: func(module wago.HostModule, params, results []uint64) { receive(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "try to receive one UDP datagram with explicit truncation metadata"},
		{Name: "close", Func: func(module wago.HostModule, params, results []uint64) { closeHandle(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact live UDP socket handle"},
		{Name: "poll", Func: func(module wago.HostModule, params, results []uint64) { guest.Poll(host, module, params, results) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded UDP readiness and namespace-service pass"},
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

func bind(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	endpointPtr, endpointOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !endpointOK || !outOK || !udpabi.CheckBindV1(memory, endpointPtr, out) {
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
	handle, progress, err := udpinstance.Bind(state, resource.Handle(params[0]), local)
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
		_ = state.CloseHandle(handle, resource.KindUDPSocket)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func send(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	payloadPtr, ptrOK := abicore.NarrowUint32(params[1])
	payloadLength, lengthOK := abicore.NarrowUint32(params[2])
	remotePtr, remoteOK := abicore.NarrowUint32(params[3])
	if !ptrOK || !lengthOK || !remoteOK {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	payload, ok := abicore.Slice(memory, payloadPtr, payloadLength)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	remote, ok := abicore.DecodeEndpointV1(memory, remotePtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	progress, err := udpinstance.Send(state, resource.Handle(params[0]), payload, remote)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	guest.SetStatus(results, guest.FromProgress(progress))
}

func receive(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	payloadPtr, ptrOK := abicore.NarrowUint32(params[1])
	payloadLength, lengthOK := abicore.NarrowUint32(params[2])
	resultPtr, resultOK := abicore.NarrowUint32(params[3])
	if !ptrOK || !lengthOK || !resultOK || !abicore.CheckRanges(memory, true,
		abicore.Range{Ptr: payloadPtr, Length: payloadLength},
		abicore.Range{Ptr: resultPtr, Length: udpabi.ReceiveResultV1Size},
	) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	payload, _ := abicore.Slice(memory, payloadPtr, payloadLength)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	result, err := udpinstance.Receive(state, resource.Handle(params[0]), payload)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if !result.Ready {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if !udpabi.EncodeReceiveResultV1(memory, resultPtr, result, len(payload)) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func closeHandle(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindUDPSocket)))
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
