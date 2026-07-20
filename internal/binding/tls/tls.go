// Package tls owns the checked outbound TLS guest import table.
package tls

import (
	"unicode/utf8"

	abicore "github.com/wago-org/net/internal/abi/core"
	tlsabi "github.com/wago-org/net/internal/abi/tls"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	tlsinstance "github.com/wago-org/net/internal/instance/tls"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	Module                             = "wago_net_tls"
	Capability         wago.Capability = "net.tls"
	MaxServerNameBytes uint32          = 253
)

func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleTLS, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked outbound verified TLS client streams for the exact calling instance"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(module wago.HostModule, params, results []uint64) {
			namespaceDefault(host, module, params, results)
		}, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's TLS namespace"},
		{Name: "connect", Func: func(module wago.HostModule, params, results []uint64) { connect(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one host-profiled verified TLS client connection"},
		{Name: "finish_connect", Func: func(module wago.HostModule, params, results []uint64) { finishConnect(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "advance TCP, TLS handshake, verification, and required ALPN"},
		{Name: "read", Func: func(module wago.HostModule, params, results []uint64) { read(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one checked partial decrypted read"},
		{Name: "write", Func: func(module wago.HostModule, params, results []uint64) { write(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one checked partial plaintext write"},
		{Name: "shutdown_write", Func: func(module wago.HostModule, params, results []uint64) { shutdownWrite(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "queue TLS close_notify and reject later plaintext writes"},
		{Name: "connection_info", Func: func(module wago.HostModule, params, results []uint64) { connectionInfo(host, module, params, results) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "return bounded verified TLS connection metadata"},
		{Name: "close", Func: func(module wago.HostModule, params, results []uint64) { closeStream(host, module, params, results) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "abort and close one exact TLS stream without waiting for the peer"},
		{Name: "poll", Func: func(module wago.HostModule, params, results []uint64) { guest.Poll(host, module, params, results) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one bounded TLS readiness and transport-service pass"},
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

func connect(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 6 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	endpointPtr, endpointOK := abicore.NarrowUint32(params[1])
	profileID, profileOK := abicore.NarrowUint32(params[2])
	namePtr, nameOK := abicore.NarrowUint32(params[3])
	nameLength, lengthOK := abicore.NarrowUint32(params[4])
	out, outOK := abicore.NarrowUint32(params[5])
	if !endpointOK || !profileOK || !nameOK || !lengthOK || !outOK || profileID == 0 || nameLength == 0 || nameLength > MaxServerNameBytes || !tlsabi.CheckCreateV1(memory, endpointPtr, namePtr, nameLength, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	remote, ok := abicore.DecodeEndpointV1(memory, endpointPtr)
	nameBytes, nameRangeOK := abicore.Slice(memory, namePtr, nameLength)
	if !ok || !nameRangeOK || !utf8.Valid(nameBytes) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	// String conversion copies guest bytes; no guest slice survives this call.
	serverName := string(nameBytes)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := tlsinstance.Connect(state, resource.Handle(params[0]), remote, profileID, serverName)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK && status != guest.StatusInProgress {
		_ = state.CloseHandle(handle, resource.KindTLSStream)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	local, actualRemote, err := tlsinstance.Endpoints(state, handle)
	if err != nil || !tlsabi.EncodeStreamV1(memory, out, handle, local, actualRemote) {
		_ = state.CloseHandle(handle, resource.KindTLSStream)
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
	progress, err := tlsinstance.FinishConnect(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	guest.SetStatus(results, guest.FromProgress(progress))
}

func read(host plugin.Host, module wago.HostModule, params, results []uint64) {
	ioCall(host, module, params, results, true)
}
func write(host plugin.Host, module wago.HostModule, params, results []uint64) {
	ioCall(host, module, params, results, false)
}

func ioCall(host plugin.Host, module wago.HostModule, params, results []uint64, reading bool) {
	if len(params) != 4 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	payloadPtr, payloadOK := abicore.NarrowUint32(params[1])
	payloadLength, lengthOK := abicore.NarrowUint32(params[2])
	resultPtr, resultOK := abicore.NarrowUint32(params[3])
	if !payloadOK || !lengthOK || !resultOK || !tlsabi.CheckIOV1(memory, payloadPtr, payloadLength, resultPtr) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	payload, _ := abicore.Slice(memory, payloadPtr, payloadLength)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	var result nscore.IOResult
	var err error
	if reading {
		result, err = tlsinstance.Read(state, resource.Handle(params[0]), payload)
	} else {
		result, err = tlsinstance.Write(state, resource.Handle(params[0]), payload)
	}
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromIOResult(result, len(payload))
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	if !tlsabi.EncodeIOResultV1(memory, resultPtr, result, len(payload)) {
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
	progress, err := tlsinstance.ShutdownWrite(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	guest.SetStatus(results, guest.FromProgress(progress))
}

func connectionInfo(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out, ok := abicore.NarrowUint32(params[1])
	if !ok || !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: tlsabi.ConnectionInfoV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	info, progress, err := tlsinstance.ConnectionInfo(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	if !tlsabi.EncodeConnectionInfoV1(memory, out, info) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func closeStream(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindTLSStream)))
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
