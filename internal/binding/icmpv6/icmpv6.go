// Package icmpv6 owns the checked ICMPv6/NDP guest import table.
package icmpv6

import (
	abicore "github.com/wago-org/net/internal/abi/core"
	icmpabi "github.com/wago-org/net/internal/abi/icmpv6"
	"github.com/wago-org/net/internal/guest"
	instance "github.com/wago-org/net/internal/instance/core"
	icmpinstance "github.com/wago-org/net/internal/instance/icmpv6"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

const (
	Module                     = "wago_net_icmpv6"
	Capability wago.Capability = "net.icmpv6"
)

func Descriptor(backend ...plugin.Backend) plugin.Module {
	return plugin.NewModule(plugin.ModuleICMPv6, func(registry *wago.Registry, host plugin.Host) {
		registry.Capability(Capability, wago.CapabilityDocs("use checked bounded ICMPv6 echo and Neighbor Discovery for the exact calling instance"))
		plugin.RegisterBindings(registry.ImportModule(Module), Bindings(host))
	}, backend...)
}

func Bindings(host plugin.Host) []plugin.Binding {
	return []plugin.Binding{
		{Name: "namespace_default", Func: func(m wago.HostModule, p, r []uint64) { NamespaceDefault(host, m, p, r) }, Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "discover the calling instance's ICMPv6 namespace"},
		{Name: "operations", Func: func(m wago.HostModule, p, r []uint64) { Operations(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy the truthful finite ICMPv6/NDP supported-operation bitset"},
		{Name: "echo", Func: func(m wago.HostModule, p, r []uint64) { Echo(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one copied bounded ICMPv6 echo"},
		{Name: "echo_result", Func: func(m wago.HostModule, p, r []uint64) { EchoResult(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy one exact completed ICMPv6 echo reply"},
		{Name: "cancel_echo", Func: func(m wago.HostModule, p, r []uint64) { CancelEcho(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one unfinished ICMPv6 echo"},
		{Name: "close_echo", Func: func(m wago.HostModule, p, r []uint64) { CloseEcho(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact ICMPv6 echo handle"},
		{Name: "resolve", Func: func(m wago.HostModule, p, r []uint64) { Resolve(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "start one bounded Neighbor Solicitation"},
		{Name: "neighbor_result", Func: func(m wago.HostModule, p, r []uint64) { NeighborResult(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy one resolved IPv6-to-Ethernet neighbor"},
		{Name: "cancel_neighbor", Func: func(m wago.HostModule, p, r []uint64) { CancelNeighbor(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "cancel one pending Neighbor Solicitation"},
		{Name: "close_neighbor", Func: func(m wago.HostModule, p, r []uint64) { CloseNeighbor(host, m, p, r) }, Params: []wago.ValType{wago.ValI64}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "close one exact neighbor-resolution handle"},
		{Name: "lookup_neighbor", Func: func(m wago.HostModule, p, r []uint64) { LookupNeighbor(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "copy one complete finite neighbor-cache entry"},
		{Name: "seed_neighbor", Func: func(m wago.HostModule, p, r []uint64) { SeedNeighbor(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "seed one finite exact neighbor-cache entry"},
		{Name: "remove_neighbor", Func: func(m wago.HostModule, p, r []uint64) { RemoveNeighbor(host, m, p, r) }, Params: []wago.ValType{wago.ValI64, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "remove one exact complete neighbor-cache entry"},
		{Name: "poll", Func: func(m wago.HostModule, p, r []uint64) { guest.Poll(host, m, p, r) }, Params: []wago.ValType{wago.ValI32, wago.ValI32, wago.ValI32, wago.ValI32}, Results: []wago.ValType{wago.ValI32}, Capability: Capability, Docs: "perform one quota-accounted bounded ICMPv6 readiness and service pass"},
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
	if handle == 0 || !abicore.EncodeHandleV1(memory, out, handle) {
		guest.SetStatus(results, guest.StatusNotSupported)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Operations(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out, ok := abicore.NarrowUint32(params[1])
	if !ok || !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: icmpabi.OperationsV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	operations, err := icmpinstance.Operations(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if !icmpabi.EncodeOperationsV1(memory, out, operations) {
		guest.SetStatus(results, guest.StatusIO)
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
	requestPtr, requestOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !requestOK || !outOK || !icmpabi.CheckEchoV1(memory, requestPtr, out) {
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
	if (status != guest.StatusOK && status != guest.StatusInProgress) || !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindICMPv6Echo)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, status)
}

func EchoResult(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 4 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	payloadPtr, payloadOK := abicore.NarrowUint32(params[1])
	payloadLen, lengthOK := abicore.NarrowUint32(params[2])
	out, outOK := abicore.NarrowUint32(params[3])
	if !payloadOK || !lengthOK || !outOK || !icmpabi.CheckEchoResultV1(memory, payloadPtr, payloadLen, out) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	payload, _ := abicore.Slice(memory, payloadPtr, payloadLen)
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	result, next, err := icmpinstance.EchoResult(state, resource.Handle(params[0]), payload)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if next == icmpns.NextWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if next != icmpns.NextReady || !icmpabi.EncodeEchoResultV1(memory, out, result, len(payload)) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func Resolve(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	keyPtr, keyOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !keyOK || !outOK || !abicore.CheckRanges(memory, true, abicore.Range{Ptr: keyPtr, Length: icmpabi.NeighborKeyV1Size}, abicore.Range{Ptr: out, Length: abicore.HandleV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := icmpabi.DecodeNeighborKeyV1(memory, keyPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	handle, progress, err := icmpinstance.Resolve(state, resource.Handle(params[0]), request)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	status = guest.FromProgress(progress)
	if (status != guest.StatusOK && status != guest.StatusInProgress) || !abicore.EncodeHandleV1(memory, out, handle) {
		_ = state.CloseHandle(handle, resource.KindICMPv6Neighbor)
		guest.SetStatus(results, guest.StatusOther)
		return
	}
	guest.SetStatus(results, status)
}

func NeighborResult(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	out, ok := abicore.NarrowUint32(params[1])
	if !ok || !abicore.CheckRanges(memory, false, abicore.Range{Ptr: out, Length: icmpabi.NeighborV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	neighbor, next, err := icmpinstance.NeighborResult(state, resource.Handle(params[0]))
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if next == icmpns.NextWouldBlock {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if next != icmpns.NextReady || !icmpabi.EncodeNeighborV1(memory, out, neighbor) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func LookupNeighbor(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 3 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	keyPtr, keyOK := abicore.NarrowUint32(params[1])
	out, outOK := abicore.NarrowUint32(params[2])
	if !keyOK || !outOK || !abicore.CheckRanges(memory, true, abicore.Range{Ptr: keyPtr, Length: icmpabi.NeighborKeyV1Size}, abicore.Range{Ptr: out, Length: icmpabi.NeighborV1Size}) {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := icmpabi.DecodeNeighborKeyV1(memory, keyPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	neighbor, found, err := icmpinstance.Lookup(state, resource.Handle(params[0]), request)
	if err != nil {
		guest.SetStatus(results, guest.FromError(err))
		return
	}
	if !found {
		guest.SetStatus(results, guest.StatusAgain)
		return
	}
	if !icmpabi.EncodeNeighborV1(memory, out, neighbor) {
		guest.SetStatus(results, guest.StatusIO)
		return
	}
	guest.SetStatus(results, guest.StatusOK)
}

func SeedNeighbor(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	neighborPtr, ptrOK := abicore.NarrowUint32(params[1])
	if !ptrOK {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	neighbor, ok := icmpabi.DecodeNeighborV1(memory, neighborPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(icmpinstance.Seed(state, resource.Handle(params[0]), neighbor)))
}

func RemoveNeighbor(host plugin.Host, module wago.HostModule, params, results []uint64) {
	if len(params) != 2 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	memory := guest.Memory(module)
	keyPtr, ptrOK := abicore.NarrowUint32(params[1])
	if !ptrOK {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	request, ok := icmpabi.DecodeNeighborKeyV1(memory, keyPtr)
	if !ok {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
		return
	}
	guest.SetStatus(results, guest.FromError(icmpinstance.Remove(state, resource.Handle(params[0]), request)))
}

func CancelEcho(host plugin.Host, module wago.HostModule, params, results []uint64) {
	state, status := oneHandleState(host, module, params, results)
	if status != guest.StatusOK {
		return
	}
	guest.SetStatus(results, guest.FromError(icmpinstance.CancelEcho(state, resource.Handle(params[0]))))
}

func CloseEcho(host plugin.Host, module wago.HostModule, params, results []uint64) {
	state, status := oneHandleState(host, module, params, results)
	if status != guest.StatusOK {
		return
	}
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindICMPv6Echo)))
}

func CancelNeighbor(host plugin.Host, module wago.HostModule, params, results []uint64) {
	state, status := oneHandleState(host, module, params, results)
	if status != guest.StatusOK {
		return
	}
	guest.SetStatus(results, guest.FromError(icmpinstance.CancelNeighbor(state, resource.Handle(params[0]))))
}

func CloseNeighbor(host plugin.Host, module wago.HostModule, params, results []uint64) {
	state, status := oneHandleState(host, module, params, results)
	if status != guest.StatusOK {
		return
	}
	guest.SetStatus(results, guest.FromError(state.CloseHandle(resource.Handle(params[0]), resource.KindICMPv6Neighbor)))
}

func oneHandleState(host plugin.Host, module wago.HostModule, params, results []uint64) (*instance.State, guest.Status) {
	if len(params) != 1 || len(results) != 1 {
		guest.SetStatus(results, guest.StatusInvalidArgument)
		return nil, guest.StatusInvalidArgument
	}
	state, status := instanceState(host, module)
	if status != guest.StatusOK {
		guest.SetStatus(results, status)
	}
	return state, status
}

func instanceState(host plugin.Host, module wago.HostModule) (*instance.State, guest.Status) {
	state, ok := host.State(module)
	if !ok || state == nil {
		return nil, guest.StatusInvalidState
	}
	return state, guest.StatusOK
}
