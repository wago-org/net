package icmpv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	icmpabi "github.com/wago-org/net/internal/abi/icmpv6"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type lifecycleBase struct{}

func (*lifecycleBase) Close() error                { return nil }
func (*lifecycleBase) Readiness() nscore.Readiness { return 0 }
func (*lifecycleBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type lifecycleNamespace struct {
	operations      icmpns.Operations
	echo            nscore.Resource
	echoProgress    nscore.Progress
	echoFailure     error
	echoRequest     icmpns.EchoRequest
	echoPayload     []byte
	echoCalls       int
	resolution      nscore.Resource
	resolveProgress nscore.Progress
	resolveFailure  error
	resolveRequest  icmpns.NeighborRequest
	resolveCalls    int
	lookupNeighbor  icmpns.Neighbor
	lookupFound     bool
	lookupFailure   error
	lookupRequest   icmpns.NeighborRequest
	lookupCalls     int
	seedFailure     error
	seeded          icmpns.Neighbor
	seedCalls       int
	removeFailure   error
	removed         icmpns.NeighborRequest
	removeCalls     int
}

func (n *lifecycleNamespace) Operations() icmpns.Operations { return n.operations }
func (n *lifecycleNamespace) TryEcho(request icmpns.EchoRequest) (nscore.Resource, nscore.Progress, error) {
	n.echoCalls++
	n.echoRequest = request
	n.echoPayload = append(n.echoPayload[:0], request.Payload...)
	return n.echo, n.echoProgress, n.echoFailure
}
func (n *lifecycleNamespace) TryResolve(request icmpns.NeighborRequest) (nscore.Resource, nscore.Progress, error) {
	n.resolveCalls++
	n.resolveRequest = request
	return n.resolution, n.resolveProgress, n.resolveFailure
}
func (n *lifecycleNamespace) LookupNeighbor(request icmpns.NeighborRequest) (icmpns.Neighbor, bool, error) {
	n.lookupCalls++
	n.lookupRequest = request
	return n.lookupNeighbor, n.lookupFound, n.lookupFailure
}
func (n *lifecycleNamespace) SeedNeighbor(neighbor icmpns.Neighbor) error {
	n.seedCalls++
	n.seeded = neighbor
	return n.seedFailure
}
func (n *lifecycleNamespace) RemoveNeighbor(request icmpns.NeighborRequest) error {
	n.removeCalls++
	n.removed = request
	return n.removeFailure
}

type lifecycleEcho struct {
	payload     []byte
	result      icmpns.EchoResult
	next        icmpns.Next
	failure     error
	resultCalls int
	cancelCalls int
	closeCalls  int
}

func (e *lifecycleEcho) Close() error              { e.closeCalls++; return nil }
func (e *lifecycleEcho) Cancel() error             { e.cancelCalls++; return nil }
func (*lifecycleEcho) Readiness() nscore.Readiness { return nscore.ReadyICMPv6Reply }
func (e *lifecycleEcho) TryResult(dst []byte) (icmpns.EchoResult, icmpns.Next, error) {
	e.resultCalls++
	result := e.result
	if e.failure == nil && e.next == icmpns.NextReady {
		result.Copied = copy(dst, e.payload)
		if result.PayloadBytes == 0 {
			result.PayloadBytes = len(e.payload)
		}
	}
	return result, e.next, e.failure
}

type lifecycleResolution struct {
	neighbor    icmpns.Neighbor
	next        icmpns.Next
	failure     error
	resultCalls int
	cancelCalls int
	closeCalls  int
}

func (r *lifecycleResolution) Close() error              { r.closeCalls++; return nil }
func (r *lifecycleResolution) Cancel() error             { r.cancelCalls++; return nil }
func (*lifecycleResolution) Readiness() nscore.Readiness { return nscore.ReadyICMPv6Neighbor }
func (r *lifecycleResolution) TryResult() (icmpns.Neighbor, icmpns.Next, error) {
	r.resultCalls++
	return r.neighbor, r.next, r.failure
}

func TestBindingsEchoAtomicStatusesAndLifecycle(t *testing.T) {
	destination := netip.MustParseAddr("2001:db8::2")
	echo := &lifecycleEcho{next: icmpns.NextWouldBlock}
	backend := &lifecycleNamespace{operations: icmpns.SupportedOperations, echo: echo, echoProgress: nscore.ProgressInProgress}
	manager, instance := attachLifecycleManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 1024)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callLifecycleBinding(t, bindingByName(t, bindings, "namespace_default"), host, 960); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[960:968]))
	operationsBefore := append([]byte(nil), host.memory[900:904]...)
	backend.operations = icmpns.SupportedOperations | (1 << 31)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "operations"), host, uint64(namespaceHandle), 900); status != guest.StatusIO || !bytes.Equal(host.memory[900:904], operationsBefore) {
		t.Fatalf("malformed operations = %v", status)
	}
	backend.operations = icmpns.SupportedOperations
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "operations"), host, uint64(namespaceHandle), 900); status != guest.StatusOK || binary.LittleEndian.Uint32(host.memory[900:904]) != uint32(icmpns.SupportedOperations) {
		t.Fatalf("operations = %v bytes=%x", status, host.memory[900:904])
	}

	payload := []byte("echo-request")
	copy(host.memory[64:64+len(payload)], payload)
	endpoint := nscore.Endpoint{Address: destination}
	if !icmpabi.EncodeEchoRequestV1(host.memory, 0, endpoint, 64, uint32(len(payload))) {
		t.Fatal("encode echo request")
	}
	before := append([]byte(nil), host.memory...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo"), host, uint64(namespaceHandle), 0, 16); status != guest.StatusInvalidArgument || backend.echoCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap echo = %v, calls=%d", status, backend.echoCalls)
	}
	host.memory[40] = 1
	handleBefore := append([]byte(nil), host.memory[128:136]...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo"), host, uint64(namespaceHandle), 0, 128); status != guest.StatusInvalidArgument || backend.echoCalls != 0 || !bytes.Equal(host.memory[128:136], handleBefore) {
		t.Fatalf("reserved echo = %v, calls=%d", status, backend.echoCalls)
	}
	host.memory[40] = 0
	backend.echoFailure = nscore.Fail(nscore.FailureRemoteUnreachable, errors.New("unreachable"))
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo"), host, uint64(namespaceHandle), 0, 128); status != guest.StatusRemoteUnreachable || backend.echoCalls != 1 || !bytes.Equal(host.memory[128:136], handleBefore) {
		t.Fatalf("failed echo = %v, calls=%d", status, backend.echoCalls)
	}
	backend.echoFailure = nil
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo"), host, uint64(namespaceHandle), 0, 128); status != guest.StatusInProgress || backend.echoCalls != 2 || backend.echoRequest.Destination != destination || backend.echoRequest.ScopeID != 0 || !bytes.Equal(backend.echoPayload, payload) {
		t.Fatalf("echo = %v calls=%d request=%+v payload=%q", status, backend.echoCalls, backend.echoRequest, backend.echoPayload)
	}
	host.memory[64] ^= 0xff
	if !bytes.Equal(backend.echoPayload, payload) {
		t.Fatalf("echo payload was retained: %x", backend.echoPayload)
	}
	echoHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[128:136]))

	payloadPtr, payloadLen, resultPtr := uint64(256), uint64(8), uint64(320)
	resultBefore := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(icmpabi.EchoResultV1Size)]...)
	payloadBefore := append([]byte(nil), host.memory[payloadPtr:payloadPtr+payloadLen]...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo_result"), host, uint64(echoHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusAgain || echo.resultCalls != 1 || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], payloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(icmpabi.EchoResultV1Size)], resultBefore) {
		t.Fatalf("would-block result = %v, calls=%d", status, echo.resultCalls)
	}
	echo.failure = nscore.Fail(nscore.FailureTimedOut, errors.New("timeout"))
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo_result"), host, uint64(echoHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusTimedOut || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], payloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(icmpabi.EchoResultV1Size)], resultBefore) {
		t.Fatalf("failed result = %v", status)
	}
	echo.failure = nil
	echo.next = icmpns.NextReady
	echo.payload = []byte("reply-data")
	echo.result = icmpns.EchoResult{Source: destination, Identifier: 7, Sequence: 9}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo_result"), host, uint64(echoHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusOK {
		t.Fatalf("ready result = %v", status)
	}
	if got := string(host.memory[payloadPtr : payloadPtr+payloadLen]); got != "reply-da" {
		t.Fatalf("echo payload = %q", got)
	}
	encoded := host.memory[resultPtr : resultPtr+uint64(icmpabi.EchoResultV1Size)]
	source, ok := abicore.DecodeEndpointV1(encoded, 0)
	if !ok || source.Address != destination || source.Port != 0 || binary.LittleEndian.Uint16(encoded[32:34]) != 7 || binary.LittleEndian.Uint16(encoded[34:36]) != 9 || binary.LittleEndian.Uint32(encoded[36:40]) != 8 || binary.LittleEndian.Uint32(encoded[40:44]) != uint32(len(echo.payload)) || binary.LittleEndian.Uint32(encoded[44:48]) != 0 {
		t.Fatalf("echo result = %x source=%+v/%v", encoded, source, ok)
	}

	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo_result"), host, uint64(namespaceHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind echo result = %v", status)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "cancel_echo"), host, uint64(echoHandle)); status != guest.StatusOK || echo.cancelCalls != 1 {
		t.Fatalf("cancel_echo = %v calls=%d", status, echo.cancelCalls)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "close_echo"), host, uint64(echoHandle)); status != guest.StatusOK || echo.closeCalls != 1 {
		t.Fatalf("close_echo = %v calls=%d", status, echo.closeCalls)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo_result"), host, uint64(echoHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle {
		t.Fatalf("stale echo result = %v", status)
	}
}

func TestBindingsNeighborAtomicStatusesCacheAndLifecycle(t *testing.T) {
	address := netip.MustParseAddr("fe80::20")
	request := icmpns.NeighborRequest{Address: address, ScopeID: 4}
	neighbor := icmpns.Neighbor{Address: address, ScopeID: 4, MAC: [6]byte{0x02, 0, 0, 0, 0, 0x20}}
	resolution := &lifecycleResolution{next: icmpns.NextWouldBlock}
	backend := &lifecycleNamespace{operations: icmpns.SupportedOperations, resolution: resolution, resolveProgress: nscore.ProgressInProgress}
	manager, instance := attachLifecycleManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 768)}
	bindings := Bindings(plugin.NewHost(manager))
	state, _ := manager.ForInstance(instance)
	namespaceHandle := state.NamespaceHandle()

	if !icmpabi.EncodeNeighborKeyV1(host.memory, 0, request) {
		t.Fatal("encode neighbor key")
	}
	before := append([]byte(nil), host.memory...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 16); status != guest.StatusInvalidArgument || backend.resolveCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap resolve = %v calls=%d", status, backend.resolveCalls)
	}
	host.memory[28] = 1
	handleBefore := append([]byte(nil), host.memory[64:72]...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 64); status != guest.StatusInvalidArgument || backend.resolveCalls != 0 || !bytes.Equal(host.memory[64:72], handleBefore) {
		t.Fatalf("reserved resolve = %v calls=%d", status, backend.resolveCalls)
	}
	host.memory[28] = 0
	backend.resolveFailure = nscore.Fail(nscore.FailureAccessDenied, errors.New("denied"))
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 64); status != guest.StatusAccessDenied || backend.resolveCalls != 1 || !bytes.Equal(host.memory[64:72], handleBefore) {
		t.Fatalf("failed resolve = %v calls=%d", status, backend.resolveCalls)
	}
	backend.resolveFailure = nil
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 64); status != guest.StatusInProgress || backend.resolveCalls != 2 || backend.resolveRequest != request {
		t.Fatalf("resolve = %v calls=%d request=%+v", status, backend.resolveCalls, backend.resolveRequest)
	}
	resolutionHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[64:72]))

	resultPtr := uint64(128)
	resultBefore := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(icmpabi.NeighborV1Size)]...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "neighbor_result"), host, uint64(resolutionHandle), resultPtr); status != guest.StatusAgain || resolution.resultCalls != 1 || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(icmpabi.NeighborV1Size)], resultBefore) {
		t.Fatalf("would-block neighbor = %v calls=%d", status, resolution.resultCalls)
	}
	resolution.failure = nscore.Fail(nscore.FailureCanceled, errors.New("canceled"))
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "neighbor_result"), host, uint64(resolutionHandle), resultPtr); status != guest.StatusCanceled || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(icmpabi.NeighborV1Size)], resultBefore) {
		t.Fatalf("failed neighbor = %v", status)
	}
	resolution.failure = nil
	resolution.next = icmpns.NextReady
	resolution.neighbor = icmpns.Neighbor{Address: address, ScopeID: 4}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "neighbor_result"), host, uint64(resolutionHandle), resultPtr); status != guest.StatusIO || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(icmpabi.NeighborV1Size)], resultBefore) {
		t.Fatalf("malformed neighbor = %v", status)
	}
	resolution.neighbor = neighbor
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "neighbor_result"), host, uint64(resolutionHandle), resultPtr); status != guest.StatusOK {
		t.Fatalf("ready neighbor = %v", status)
	}
	if decoded, ok := icmpabi.DecodeNeighborV1(host.memory, uint32(resultPtr)); !ok || decoded != neighbor {
		t.Fatalf("neighbor result = %+v/%v", decoded, ok)
	}

	lookupPtr := uint64(192)
	lookupBefore := append([]byte(nil), host.memory[lookupPtr:lookupPtr+uint64(icmpabi.NeighborV1Size)]...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "lookup_neighbor"), host, uint64(namespaceHandle), 0, 16); status != guest.StatusInvalidArgument || backend.lookupCalls != 0 {
		t.Fatalf("overlap lookup = %v calls=%d", status, backend.lookupCalls)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "lookup_neighbor"), host, uint64(namespaceHandle), 0, lookupPtr); status != guest.StatusAgain || backend.lookupCalls != 1 || backend.lookupRequest != request || !bytes.Equal(host.memory[lookupPtr:lookupPtr+uint64(icmpabi.NeighborV1Size)], lookupBefore) {
		t.Fatalf("missing lookup = %v calls=%d request=%+v", status, backend.lookupCalls, backend.lookupRequest)
	}
	backend.lookupNeighbor, backend.lookupFound = neighbor, true
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "lookup_neighbor"), host, uint64(namespaceHandle), 0, lookupPtr); status != guest.StatusOK {
		t.Fatalf("lookup = %v", status)
	}
	if decoded, ok := icmpabi.DecodeNeighborV1(host.memory, uint32(lookupPtr)); !ok || decoded != neighbor {
		t.Fatalf("lookup result = %+v/%v", decoded, ok)
	}

	if !icmpabi.EncodeNeighborV1(host.memory, 256, neighbor) {
		t.Fatal("encode neighbor")
	}
	host.memory[256+38] = 1
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "seed_neighbor"), host, uint64(namespaceHandle), 256); status != guest.StatusInvalidArgument || backend.seedCalls != 0 {
		t.Fatalf("reserved seed = %v calls=%d", status, backend.seedCalls)
	}
	host.memory[256+38] = 0
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "seed_neighbor"), host, uint64(namespaceHandle), 256); status != guest.StatusOK || backend.seedCalls != 1 || backend.seeded != neighbor {
		t.Fatalf("seed = %v calls=%d neighbor=%+v", status, backend.seedCalls, backend.seeded)
	}
	backend.removeFailure = nscore.Fail(nscore.FailureNotSupported, errors.New("unsupported"))
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "remove_neighbor"), host, uint64(namespaceHandle), 0); status != guest.StatusNotSupported || backend.removeCalls != 1 || backend.removed != request {
		t.Fatalf("failed remove = %v calls=%d request=%+v", status, backend.removeCalls, backend.removed)
	}
	backend.removeFailure = nil
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "remove_neighbor"), host, uint64(namespaceHandle), 0); status != guest.StatusOK || backend.removeCalls != 2 {
		t.Fatalf("remove = %v calls=%d", status, backend.removeCalls)
	}

	if status := callLifecycleBinding(t, bindingByName(t, bindings, "neighbor_result"), host, uint64(namespaceHandle), resultPtr); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind neighbor result = %v", status)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "cancel_neighbor"), host, uint64(resolutionHandle)); status != guest.StatusOK || resolution.cancelCalls != 1 {
		t.Fatalf("cancel_neighbor = %v calls=%d", status, resolution.cancelCalls)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "close_neighbor"), host, uint64(resolutionHandle)); status != guest.StatusOK || resolution.closeCalls != 1 {
		t.Fatalf("close_neighbor = %v calls=%d", status, resolution.closeCalls)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "neighbor_result"), host, uint64(resolutionHandle), resultPtr); status != guest.StatusBadHandle {
		t.Fatalf("stale neighbor result = %v", status)
	}
}

func TestBindingsPrevalidateICMPv6OutputsBeforeLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x3c}, 64)}
	bindings := Bindings(plugin.NewHost(manager))
	before := append([]byte(nil), host.memory...)
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "namespace_default"), host, 57); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("namespace range = %v", status)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "operations"), host, 1, 61); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("operations range = %v", status)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "echo_result"), host, 1, 0, 64, 0); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("echo result range = %v", status)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "neighbor_result"), host, 1, 25); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("neighbor result range = %v", status)
	}
	if status := callLifecycleBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func attachLifecycleManager(t testing.TB, backend icmpns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(&lifecycleBase{}, nscore.Service{Key: icmpns.ServiceKey, Value: backend})
	}
	manager, err := instancecore.NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	return manager, instance
}

func bindingByName(t testing.TB, bindings []plugin.Binding, name string) wago.HostFunc {
	t.Helper()
	for _, binding := range bindings {
		if binding.Name == name {
			return binding.Func
		}
	}
	t.Fatalf("binding %q missing", name)
	return nil
}

func callLifecycleBinding(t testing.TB, function wago.HostFunc, host testHost, params ...uint64) guest.Status {
	t.Helper()
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}

func BenchmarkNeighborResultBindingReady(b *testing.B) {
	neighbor := icmpns.Neighbor{Address: netip.MustParseAddr("2001:db8::20"), MAC: [6]byte{0x02, 0, 0, 0, 0, 0x20}}
	resolution := &lifecycleResolution{neighbor: neighbor, next: icmpns.NextReady}
	manager, instance := attachLifecycleManager(b, &lifecycleNamespace{operations: icmpns.SupportedOperations})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindICMPv6Neighbor, resolution)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, icmpabi.NeighborV1Size)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "neighbor_result")
	params := []uint64{uint64(handle), 0}
	var results [1]uint64
	function(host, params, results[:])
	if status := guest.Status(int32(results[0])); status != guest.StatusOK {
		b.Fatalf("warmup status = %v", status)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		function(host, params, results[:])
	}
}
