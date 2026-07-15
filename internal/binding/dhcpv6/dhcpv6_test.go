package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	dhcpabi "github.com/wago-org/net/internal/abi/dhcpv6"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type testHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h testHost) Memory() []byte           { return h.memory }
func (h testHost) Instance() *wago.Instance { return h.instance }

type fakeBase struct{}

func (*fakeBase) Close() error                { return nil }
func (*fakeBase) Readiness() nscore.Readiness { return 0 }
func (*fakeBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeNamespace struct {
	lease           *fakeLease
	calls           int
	operationsCalls int
}

func (n *fakeNamespace) Operations() dhcpns.Operations {
	n.operationsCalls++
	return dhcpns.SupportedOperations
}
func (n *fakeNamespace) TryAcquire() (nscore.Resource, nscore.Progress, error) {
	n.calls++
	return n.lease, nscore.ProgressInProgress, nil
}

type fakeLease struct {
	configuration dhcpns.Configuration
	result        dhcpns.ResultState
	failure       error
	resultCalls   int
	cancelCalls   int
	closeCalls    int
}

func (l *fakeLease) Close() error              { l.closeCalls++; return nil }
func (l *fakeLease) Cancel() error             { l.cancelCalls++; return nil }
func (*fakeLease) Readiness() nscore.Readiness { return nscore.ReadyDHCPv6Result }
func (l *fakeLease) TryResult() (dhcpns.Configuration, dhcpns.ResultState, error) {
	l.resultCalls++
	return l.configuration, l.result, l.failure
}

func TestResultBindingChecksMemoryAndEncodesReadyConfiguration(t *testing.T) {
	configuration := dhcpns.Configuration{
		TransactionID:            0x123456,
		IAID:                     [4]byte{2, 0, 0, 1},
		AssignedAddr:             netip.MustParseAddr("2001:db8::10"),
		ServerAddr:               netip.MustParseAddr("fe80::2"),
		ServerScopeID:            7,
		ServerDUIDLength:         10,
		PreferredLifetimeSeconds: 1800,
		ValidLifetimeSeconds:     3600,
	}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2})
	lease := &fakeLease{configuration: configuration, result: dhcpns.ResultReady}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: &fakeNamespace{lease: lease}})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: make([]byte, 4096)}
	bindings := Bindings(plugin.NewHost(manager))

	namespace := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 400)
	if namespace.status != guest.StatusOK {
		t.Fatalf("namespace = %v", namespace.status)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[400:408])
	started := callBinding(t, bindingByName(t, bindings, "start"), host, namespaceHandle, uint64(dhcpns.OperationAcquire), 320)
	if started.status != guest.StatusInProgress {
		t.Fatalf("start = %v", started.status)
	}
	leaseHandle := binary.LittleEndian.Uint64(host.memory[320:328])

	before := bytes.Repeat([]byte{0xa5}, 16)
	copy(host.memory[:16], before)
	failed := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, uint64(len(host.memory)-1))
	if failed.status != guest.StatusInvalidArgument || !bytes.Equal(host.memory[:16], before) {
		t.Fatalf("out-of-bounds result = %v", failed.status)
	}
	for i := range host.memory[:dhcpabi.ConfigurationV1Size] {
		host.memory[i] = 0xa5
	}
	ready := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, 0)
	if ready.status != guest.StatusOK || binary.LittleEndian.Uint32(host.memory[:4]) != configuration.TransactionID ||
		host.memory[dhcpabi.ConfigurationV1Size-1] != 0 {
		t.Fatalf("ready result = %v xid=%x", ready.status, binary.LittleEndian.Uint32(host.memory[:4]))
	}
}

func TestBindingsRejectHighBitI32AliasesBeforeStateAndBackendWork(t *testing.T) {
	lease := &fakeLease{result: dhcpns.ResultWouldBlock}
	backend := &fakeNamespace{lease: lease}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x6d}, 4096)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	namespaceHandle := state.NamespaceHandle()
	leaseHandle, err := state.Resources().Add(resource.KindDHCPv6Lease, lease)
	if err != nil {
		t.Fatal(err)
	}

	high := uint64(1) << 32
	tests := []struct {
		name    string
		binding string
		params  []uint64
	}{
		{name: "namespace output", binding: "namespace_default", params: []uint64{high | 400}},
		{name: "operations output", binding: "operations", params: []uint64{uint64(namespaceHandle), high | 256}},
		{name: "start output", binding: "start", params: []uint64{uint64(namespaceHandle), uint64(dhcpns.OperationAcquire), high | 320}},
		{name: "result output", binding: "result", params: []uint64{uint64(leaseHandle), high | 512}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := append([]byte(nil), host.memory...)
			acquireCalls, operationsCalls, resultCalls := backend.calls, backend.operationsCalls, lease.resultCalls
			if status := callBinding(t, bindingByName(t, bindings, test.binding), host, test.params...).status; status != guest.StatusInvalidArgument {
				t.Fatalf("status = %v", status)
			}
			if backend.calls != acquireCalls || backend.operationsCalls != operationsCalls || lease.resultCalls != resultCalls {
				t.Fatalf("backend work changed: acquire=%d operations=%d result=%d", backend.calls, backend.operationsCalls, lease.resultCalls)
			}
			if !bytes.Equal(host.memory, before) {
				t.Fatal("invalid alias mutated guest memory")
			}
		})
	}
}

func TestBindingsPreserveFullWidthNamespaceAndLeaseHandles(t *testing.T) {
	lease := &fakeLease{result: dhcpns.ResultWouldBlock}
	backend := &fakeNamespace{lease: lease}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x7b}, 4096)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	namespaceHandle := state.NamespaceHandle()
	leaseHandle, err := state.Resources().Add(resource.KindDHCPv6Lease, lease)
	if err != nil {
		t.Fatal(err)
	}
	const high = uint64(1) << 63

	operationsPtr := uint64(256)
	operationsBefore := append([]byte(nil), host.memory[operationsPtr:operationsPtr+uint64(dhcpabi.OperationsV1Size)]...)
	if status := callBinding(t, bindingByName(t, bindings, "operations"), host, uint64(namespaceHandle)|high, operationsPtr).status; status != guest.StatusBadHandle || backend.operationsCalls != 0 || !bytes.Equal(host.memory[operationsPtr:operationsPtr+uint64(dhcpabi.OperationsV1Size)], operationsBefore) {
		t.Fatalf("high namespace operations = %v calls=%d", status, backend.operationsCalls)
	}
	startPtr := uint64(320)
	startBefore := append([]byte(nil), host.memory[startPtr:startPtr+8]...)
	if status := callBinding(t, bindingByName(t, bindings, "start"), host, uint64(namespaceHandle)|high, uint64(dhcpns.OperationAcquire), startPtr).status; status != guest.StatusBadHandle || backend.calls != 0 || !bytes.Equal(host.memory[startPtr:startPtr+8], startBefore) {
		t.Fatalf("high namespace start = %v calls=%d", status, backend.calls)
	}

	resultPtr := uint64(512)
	resultBefore := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(dhcpabi.ConfigurationV1Size)]...)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(leaseHandle)|high, resultPtr).status; status != guest.StatusBadHandle || lease.resultCalls != 0 || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(dhcpabi.ConfigurationV1Size)], resultBefore) {
		t.Fatalf("high lease result = %v calls=%d", status, lease.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(leaseHandle)|high).status; status != guest.StatusBadHandle || lease.cancelCalls != 0 {
		t.Fatalf("high lease cancel = %v calls=%d", status, lease.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(leaseHandle)|high).status; status != guest.StatusBadHandle || lease.closeCalls != 0 {
		t.Fatalf("high lease close = %v calls=%d", status, lease.closeCalls)
	}

	if status := callBinding(t, bindingByName(t, bindings, "operations"), host, uint64(namespaceHandle), operationsPtr).status; status != guest.StatusOK || backend.operationsCalls != 1 {
		t.Fatalf("exact namespace operations = %v calls=%d", status, backend.operationsCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(leaseHandle), resultPtr).status; status != guest.StatusAgain || lease.resultCalls != 1 {
		t.Fatalf("exact lease result = %v calls=%d", status, lease.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(leaseHandle)).status; status != guest.StatusOK || lease.cancelCalls != 1 {
		t.Fatalf("exact lease cancel = %v calls=%d", status, lease.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(leaseHandle)).status; status != guest.StatusOK || lease.closeCalls != 1 {
		t.Fatalf("exact lease close = %v calls=%d", status, lease.closeCalls)
	}
}

func TestBindingsRejectTypedNilAndIsolateReusedLeaseGeneration(t *testing.T) {
	backend := &fakeNamespace{}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: backend})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 4096)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("instance state missing")
	}
	namespaceHandle := state.NamespaceHandle()

	outPtr := uint64(320)
	outBefore := append([]byte(nil), host.memory[outPtr:outPtr+uint64(8)]...)
	if status := callBinding(t, bindingByName(t, bindings, "start"), host, uint64(namespaceHandle), uint64(dhcpns.OperationAcquire)+256, outPtr); status.status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory[outPtr:outPtr+uint64(8)], outBefore) {
		t.Fatalf("truncated operation start = %v calls=%d", status.status, backend.calls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "start"), host, uint64(namespaceHandle), uint64(dhcpns.OperationAcquire), uint64(len(host.memory)-1)); status.status != guest.StatusInvalidArgument || backend.calls != 0 {
		t.Fatalf("out-of-bounds start = %v calls=%d", status.status, backend.calls)
	}
	var typedNil *fakeLease
	backend.lease = typedNil
	if status := callBinding(t, bindingByName(t, bindings, "start"), host, uint64(namespaceHandle), uint64(dhcpns.OperationAcquire), outPtr); status.status != guest.StatusIO || backend.calls != 1 || !bytes.Equal(host.memory[outPtr:outPtr+uint64(8)], outBefore) {
		t.Fatalf("typed-nil start = %v calls=%d", status.status, backend.calls)
	}

	first := &fakeLease{result: dhcpns.ResultWouldBlock}
	backend.lease = first
	if status := callBinding(t, bindingByName(t, bindings, "start"), host, uint64(namespaceHandle), uint64(dhcpns.OperationAcquire), outPtr); status.status != guest.StatusInProgress || backend.calls != 2 {
		t.Fatalf("first start = %v calls=%d", status.status, backend.calls)
	}
	firstHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[outPtr : outPtr+uint64(8)]))
	resultPtr := uint64(512)
	resultBefore := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(dhcpabi.ConfigurationV1Size)]...)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(firstHandle), resultPtr); status.status != guest.StatusAgain || first.resultCalls != 1 || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(dhcpabi.ConfigurationV1Size)], resultBefore) {
		t.Fatalf("would-block result = %v calls=%d", status.status, first.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(namespaceHandle), resultPtr); status.status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind result = %v", status.status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(firstHandle)); status.status != guest.StatusOK || first.cancelCalls != 1 {
		t.Fatalf("first cancel = %v calls=%d", status.status, first.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(firstHandle)); status.status != guest.StatusOK || first.closeCalls != 1 {
		t.Fatalf("first close = %v calls=%d", status.status, first.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(firstHandle), resultPtr); status.status != guest.StatusBadHandle {
		t.Fatalf("stale result = %v", status.status)
	}

	fresh := &fakeLease{result: dhcpns.ResultWouldBlock}
	backend.lease = fresh
	freshPtr := uint64(336)
	if status := callBinding(t, bindingByName(t, bindings, "start"), host, uint64(namespaceHandle), uint64(dhcpns.OperationAcquire), freshPtr); status.status != guest.StatusInProgress {
		t.Fatalf("fresh start = %v", status.status)
	}
	freshHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[freshPtr : freshPtr+uint64(8)]))
	if freshHandle == firstHandle || uint16(freshHandle) != uint16(firstHandle) {
		t.Fatalf("generation-safe slot reuse = old %v fresh %v", firstHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(firstHandle)); status.status != guest.StatusBadHandle || fresh.cancelCalls != 0 {
		t.Fatalf("stale cancel after reuse = %v fresh calls=%d", status.status, fresh.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(firstHandle)); status.status != guest.StatusBadHandle || fresh.closeCalls != 0 {
		t.Fatalf("stale close after reuse = %v fresh calls=%d", status.status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(firstHandle), resultPtr); status.status != guest.StatusBadHandle || fresh.resultCalls != 0 {
		t.Fatalf("stale result after reuse = %v fresh calls=%d", status.status, fresh.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(freshHandle), resultPtr); status.status != guest.StatusAgain || fresh.resultCalls != 1 {
		t.Fatalf("fresh result = %v calls=%d", status.status, fresh.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(freshHandle)); status.status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("fresh close = %v calls=%d", status.status, fresh.closeCalls)
	}
}

func attachManager(t testing.TB, backend *fakeNamespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: backend})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	return manager, instance
}

type bindingResult struct{ status guest.Status }

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

func callBinding(t testing.TB, function wago.HostFunc, host testHost, params ...uint64) bindingResult {
	t.Helper()
	var results [1]uint64
	function(host, params, results[:])
	return bindingResult{status: guest.Status(int32(results[0]))}
}

func BenchmarkResultBindingReady(b *testing.B) {
	configuration := dhcpns.Configuration{
		TransactionID:            0x123456,
		IAID:                     [4]byte{2, 0, 0, 1},
		AssignedAddr:             netip.MustParseAddr("2001:db8::10"),
		ServerAddr:               netip.MustParseAddr("fe80::2"),
		ServerScopeID:            7,
		ServerDUIDLength:         10,
		PreferredLifetimeSeconds: 1800,
		ValidLifetimeSeconds:     3600,
	}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2})
	lease := &fakeLease{configuration: configuration, result: dhcpns.ResultReady}
	manager, instance := attachManager(b, &fakeNamespace{lease: lease})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindDHCPv6Lease, lease)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, dhcpabi.ConfigurationV1Size)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "result")
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
