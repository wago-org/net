package ntp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	ntpabi "github.com/wago-org/net/internal/abi/ntp"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
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
	next     nscore.Resource
	progress nscore.Progress
	failure  error
	calls    int
}

func (n *fakeNamespace) TrySync() (nscore.Resource, nscore.Progress, error) {
	n.calls++
	return n.next, n.progress, n.failure
}

type fakeSync struct {
	sample      ntpns.Sample
	next        ntpns.Next
	failure     error
	resultCalls int
	cancelCalls int
	closeCalls  int
}

func (s *fakeSync) Close() error {
	s.closeCalls++
	return nil
}
func (s *fakeSync) Cancel() error {
	s.cancelCalls++
	return nil
}
func (*fakeSync) Readiness() nscore.Readiness { return nscore.ReadyNTPResult }
func (s *fakeSync) TryResult() (ntpns.Sample, ntpns.Next, error) {
	s.resultCalls++
	return s.sample, s.next, s.failure
}

func TestBindingsSyncResultAtomicStatusesAndLifecycle(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 480); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[480:488]))
	handleBefore := append([]byte(nil), host.memory[32:40]...)
	backend.failure = nscore.Fail(nscore.FailureTimedOut, errors.New("timeout"))
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle), 32); status != guest.StatusTimedOut || backend.calls != 1 || !bytes.Equal(host.memory[32:40], handleBefore) {
		t.Fatalf("failed sync = %v, calls=%d", status, backend.calls)
	}

	synchronization := &fakeSync{next: ntpns.NextWouldBlock}
	var typedNil *fakeSync
	backend.next, backend.progress, backend.failure = typedNil, nscore.ProgressDone, nil
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle), 32); status != guest.StatusIO || backend.calls != 2 || !bytes.Equal(host.memory[32:40], handleBefore) {
		t.Fatalf("typed-nil sync = %v, calls=%d", status, backend.calls)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	resourcesBefore := state.Resources().Len()
	readinessBefore := state.Readiness().Snapshot()
	invalidProgress := new(fakeSync)
	backend.next, backend.progress = invalidProgress, nscore.Progress(99)
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle), 32); status != guest.StatusIO || backend.calls != 3 || invalidProgress.closeCalls != 1 || state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore || !bytes.Equal(host.memory[32:40], handleBefore) {
		t.Fatalf("invalid-progress sync = %v, calls=%d closes=%d resources=%d readiness=%+v", status, backend.calls, invalidProgress.closeCalls, state.Resources().Len(), state.Readiness().Snapshot())
	}
	backend.next, backend.progress = synchronization, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle), 32); status != guest.StatusOK || backend.calls != 4 {
		t.Fatalf("sync = %v, calls=%d", status, backend.calls)
	}
	handle := resource.Handle(binary.LittleEndian.Uint64(host.memory[32:40]))

	pending := new(fakeSync)
	backend.next, backend.progress = pending, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle), 40); status != guest.StatusInProgress {
		t.Fatalf("in-progress sync = %v", status)
	}
	pendingHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[40:48]))

	outputBefore := append([]byte(nil), host.memory[128:128+ntpabi.SampleV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(handle), 128); status != guest.StatusAgain || synchronization.resultCalls != 1 || !bytes.Equal(host.memory[128:128+ntpabi.SampleV1Size], outputBefore) {
		t.Fatalf("would-block result = %v, calls=%d", status, synchronization.resultCalls)
	}
	synchronization.failure = nscore.Fail(nscore.FailureCanceled, errors.New("canceled"))
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(handle), 128); status != guest.StatusCanceled || !bytes.Equal(host.memory[128:128+ntpabi.SampleV1Size], outputBefore) {
		t.Fatalf("failed result = %v", status)
	}
	synchronization.failure = nil
	synchronization.next = 99
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(handle), 128); status != guest.StatusIO || !bytes.Equal(host.memory[128:128+ntpabi.SampleV1Size], outputBefore) {
		t.Fatalf("malformed state = %v", status)
	}
	synchronization.next = ntpns.NextReady
	synchronization.sample = ntpns.Sample{Server: netip.MustParseAddr("192.0.2.123")}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(handle), 128); status != guest.StatusIO || !bytes.Equal(host.memory[128:128+ntpabi.SampleV1Size], outputBefore) {
		t.Fatalf("malformed sample = %v", status)
	}

	synchronization.sample = validSample()
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(handle), 128); status != guest.StatusOK {
		t.Fatalf("ready result = %v", status)
	}
	decoded, ok := ntpabi.DecodeSampleV1(host.memory, 128)
	if !ok || decoded != synchronization.sample {
		t.Fatalf("decoded sample = %+v, %v", decoded, ok)
	}
	encoded := host.memory[128 : 128+ntpabi.SampleV1Size]
	if encoded[47] != 0 || binary.LittleEndian.Uint32(encoded[68:72]) != 0 {
		t.Fatalf("reserved output = %x/%x", encoded[47], encoded[68:72])
	}

	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(namespaceHandle), 128); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind result = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(handle)); status != guest.StatusOK || synchronization.cancelCalls != 1 {
		t.Fatalf("cancel = %v, calls=%d", status, synchronization.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(handle)); status != guest.StatusOK || synchronization.closeCalls != 1 {
		t.Fatalf("close = %v, calls=%d", status, synchronization.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(handle), 128); status != guest.StatusBadHandle {
		t.Fatalf("stale result = %v", status)
	}

	fresh := &fakeSync{next: ntpns.NextWouldBlock}
	backend.next, backend.progress = fresh, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle), 48); status != guest.StatusInProgress {
		t.Fatalf("fresh sync = %v", status)
	}
	freshHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[48:56]))
	if freshHandle == handle || uint16(freshHandle) != uint16(handle) {
		t.Fatalf("generation-safe slot reuse = old %v, fresh %v", handle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(handle)); status != guest.StatusBadHandle || fresh.cancelCalls != 0 {
		t.Fatalf("stale cancel = %v, fresh calls=%d", status, fresh.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(handle)); status != guest.StatusBadHandle || fresh.closeCalls != 0 {
		t.Fatalf("stale close = %v, fresh calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(freshHandle), 128); status != guest.StatusAgain || fresh.resultCalls != 1 {
		t.Fatalf("fresh result = %v, calls=%d", status, fresh.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("fresh close = %v, calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(pendingHandle)); status != guest.StatusOK || pending.closeCalls != 1 {
		t.Fatalf("close pending = %v, calls=%d", status, pending.closeCalls)
	}
}

func TestBindingsPreserveFullWidthNamespaceAndSynchronizationHandles(t *testing.T) {
	synchronization := &fakeSync{next: ntpns.NextWouldBlock}
	backend := &fakeNamespace{next: synchronization, progress: nscore.ProgressInProgress}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x7b}, 512)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	namespaceHandle := state.NamespaceHandle()
	syncHandle, err := state.Resources().Add(resource.KindNTPSync, synchronization)
	if err != nil {
		t.Fatal(err)
	}
	const high = uint64(1) << 63

	handlePtr := uint64(32)
	handleBefore := append([]byte(nil), host.memory[handlePtr:handlePtr+8]...)
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle)|high, handlePtr); status != guest.StatusBadHandle || backend.calls != 0 || !bytes.Equal(host.memory[handlePtr:handlePtr+8], handleBefore) {
		t.Fatalf("high namespace sync = %v calls=%d", status, backend.calls)
	}

	resultPtr := uint64(128)
	resultBefore := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(ntpabi.SampleV1Size)]...)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(syncHandle)|high, resultPtr); status != guest.StatusBadHandle || synchronization.resultCalls != 0 || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(ntpabi.SampleV1Size)], resultBefore) {
		t.Fatalf("high synchronization result = %v calls=%d", status, synchronization.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(syncHandle)|high); status != guest.StatusBadHandle || synchronization.cancelCalls != 0 {
		t.Fatalf("high synchronization cancel = %v calls=%d", status, synchronization.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(syncHandle)|high); status != guest.StatusBadHandle || synchronization.closeCalls != 0 {
		t.Fatalf("high synchronization close = %v calls=%d", status, synchronization.closeCalls)
	}

	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(namespaceHandle), handlePtr); status != guest.StatusInProgress || backend.calls != 1 {
		t.Fatalf("exact namespace sync = %v calls=%d", status, backend.calls)
	}
	createdHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[handlePtr : handlePtr+8]))
	if createdHandle == 0 {
		t.Fatal("exact namespace sync returned zero handle")
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(syncHandle), resultPtr); status != guest.StatusAgain || synchronization.resultCalls != 1 {
		t.Fatalf("exact synchronization result = %v calls=%d", status, synchronization.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(syncHandle)); status != guest.StatusOK || synchronization.cancelCalls != 1 {
		t.Fatalf("exact synchronization cancel = %v calls=%d", status, synchronization.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(syncHandle)); status != guest.StatusOK || synchronization.closeCalls != 1 {
		t.Fatalf("exact synchronization close = %v calls=%d", status, synchronization.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(createdHandle)); status != guest.StatusOK || synchronization.closeCalls != 2 {
		t.Fatalf("created synchronization close = %v calls=%d", status, synchronization.closeCalls)
	}
}

func TestBindingsRejectHighBitI32AliasesBeforeBackendCalls(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	bindings := Bindings(plugin.NewHost(manager))
	state, _ := manager.ForInstance(instance)
	synchronization := &fakeSync{next: ntpns.NextWouldBlock}
	handle, err := state.Resources().Add(resource.KindNTPSync, synchronization)
	if err != nil {
		t.Fatal(err)
	}

	const high = uint64(1) << 32
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, high+480); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("high namespace output = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, uint64(state.NamespaceHandle()), high+32); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high sync output = %v, calls=%d", status, backend.calls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, uint64(handle), high+128); status != guest.StatusInvalidArgument || synchronization.resultCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high result output = %v, calls=%d", status, synchronization.resultCalls)
	}
}

func TestBindingsPrevalidateOutputsBeforeInstanceAndHandleLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 64)}
	bindings := Bindings(plugin.NewHost(manager))
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 57); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("namespace range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "sync"), host, 1, 57); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("sync range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, 1, 1); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("result range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func TestNamespaceDefaultNotSupportedAfterNamespaceClose(t *testing.T) {
	manager, instance := attachManager(t, nil)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 32)}
	if status := callBinding(t, bindingByName(t, Bindings(plugin.NewHost(manager)), "namespace_default"), host, 0); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	state, _ := manager.ForInstance(instance)
	if err := state.CloseHandle(state.NamespaceHandle(), resource.KindNamespace); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), host.memory[8:16]...)
	if status := callBinding(t, bindingByName(t, Bindings(plugin.NewHost(manager)), "namespace_default"), host, 8); status != guest.StatusNotSupported || !bytes.Equal(host.memory[8:16], before) {
		t.Fatalf("closed namespace = %v", status)
	}
}

func validSample() ntpns.Sample {
	return ntpns.Sample{
		Server: netip.MustParseAddr("192.0.2.123"), CorrectedTime: time.Date(2026, 7, 13, 22, 0, 0, 123456789, time.UTC),
		Offset: -250 * time.Millisecond, RoundTripDelay: 20 * time.Millisecond,
		Stratum: 2, Leap: 0, Version: 4, ReferenceID: [4]byte{'G', 'P', 'S', 0},
	}
}

func attachManager(t testing.TB, backend ntpns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		if backend == nil {
			return nscore.ComposeNamespace(&fakeBase{})
		}
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: ntpns.ServiceKey, Value: backend})
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

func callBinding(t testing.TB, function wago.HostFunc, host testHost, params ...uint64) guest.Status {
	t.Helper()
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}

func BenchmarkResultBindingReady(b *testing.B) {
	synchronization := &fakeSync{sample: validSample(), next: ntpns.NextReady}
	manager, instance := attachManager(b, &fakeNamespace{next: synchronization, progress: nscore.ProgressDone})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindNTPSync, synchronization)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, ntpabi.SampleV1Size)}
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
