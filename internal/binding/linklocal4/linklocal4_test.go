package linklocal4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	linklocalabi "github.com/wago-org/net/internal/abi/linklocal4"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
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
	claim    *fakeClaim
	progress nscore.Progress
	calls    int
}

func (n *fakeNamespace) TryClaim(linklocalns.Request) (nscore.Resource, nscore.Progress, error) {
	n.calls++
	return n.claim, n.progress, nil
}

type fakeClaim struct {
	value    linklocalns.Result
	result   linklocalns.ResultState
	failure  error
	closed   bool
	canceled bool
	released bool
}

func (c *fakeClaim) Close() error { c.closed = true; return nil }
func (c *fakeClaim) Cancel() error {
	c.canceled = true
	return nil
}
func (c *fakeClaim) Release() error { c.released = true; return nil }
func (*fakeClaim) Readiness() nscore.Readiness {
	return nscore.ReadyLinkLocal4Result
}
func (c *fakeClaim) TryResult() (linklocalns.Result, linklocalns.ResultState, error) {
	return c.value, c.result, c.failure
}

func TestBindingsPrevalidateClaimAndPreserveResultOutputs(t *testing.T) {
	claim := &fakeClaim{result: linklocalns.ResultWouldBlock}
	backend := &fakeNamespace{claim: claim, progress: nscore.ProgressInProgress}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 480); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[480:488])
	request := linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}
	if !linklocalabi.EncodeRequestV1(host.memory, 0, request) {
		t.Fatal("encode request")
	}
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "claim"), host, namespaceHandle, 0, 8); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap claim = %v, calls=%d", status, backend.calls)
	}

	host.memory[16] = 1
	outBefore := append([]byte(nil), host.memory[64:72]...)
	if status := callBinding(t, bindingByName(t, bindings, "claim"), host, namespaceHandle, 0, 64); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory[64:72], outBefore) {
		t.Fatalf("reserved claim = %v, calls=%d", status, backend.calls)
	}
	host.memory[16] = 0
	invalidProgress := &fakeClaim{}
	backend.claim, backend.progress = invalidProgress, nscore.ProgressWouldBlock
	if status := callBinding(t, bindingByName(t, bindings, "claim"), host, namespaceHandle, 0, 64); status != guest.StatusIO || backend.calls != 1 || !invalidProgress.closed || !bytes.Equal(host.memory[64:72], outBefore) {
		t.Fatalf("invalid-progress claim = %v, calls=%d, closed=%v", status, backend.calls, invalidProgress.closed)
	}
	var typedNil *fakeClaim
	backend.claim, backend.progress = typedNil, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "claim"), host, namespaceHandle, 0, 64); status != guest.StatusIO || backend.calls != 2 || !bytes.Equal(host.memory[64:72], outBefore) {
		t.Fatalf("typed-nil claim = %v, calls=%d", status, backend.calls)
	}
	backend.claim, backend.progress = claim, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "claim"), host, namespaceHandle, 0, 64); status != guest.StatusInProgress || backend.calls != 3 {
		t.Fatalf("valid claim = %v, calls=%d", status, backend.calls)
	}
	claimHandle := binary.LittleEndian.Uint64(host.memory[64:72])

	resultBefore := append([]byte(nil), host.memory[128:128+linklocalabi.ResultV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, claimHandle, 128); status != guest.StatusAgain || !bytes.Equal(host.memory[128:128+linklocalabi.ResultV1Size], resultBefore) {
		t.Fatalf("would-block result = %v", status)
	}
	claim.failure = nscore.Fail(nscore.FailureCanceled, errors.New("canceled"))
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, claimHandle, 128); status != guest.StatusCanceled || !bytes.Equal(host.memory[128:128+linklocalabi.ResultV1Size], resultBefore) {
		t.Fatalf("failed result = %v", status)
	}
	claim.failure = nil
	claim.result = linklocalns.ResultState(255)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, claimHandle, 128); status != guest.StatusIO || !bytes.Equal(host.memory[128:128+linklocalabi.ResultV1Size], resultBefore) {
		t.Fatalf("invalid-state result = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, namespaceHandle, 128); status != guest.StatusBadHandle || !bytes.Equal(host.memory[128:128+linklocalabi.ResultV1Size], resultBefore) {
		t.Fatalf("wrong-kind result = %v", status)
	}
	claim.value = validResult(t)
	claim.result = linklocalns.ResultReady
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, claimHandle, 128); status != guest.StatusOK || binary.LittleEndian.Uint32(host.memory[160:164]) != 16 || binary.LittleEndian.Uint32(host.memory[172:176]) != 0 {
		t.Fatalf("ready result = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, claimHandle); status != guest.StatusOK || !claim.canceled {
		t.Fatalf("cancel = %v, canceled=%v", status, claim.canceled)
	}
	if status := callBinding(t, bindingByName(t, bindings, "release"), host, claimHandle); status != guest.StatusOK || !claim.released {
		t.Fatalf("release = %v, released=%v", status, claim.released)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, claimHandle); status != guest.StatusOK || !claim.closed {
		t.Fatalf("close = %v, closed=%v", status, claim.closed)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, claimHandle, 128); status != guest.StatusBadHandle {
		t.Fatalf("stale result = %v", status)
	}

	fresh := &fakeClaim{result: linklocalns.ResultWouldBlock}
	backend.claim, backend.progress = fresh, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "claim"), host, namespaceHandle, 0, 72); status != guest.StatusInProgress {
		t.Fatalf("fresh claim = %v", status)
	}
	freshHandle := binary.LittleEndian.Uint64(host.memory[72:80])
	if freshHandle == claimHandle || uint16(freshHandle) != uint16(claimHandle) {
		t.Fatalf("generation-safe slot reuse = old %v, fresh %v", claimHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "release"), host, claimHandle); status != guest.StatusBadHandle || fresh.released {
		t.Fatalf("stale release = %v, fresh released=%v", status, fresh.released)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, freshHandle, 128); status != guest.StatusAgain {
		t.Fatalf("fresh result = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, freshHandle); status != guest.StatusOK || !fresh.closed {
		t.Fatalf("close fresh = %v, closed=%v", status, fresh.closed)
	}
}

func TestResultRejectsOutOfBoundsBeforeHandleLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 32)}
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, Bindings(plugin.NewHost(manager)), "result"), host, 1, 1); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("out-of-bounds result = %v", status)
	}
}

func attachManager(t testing.TB, backend linklocalns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: linklocalns.ServiceKey, Value: backend})
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

func validResult(t testing.TB) linklocalns.Result {
	t.Helper()
	result := linklocalns.Result{Address: netip.MustParseAddr("169.254.42.7"), Subnet: linklocalns.Prefix, Conflicts: 2, Applied: true}
	if !result.Valid() {
		t.Fatal("invalid result fixture")
	}
	return result
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
	claim := &fakeClaim{value: validResult(b), result: linklocalns.ResultReady}
	manager, instance := attachManager(b, &fakeNamespace{claim: claim})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindLinkLocal4Claim, claim)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, 128)}
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
