package linklocal4

import (
	"errors"
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeBase struct{ closed bool }

func (b *fakeBase) Close() error { b.closed = true; return nil }
func (b *fakeBase) Readiness() nscore.Readiness {
	if b.closed {
		return nscore.ReadyClosed
	}
	return 0
}
func (*fakeBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeNamespace struct {
	next     nscore.Resource
	progress nscore.Progress
	failure  error
	request  linklocalns.Request
	calls    int
}

func (n *fakeNamespace) TryClaim(request linklocalns.Request) (nscore.Resource, nscore.Progress, error) {
	n.request = request
	n.calls++
	return n.next, n.progress, n.failure
}

type fakeClaim struct {
	value       linklocalns.Result
	result      linklocalns.ResultState
	failure     error
	canceled    bool
	released    bool
	closed      bool
	closeCalls  int
	cancelCalls int
}

func (c *fakeClaim) Close() error {
	c.closed = true
	c.closeCalls++
	return nil
}
func (c *fakeClaim) Cancel() error {
	c.canceled = true
	c.cancelCalls++
	return nil
}
func (c *fakeClaim) Release() error { c.released = true; return nil }
func (c *fakeClaim) Readiness() nscore.Readiness {
	if c.closed {
		return nscore.ReadyClosed
	}
	return nscore.ReadyLinkLocal4Result
}
func (c *fakeClaim) TryResult() (linklocalns.Result, linklocalns.ResultState, error) {
	return c.value, c.result, c.failure
}

func TestInstanceLinkLocal4ExactKindLifecycle(t *testing.T) {
	request := linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}
	claim := &fakeClaim{value: validResult(t), result: linklocalns.ResultReady}
	backend := &fakeNamespace{next: claim, progress: nscore.ProgressInProgress}
	state, manager, instance, base := attachState(t, backend, 4)

	handle, progress, err := Claim(state, state.NamespaceHandle(), request)
	if err != nil || progress != nscore.ProgressInProgress || handle == 0 || backend.request != request {
		t.Fatalf("Claim = %v, %v, %v, request=%+v", handle, progress, err, backend.request)
	}
	if _, err := state.Resources().Lookup(handle, resource.KindDHCPv4Lease); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind lookup = %v", err)
	}
	got, result, err := Result(state, handle)
	if err != nil || result != linklocalns.ResultReady || got != claim.value {
		t.Fatalf("Result = %+v, %v, %v", got, result, err)
	}
	if err := Cancel(state, handle); err != nil || !claim.canceled {
		t.Fatalf("Cancel = %v, canceled=%v", err, claim.canceled)
	}
	if err := Release(state, handle); err != nil || !claim.released {
		t.Fatalf("Release = %v, released=%v", err, claim.released)
	}
	if err := state.CloseHandle(handle, resource.KindLinkLocal4Claim); err != nil || !claim.closed {
		t.Fatalf("CloseHandle = %v, closed=%v", err, claim.closed)
	}
	if _, _, err := Result(state, handle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale result = %v", err)
	}
	if err := manager.Detach(instance); err != nil || !base.closed {
		t.Fatalf("Detach = %v, base closed=%v", err, base.closed)
	}
}

func TestClaimRejectsInvalidBackendResourcesAndRollsBackRegistration(t *testing.T) {
	var typedNil *fakeClaim
	backend := &fakeNamespace{next: typedNil, progress: nscore.ProgressDone}
	state, manager, instance, _ := attachState(t, backend, 4)
	if handle, progress, err := Claim(state, state.NamespaceHandle(), linklocalns.Request{}); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureIO {
		t.Fatalf("typed nil claim = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("typed nil published: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
	_ = manager.Detach(instance)

	claim := &fakeClaim{value: validResult(t), result: linklocalns.ResultReady}
	backend = &fakeNamespace{next: claim, progress: 99}
	state, manager, instance, _ = attachState(t, backend, 4)
	if handle, _, err := Claim(state, state.NamespaceHandle(), linklocalns.Request{}); handle != 0 || failureOf(err) != nscore.FailureIO || !claim.closed {
		t.Fatalf("invalid progress = %v, %v, closed=%v", handle, err, claim.closed)
	}
	_ = manager.Detach(instance)

	claim = &fakeClaim{value: validResult(t), result: linklocalns.ResultReady}
	backend = &fakeNamespace{next: claim, progress: nscore.ProgressDone}
	state, manager, instance, _ = attachState(t, backend, 1)
	defer manager.Detach(instance)
	if handle, progress, err := Claim(state, state.NamespaceHandle(), linklocalns.Request{}); handle != 0 || progress != 0 || !errors.Is(err, readiness.ErrLimit) || !claim.closed || claim.closeCalls != 1 {
		t.Fatalf("registration rollback = %v, %v, %v, closed=%v calls=%d", handle, progress, err, claim.closed, claim.closeCalls)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("rollback retained state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
}

func TestBackendFailuresAndMalformedResultsClearOutputs(t *testing.T) {
	backend := &fakeNamespace{progress: nscore.ProgressDone, failure: nscore.Fail(nscore.FailureTemporary, errors.New("claim"))}
	state, manager, instance, _ := attachState(t, backend, 4)
	if handle, progress, err := Claim(state, state.NamespaceHandle(), linklocalns.Request{}); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTemporary {
		t.Fatalf("failed claim = %v, %v, %v", handle, progress, err)
	}
	_ = manager.Detach(instance)

	claim := &fakeClaim{value: validResult(t), result: linklocalns.ResultWouldBlock}
	backend = &fakeNamespace{next: claim, progress: nscore.ProgressDone}
	state, manager, instance, _ = attachState(t, backend, 4)
	defer manager.Detach(instance)
	handle, _, err := Claim(state, state.NamespaceHandle(), linklocalns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if got, result, err := Result(state, handle); err != nil || result != linklocalns.ResultWouldBlock || got != (linklocalns.Result{}) {
		t.Fatalf("would block = %+v, %v, %v", got, result, err)
	}
	claim.failure = nscore.Fail(nscore.FailureTemporary, errors.New("result"))
	claim.result = linklocalns.ResultReady
	if got, result, err := Result(state, handle); failureOf(err) != nscore.FailureTemporary || got != (linklocalns.Result{}) || result != 0 {
		t.Fatalf("failed result = %+v, %v, %v", got, result, err)
	}
	claim.failure = nil
	claim.value = linklocalns.Result{}
	if got, result, err := Result(state, handle); failureOf(err) != nscore.FailureIO || got != (linklocalns.Result{}) || result != 0 {
		t.Fatalf("invalid ready result = %+v, %v, %v", got, result, err)
	}
	claim.value = validResult(t)
	claim.result = 99
	if got, result, err := Result(state, handle); failureOf(err) != nscore.FailureIO || got != (linklocalns.Result{}) || result != 0 {
		t.Fatalf("invalid result state = %+v, %v, %v", got, result, err)
	}
}

func TestDetachClosesLiveLinkLocal4Claim(t *testing.T) {
	claim := &fakeClaim{value: validResult(t), result: linklocalns.ResultReady}
	backend := &fakeNamespace{next: claim, progress: nscore.ProgressInProgress}
	state, manager, instance, _ := attachState(t, backend, 4)
	if _, _, err := Claim(state, state.NamespaceHandle(), linklocalns.Request{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Detach(instance); err != nil || !claim.closed || claim.closeCalls != 1 {
		t.Fatalf("Detach = %v, closed=%v calls=%d", err, claim.closed, claim.closeCalls)
	}
}

func attachState(t testing.TB, backend linklocalns.Namespace, maxRegistrations int) (*instancecore.State, *instancecore.Manager, *wago.Instance, *fakeBase) {
	t.Helper()
	base := new(fakeBase)
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: maxRegistrations}
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(base, nscore.Service{Key: linklocalns.ServiceKey, Value: backend})
	}
	manager, err := instancecore.NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("state not attached")
	}
	return state, manager, instance, base
}

func validResult(t testing.TB) linklocalns.Result {
	t.Helper()
	result := linklocalns.Result{
		Address: netip.MustParseAddr("169.254.42.7"), Subnet: linklocalns.Prefix,
		Conflicts: 2, Applied: true,
	}
	if !result.Valid() {
		t.Fatal("invalid result fixture")
	}
	return result
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func BenchmarkResultReady(b *testing.B) {
	claim := &fakeClaim{value: validResult(b), result: linklocalns.ResultReady}
	backend := &fakeNamespace{next: claim, progress: nscore.ProgressDone}
	state, manager, instance, _ := attachState(b, backend, 4)
	defer manager.Detach(instance)
	handle, _, err := Claim(state, state.NamespaceHandle(), linklocalns.Request{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _, _ = Result(state, handle)
	}
}
