package dhcpv4

import (
	"errors"
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
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
	request  dhcpns.Request
	calls    int
}

func (n *fakeNamespace) TryAcquire(request dhcpns.Request) (nscore.Resource, nscore.Progress, error) {
	n.request = request
	n.calls++
	return n.next, n.progress, n.failure
}

type fakeLease struct {
	lease       dhcpns.Lease
	result      dhcpns.ResultState
	failure     error
	canceled    bool
	released    bool
	closed      bool
	closeCalls  int
	cancelCalls int
}

func (l *fakeLease) Close() error {
	l.closed = true
	l.closeCalls++
	return nil
}
func (l *fakeLease) Cancel() error {
	l.canceled = true
	l.cancelCalls++
	return nil
}
func (l *fakeLease) Release() error { l.released = true; return nil }
func (l *fakeLease) Readiness() nscore.Readiness {
	if l.closed {
		return nscore.ReadyClosed
	}
	return nscore.ReadyDHCPv4Lease
}
func (l *fakeLease) TryResult() (dhcpns.Lease, dhcpns.ResultState, error) {
	return l.lease, l.result, l.failure
}

func TestInstanceDHCPv4ExactKindLifecycle(t *testing.T) {
	request := dhcpns.Request{RequestedAddr: netip.MustParseAddr("192.0.2.20"), HostnameLength: 4, ClientIDLength: 3}
	copy(request.Hostname[:], "host")
	copy(request.ClientID[:], "id1")
	lease := &fakeLease{lease: validLease(t), result: dhcpns.ResultReady}
	backend := &fakeNamespace{next: lease, progress: nscore.ProgressInProgress}
	state, manager, instance, base := attachState(t, backend, 4)

	handle, progress, err := Acquire(state, state.NamespaceHandle(), request)
	if err != nil || progress != nscore.ProgressInProgress || handle == 0 || backend.request != request {
		t.Fatalf("Acquire = %v, %v, %v, request=%+v", handle, progress, err, backend.request)
	}
	if _, err := state.Resources().Lookup(handle, resource.KindLinkLocal4Claim); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind lookup = %v", err)
	}
	got, result, err := Result(state, handle)
	if err != nil || result != dhcpns.ResultReady || got != lease.lease {
		t.Fatalf("Result = %+v, %v, %v", got, result, err)
	}
	if err := Cancel(state, handle); err != nil || !lease.canceled {
		t.Fatalf("Cancel = %v, canceled=%v", err, lease.canceled)
	}
	if err := Release(state, handle); err != nil || !lease.released {
		t.Fatalf("Release = %v, released=%v", err, lease.released)
	}
	if err := state.CloseHandle(handle, resource.KindDHCPv4Lease); err != nil || !lease.closed {
		t.Fatalf("CloseHandle = %v, closed=%v", err, lease.closed)
	}
	if _, _, err := Result(state, handle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale result = %v", err)
	}
	if err := manager.Detach(instance); err != nil || !base.closed {
		t.Fatalf("Detach = %v, base closed=%v", err, base.closed)
	}
}

func TestAcquireRejectsInvalidBackendResourcesAndRollsBackRegistration(t *testing.T) {
	var typedNil *fakeLease
	backend := &fakeNamespace{next: typedNil, progress: nscore.ProgressDone}
	state, manager, instance, _ := attachState(t, backend, 4)
	if handle, progress, err := Acquire(state, state.NamespaceHandle(), dhcpns.Request{}); handle != 0 || progress != nscore.ProgressDone || failureOf(err) != nscore.FailureIO {
		t.Fatalf("typed nil acquire = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("typed nil published: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
	_ = manager.Detach(instance)

	lease := &fakeLease{lease: validLease(t), result: dhcpns.ResultReady}
	backend = &fakeNamespace{next: lease, progress: 99}
	state, manager, instance, _ = attachState(t, backend, 4)
	if handle, _, err := Acquire(state, state.NamespaceHandle(), dhcpns.Request{}); handle != 0 || failureOf(err) != nscore.FailureIO || !lease.closed {
		t.Fatalf("invalid progress = %v, %v, closed=%v", handle, err, lease.closed)
	}
	_ = manager.Detach(instance)

	lease = &fakeLease{lease: validLease(t), result: dhcpns.ResultReady}
	backend = &fakeNamespace{next: lease, progress: nscore.ProgressDone}
	state, manager, instance, _ = attachState(t, backend, 1)
	defer manager.Detach(instance)
	if handle, progress, err := Acquire(state, state.NamespaceHandle(), dhcpns.Request{}); handle != 0 || progress != 0 || !errors.Is(err, readiness.ErrLimit) || !lease.closed || lease.closeCalls != 1 {
		t.Fatalf("registration rollback = %v, %v, %v, closed=%v calls=%d", handle, progress, err, lease.closed, lease.closeCalls)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("rollback retained state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
}

func TestResultRejectsMalformedBackendStates(t *testing.T) {
	lease := &fakeLease{result: dhcpns.ResultWouldBlock}
	backend := &fakeNamespace{next: lease, progress: nscore.ProgressDone}
	state, manager, instance, _ := attachState(t, backend, 4)
	defer manager.Detach(instance)
	handle, _, err := Acquire(state, state.NamespaceHandle(), dhcpns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if got, result, err := Result(state, handle); err != nil || result != dhcpns.ResultWouldBlock || got != (dhcpns.Lease{}) {
		t.Fatalf("would block = %+v, %v, %v", got, result, err)
	}
	lease.result = dhcpns.ResultReady
	if got, result, err := Result(state, handle); failureOf(err) != nscore.FailureIO || got != (dhcpns.Lease{}) || result != 0 {
		t.Fatalf("invalid ready lease = %+v, %v, %v", got, result, err)
	}
	lease.lease = validLease(t)
	lease.result = 99
	if got, result, err := Result(state, handle); failureOf(err) != nscore.FailureIO || got != (dhcpns.Lease{}) || result != 0 {
		t.Fatalf("invalid result state = %+v, %v, %v", got, result, err)
	}
}

func TestDetachClosesLiveDHCPv4Lease(t *testing.T) {
	lease := &fakeLease{lease: validLease(t), result: dhcpns.ResultReady}
	backend := &fakeNamespace{next: lease, progress: nscore.ProgressInProgress}
	state, manager, instance, _ := attachState(t, backend, 4)
	if _, _, err := Acquire(state, state.NamespaceHandle(), dhcpns.Request{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Detach(instance); err != nil || !lease.closed || lease.closeCalls != 1 {
		t.Fatalf("Detach = %v, closed=%v calls=%d", err, lease.closed, lease.closeCalls)
	}
}

func attachState(t testing.TB, backend dhcpns.Namespace, maxRegistrations int) (*instancecore.State, *instancecore.Manager, *wago.Instance, *fakeBase) {
	t.Helper()
	base := new(fakeBase)
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: maxRegistrations}
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(base, nscore.Service{Key: dhcpns.ServiceKey, Value: backend})
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

func validLease(t testing.TB) dhcpns.Lease {
	t.Helper()
	lease := dhcpns.Lease{
		AssignedAddr: netip.MustParseAddr("192.0.2.20"), ServerAddr: netip.MustParseAddr("192.0.2.1"),
		RouterAddr: netip.MustParseAddr("192.0.2.1"), BroadcastAddr: netip.MustParseAddr("192.0.2.255"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, RenewalSeconds: 1800, RebindSeconds: 3150,
		DNSCount: 1, DNSServers: [dhcpns.MaxDNSServers]netip.Addr{netip.MustParseAddr("192.0.2.53")}, Applied: true,
	}
	if !lease.Valid() {
		t.Fatal("invalid lease fixture")
	}
	return lease
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func BenchmarkResultReady(b *testing.B) {
	lease := &fakeLease{lease: validLease(b), result: dhcpns.ResultReady}
	backend := &fakeNamespace{next: lease, progress: nscore.ProgressDone}
	state, manager, instance, _ := attachState(b, backend, 4)
	defer manager.Detach(instance)
	handle, _, err := Acquire(state, state.NamespaceHandle(), dhcpns.Request{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _, _ = Result(state, handle)
	}
}
