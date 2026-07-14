package dhcpv6

import (
	"errors"
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
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
	operations dhcpns.Operations
	next       nscore.Resource
	progress   nscore.Progress
	failure    error
}

func (n *fakeNamespace) Operations() dhcpns.Operations { return n.operations }
func (n *fakeNamespace) TryAcquire() (nscore.Resource, nscore.Progress, error) {
	return n.next, n.progress, n.failure
}

type fakeLease struct {
	configuration dhcpns.Configuration
	result        dhcpns.ResultState
	failure       error
	canceled      bool
	closed        bool
	closeCalls    int
}

func (l *fakeLease) Close() error {
	l.closed = true
	l.closeCalls++
	return nil
}
func (l *fakeLease) Cancel() error {
	l.canceled = true
	return nil
}
func (l *fakeLease) Readiness() nscore.Readiness {
	if l.closed {
		return nscore.ReadyClosed
	}
	return nscore.ReadyDHCPv6Result
}
func (l *fakeLease) TryResult() (dhcpns.Configuration, dhcpns.ResultState, error) {
	return l.configuration, l.result, l.failure
}

func TestInstanceDHCPv6ExactKindLifecycleAndUnsupportedValidation(t *testing.T) {
	lease := &fakeLease{configuration: validConfiguration(t), result: dhcpns.ResultReady}
	adapter := &fakeNamespace{operations: dhcpns.SupportedOperations, next: lease, progress: nscore.ProgressInProgress}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: adapter})
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
	state, _ := manager.ForInstance(instance)
	namespaceHandle := state.NamespaceHandle()

	operations, err := Operations(state, namespaceHandle)
	if err != nil || operations != dhcpns.SupportedOperations {
		t.Fatalf("Operations = %v, %v", operations, err)
	}
	if _, _, err := Start(state, resource.Handle(1), dhcpns.OperationRenew); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("unsupported operation skipped namespace validation: %v", err)
	}
	if _, _, err := Start(state, namespaceHandle, dhcpns.OperationRenew); failureOf(err) != nscore.FailureNotSupported {
		t.Fatalf("Renew = %v", err)
	}

	handle, progress, err := Start(state, namespaceHandle, dhcpns.OperationAcquire)
	if err != nil || progress != nscore.ProgressInProgress || handle == 0 {
		t.Fatalf("Start = %v, %v, %v", handle, progress, err)
	}
	if _, err := state.Resources().Lookup(handle, resource.KindDNSQuery); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind lookup = %v", err)
	}
	configuration, result, err := Result(state, handle)
	if err != nil || result != dhcpns.ResultReady || !configuration.Valid() {
		t.Fatalf("Result = %+v, %v, %v", configuration, result, err)
	}
	if err := Cancel(state, handle); err != nil || !lease.canceled {
		t.Fatalf("Cancel = %v, canceled=%v", err, lease.canceled)
	}
	if err := state.CloseHandle(handle, resource.KindDHCPv6Lease); err != nil || !lease.closed {
		t.Fatalf("CloseHandle = %v, closed=%v", err, lease.closed)
	}
	if _, _, err := Result(state, handle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale result = %v", err)
	}
}

func TestStartRejectsTypedNilBackendResource(t *testing.T) {
	var lease *fakeLease
	adapter := &fakeNamespace{operations: dhcpns.SupportedOperations, next: lease, progress: nscore.ProgressDone}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: adapter})
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
	state, _ := manager.ForInstance(instance)
	if handle, progress, err := Start(state, state.NamespaceHandle(), dhcpns.OperationAcquire); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureIO {
		t.Fatalf("typed nil backend start = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("typed nil backend resource published: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
}

func TestStartClosesInvalidBackendResource(t *testing.T) {
	lease := &fakeLease{configuration: validConfiguration(t), result: dhcpns.ResultReady}
	adapter := &fakeNamespace{operations: dhcpns.SupportedOperations, next: lease, progress: 99}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: adapter})
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
	state, _ := manager.ForInstance(instance)
	if handle, progress, err := Start(state, state.NamespaceHandle(), dhcpns.OperationAcquire); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureIO || !lease.closed || lease.closeCalls != 1 {
		t.Fatalf("invalid backend start = %v, %v, %v, closed=%v calls=%d", handle, progress, err, lease.closed, lease.closeCalls)
	}
}

func TestBackendFailuresAndInvalidResultsClearOutputs(t *testing.T) {
	cause := errors.New("backend failed")
	failure := nscore.Fail(nscore.FailureTemporary, cause)
	failedLease := &fakeLease{configuration: validConfiguration(t), result: dhcpns.ResultReady}
	adapter := &fakeNamespace{
		operations: dhcpns.SupportedOperations | dhcpns.Operations(1<<31),
		next:       failedLease, progress: nscore.ProgressDone, failure: failure,
	}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: adapter})
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
	state, _ := manager.ForInstance(instance)

	if operations, err := Operations(state, state.NamespaceHandle()); failureOf(err) != nscore.FailureIO || operations != 0 {
		t.Fatalf("invalid operations = %v, %v", operations, err)
	}
	adapter.operations = dhcpns.SupportedOperations
	resourcesBefore := state.Resources().Len()
	readinessBefore := state.Readiness().Snapshot()
	if handle, progress, err := Start(state, state.NamespaceHandle(), dhcpns.OperationAcquire); failureOf(err) != nscore.FailureTemporary || !errors.Is(err, cause) || handle != 0 || progress != 0 {
		t.Fatalf("failed start = %v, %v, %v", handle, progress, err)
	}
	if failedLease.closeCalls != 1 || state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("failed start published state: closes=%d resources=%d readiness=%+v", failedLease.closeCalls, state.Resources().Len(), state.Readiness().Snapshot())
	}
	var typedNil *fakeLease
	adapter.next = typedNil
	if handle, progress, err := Start(state, state.NamespaceHandle(), dhcpns.OperationAcquire); failureOf(err) != nscore.FailureTemporary || handle != 0 || progress != 0 {
		t.Fatalf("typed-nil failed start = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("typed-nil failed start published state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
	lease := &fakeLease{configuration: validConfiguration(t), result: dhcpns.ResultReady, failure: failure}
	adapter.next, adapter.failure = lease, nil
	handle, progress, err := Start(state, state.NamespaceHandle(), dhcpns.OperationAcquire)
	if err != nil || handle == 0 || progress != nscore.ProgressDone {
		t.Fatalf("successful start = %v, %v, %v", handle, progress, err)
	}
	if configuration, result, err := Result(state, handle); !errors.Is(err, failure) || configuration != (dhcpns.Configuration{}) || result != 0 {
		t.Fatalf("failed result = %+v, %v, %v", configuration, result, err)
	}
	lease.failure = nil
	lease.result = dhcpns.ResultWouldBlock
	if configuration, result, err := Result(state, handle); err != nil || configuration != (dhcpns.Configuration{}) || result != dhcpns.ResultWouldBlock {
		t.Fatalf("would-block result = %+v, %v, %v", configuration, result, err)
	}
	lease.result = dhcpns.ResultReady
	lease.configuration = dhcpns.Configuration{}
	if configuration, result, err := Result(state, handle); failureOf(err) != nscore.FailureIO || configuration != (dhcpns.Configuration{}) || result != 0 {
		t.Fatalf("invalid configuration = %+v, %v, %v", configuration, result, err)
	}
	lease.configuration = validConfiguration(t)
	lease.configuration.PrefixRenewalSeconds = 1
	if configuration, result, err := Result(state, handle); failureOf(err) != nscore.FailureIO || configuration != (dhcpns.Configuration{}) || result != 0 {
		t.Fatalf("orphan prefix timers = %+v, %v, %v", configuration, result, err)
	}
	lease.configuration = validConfiguration(t)
	lease.result = 99
	if configuration, result, err := Result(state, handle); failureOf(err) != nscore.FailureIO || configuration != (dhcpns.Configuration{}) || result != 0 {
		t.Fatalf("invalid result state = %+v, %v, %v", configuration, result, err)
	}
}

func validConfiguration(t testing.TB) dhcpns.Configuration {
	t.Helper()
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
	if !configuration.Valid() {
		t.Fatal("invalid fixture")
	}
	return configuration
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}
