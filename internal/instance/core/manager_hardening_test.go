package core

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type hardeningNamespace struct {
	closed   atomic.Int32
	closeErr error
}

func (n *hardeningNamespace) Close() error {
	n.closed.Add(1)
	return n.closeErr
}

func (*hardeningNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (*hardeningNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*hardeningNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*hardeningNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*hardeningNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*hardeningNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type hardeningInstanceHostModule struct {
	instance *wago.Instance
}

func (*hardeningInstanceHostModule) Memory() []byte { return nil }
func (m *hardeningInstanceHostModule) Instance() *wago.Instance {
	return m.instance
}

type hardeningMemoryOnlyModule struct{}

func (*hardeningMemoryOnlyModule) Memory() []byte { return nil }

func TestDetachWaitsForInProgressAttachAndClosesPublishedState(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := new(hardeningNamespace)
	config := DefaultConfig()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		close(entered)
		<-release
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	attachDone := make(chan error, 1)
	go func() { attachDone <- manager.Attach(instance) }()
	<-entered

	detachDone := make(chan error, 1)
	go func() { detachDone <- manager.Detach(instance) }()
	select {
	case err := <-detachDone:
		t.Fatalf("Detach returned before the in-progress Attach published state: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-attachDone; err != nil {
		t.Fatalf("Attach error = %v", err)
	}
	if err := <-detachDone; err != nil {
		t.Fatalf("Detach error = %v", err)
	}
	if manager.Len() != 0 || backend.closed.Load() != 1 {
		t.Fatalf("post-detach manager len=%d backend closes=%d", manager.Len(), backend.closed.Load())
	}
}

func TestConcurrentAttachRejectsInProgressDuplicateBeforeBackendConstruction(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var factoryCalls atomic.Int32
	config := DefaultConfig()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		if factoryCalls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return new(hardeningNamespace), nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	firstDone := make(chan error, 1)
	go func() { firstDone <- manager.Attach(instance) }()
	<-entered

	secondErr := manager.Attach(instance)
	close(release)
	firstErr := <-firstDone
	detachErr := manager.Detach(instance)
	if firstErr != nil {
		t.Fatalf("first Attach error = %v", firstErr)
	}
	if !errors.Is(secondErr, ErrAlreadyAttached) {
		t.Fatalf("second Attach error = %v, want ErrAlreadyAttached", secondErr)
	}
	if factoryCalls.Load() != 1 {
		t.Fatalf("namespace factory calls = %d, want 1", factoryCalls.Load())
	}
	if detachErr != nil {
		t.Fatal(detachErr)
	}
}

func TestAttachPanicRetiresPendingStateAndAllowsRetry(t *testing.T) {
	var calls atomic.Int32
	var failedAccount *quota.Account
	backend := new(hardeningNamespace)
	config := DefaultConfig()
	config.NamespaceFactory = func(_ *policy.Policy, account *quota.Account) (nscore.Namespace, error) {
		if calls.Add(1) == 1 {
			failedAccount = account
			panic("factory panic")
		}
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = manager.Attach(instance)
	}()
	if recovered == nil {
		t.Fatal("Attach did not propagate namespace factory panic")
	}
	if manager.Len() != 0 {
		t.Fatal("panicking Attach published state")
	}
	if failedAccount == nil {
		t.Fatal("panicking factory did not receive quota account")
	}
	usage, closed := failedAccount.Snapshot()
	if !closed || usage != (quota.Usage{}) {
		t.Fatalf("panicking Attach quota usage=%+v closed=%v", usage, closed)
	}
	if err := manager.Attach(instance); err != nil {
		t.Fatalf("retry Attach error = %v", err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("retry backend closes = %d, want 1", backend.closed.Load())
	}
}

func TestNamespaceHandleIsClearedWhenBackendCloseReportsError(t *testing.T) {
	closeErr := errors.New("backend close failed")
	backend := &hardeningNamespace{closeErr: closeErr}
	config := DefaultConfig()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	handle := state.NamespaceHandle()
	if err := state.CloseHandle(handle, resource.KindNamespace); !errors.Is(err, closeErr) {
		t.Fatalf("CloseHandle error = %v, want %v", err, closeErr)
	}
	if state.NamespaceHandle() != 0 {
		t.Fatalf("NamespaceHandle = %v after retired handle", state.NamespaceHandle())
	}
	if _, err := state.Resources().Lookup(handle, resource.KindNamespace); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("retired namespace lookup error = %v, want ErrBadHandle", err)
	}
	usage, closed := state.Quotas().Snapshot()
	if closed || usage != (quota.Usage{}) {
		t.Fatalf("post-close quota usage=%+v closed=%v", usage, closed)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
}

func TestFromHostFailsClosedForUnsupportedAndTypedNilModules(t *testing.T) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, _ := manager.ForInstance(instance)
	valid := &hardeningInstanceHostModule{instance: instance}
	if got, ok := manager.FromHost(valid); !ok || got != state {
		t.Fatalf("valid host resolved state=%p ok=%v, want %p", got, ok, state)
	}
	if got, ok := manager.FromHost(new(hardeningMemoryOnlyModule)); ok || got != nil {
		t.Fatalf("HostModule-only caller resolved state=%p ok=%v", got, ok)
	}
	var typedNil *hardeningInstanceHostModule
	if got, ok := manager.FromHost(typedNil); ok || got != nil {
		t.Fatalf("typed-nil caller resolved state=%p ok=%v", got, ok)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
}

func TestLookupNamespaceReturnsExactBackendAndFailsClosedAfterRetirement(t *testing.T) {
	backend := new(hardeningNamespace)
	config := DefaultConfig()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, _ := manager.ForInstance(instance)
	handle := state.NamespaceHandle()
	got, err := state.LookupNamespace(handle)
	if err != nil || got != backend {
		t.Fatalf("LookupNamespace = %p, %v; want %p, nil", got, err, backend)
	}
	if err := state.CloseHandle(handle, resource.KindNamespace); err != nil {
		t.Fatal(err)
	}
	if _, err := state.LookupNamespace(handle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("retired LookupNamespace error = %v, want ErrBadHandle", err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
}
