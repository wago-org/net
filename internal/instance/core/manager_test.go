package core

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct {
	closed       atomic.Int32
	closeErr     error
	closePanic   any
	closeStarted chan struct{}
	closeRelease <-chan struct{}
	socket       namespace.UDPSocket
	listener     namespace.TCPListener
	stream       namespace.TCPStream
	query        namespace.DNSQuery
}

func (n *fakeNamespace) Close() error {
	if n.closed.Add(1) == 1 && n.closeStarted != nil {
		close(n.closeStarted)
	}
	if n.closeRelease != nil {
		<-n.closeRelease
	}
	if n.closePanic != nil {
		panic(n.closePanic)
	}
	return n.closeErr
}

func (n *fakeNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (n *fakeNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	if n.socket != nil {
		return n.socket, namespace.ProgressDone, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	if n.listener != nil {
		return n.listener, namespace.ProgressDone, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	if n.stream != nil {
		return n.stream, namespace.ProgressInProgress, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	if n.query != nil {
		return n.query, namespace.ProgressInProgress, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type fakeUDPSocket struct {
	closed atomic.Int32
	local  namespace.Endpoint
}

func (s *fakeUDPSocket) Close() error {
	s.closed.Add(1)
	return nil
}
func (s *fakeUDPSocket) Readiness() namespace.Readiness    { return namespace.ReadyWritable }
func (s *fakeUDPSocket) LocalEndpoint() namespace.Endpoint { return s.local }
func (s *fakeUDPSocket) TryReceive([]byte) (namespace.DatagramResult, error) {
	return namespace.DatagramResult{}, nil
}
func (s *fakeUDPSocket) TrySend([]byte, namespace.Endpoint) (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}

type fakeTCPListener struct {
	closed   atomic.Int32
	local    namespace.Endpoint
	accepted namespace.TCPStream
}

func (l *fakeTCPListener) Close() error {
	l.closed.Add(1)
	return nil
}
func (l *fakeTCPListener) Readiness() namespace.Readiness    { return namespace.ReadyAccept }
func (l *fakeTCPListener) LocalEndpoint() namespace.Endpoint { return l.local }
func (l *fakeTCPListener) TryAccept() (namespace.TCPStream, namespace.Progress, error) {
	if l.accepted == nil {
		return nil, namespace.ProgressWouldBlock, nil
	}
	stream := l.accepted
	l.accepted = nil
	return stream, namespace.ProgressDone, nil
}

type fakeTCPStream struct {
	closed  atomic.Int32
	local   namespace.Endpoint
	remote  namespace.Endpoint
	input   []byte
	written []byte
}

func (s *fakeTCPStream) Close() error {
	s.closed.Add(1)
	return nil
}
func (s *fakeTCPStream) Readiness() namespace.Readiness {
	return namespace.ReadyConnected | namespace.ReadyReadable | namespace.ReadyWritable
}
func (s *fakeTCPStream) LocalEndpoint() namespace.Endpoint  { return s.local }
func (s *fakeTCPStream) RemoteEndpoint() namespace.Endpoint { return s.remote }
func (s *fakeTCPStream) TryFinishConnect() (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}
func (s *fakeTCPStream) TryRead(dst []byte) (namespace.IOResult, error) {
	if len(s.input) == 0 {
		return namespace.IOResult{State: namespace.IOWouldBlock}, nil
	}
	n := copy(dst, s.input)
	s.input = s.input[n:]
	return namespace.IOResult{Bytes: n, State: namespace.IOReady}, nil
}
func (s *fakeTCPStream) TryWrite(src []byte) (namespace.IOResult, error) {
	if len(src) == 0 {
		return namespace.IOResult{State: namespace.IOReady}, nil
	}
	n := min(3, len(src))
	s.written = append(s.written, src[:n]...)
	return namespace.IOResult{Bytes: n, State: namespace.IOReady}, nil
}
func (s *fakeTCPStream) TryShutdownWrite() (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}

type fakeDNSQuery struct {
	closed   atomic.Int32
	canceled atomic.Int32
	records  []namespace.DNSRecord
	failure  error
}

func (q *fakeDNSQuery) Close() error {
	q.closed.Add(1)
	return nil
}
func (q *fakeDNSQuery) Cancel() error {
	q.canceled.Add(1)
	q.failure = namespace.Fail(namespace.FailureCanceled, nil)
	return nil
}
func (q *fakeDNSQuery) Readiness() namespace.Readiness {
	if q.failure != nil {
		return namespace.ReadyError
	}
	if len(q.records) != 0 {
		return namespace.ReadyDNSResult
	}
	return 0
}
func (q *fakeDNSQuery) TryNext() (namespace.DNSRecord, namespace.DNSNext, error) {
	if q.failure != nil {
		return namespace.DNSRecord{}, 0, q.failure
	}
	if len(q.records) == 0 {
		return namespace.DNSRecord{}, namespace.DNSNextWouldBlock, nil
	}
	record := q.records[0]
	q.records = q.records[1:]
	return record, namespace.DNSNextReady, nil
}

type fakePollable struct{}

func (fakePollable) Close() error                   { return nil }
func (fakePollable) Readiness() namespace.Readiness { return namespace.ReadyReadable }

func TestLifecycleHooksAttachAndDetachExactInstance(t *testing.T) {
	backend := new(fakeNamespace)
	config := DefaultConfig()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(backend)
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.AfterInstantiate(nil, instance); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.ForInstance(instance); !ok {
		t.Fatal("lifecycle hook did not publish exact instance state")
	}
	if err := manager.AfterInstantiate(nil, instance); !errors.Is(err, ErrAlreadyAttached) {
		t.Fatalf("duplicate AfterInstantiate = %v", err)
	}
	manager.BeforeClose(nil)
	if _, ok := manager.ForInstance(instance); !ok {
		t.Fatal("nil close context detached live instance")
	}
	manager.BeforeClose(&wago.InstanceContext{Instance: instance})
	if _, ok := manager.ForInstance(instance); ok {
		t.Fatal("BeforeClose retained exact instance state")
	}
	manager.BeforeClose(&wago.InstanceContext{Instance: instance})
	if backend.closed.Load() != 1 {
		t.Fatalf("backend close calls = %d, want 1", backend.closed.Load())
	}
}

func TestLookupNamespaceReturnsOnlyExactBackendNeutralOwners(t *testing.T) {
	if _, err := (*State)(nil).LookupNamespace(1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil state lookup = %v", err)
	}
	base := new(fakeNamespace)
	service := new(int)
	config := DefaultConfig()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(base, nscore.Service{Key: "test", Value: service})
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
	backend, err := state.LookupNamespace(state.NamespaceHandle())
	if err != nil {
		t.Fatal(err)
	}
	if got := nscore.ResolveNamespaceBase(backend); got != base {
		t.Fatalf("resolved base = %T %p, want %p", got, got, base)
	}
	owned := &ownedNamespace{Namespace: backend}
	if owned.NamespaceBackend() != backend || (*ownedNamespace)(nil).NamespaceBackend() != nil {
		t.Fatal("owned namespace backend facade changed ownership")
	}

	direct := new(fakeNamespace)
	directHandle, err := state.Resources().Add(resource.KindNamespace, direct)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := state.LookupNamespace(directHandle); err != nil || got != direct {
		t.Fatalf("direct namespace lookup = %T %v", got, err)
	}
	invalidHandle, err := state.Resources().Add(resource.KindNamespace, fakePollable{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.LookupNamespace(invalidHandle); !errors.Is(err, ErrInvalidBackendResult) {
		t.Fatalf("invalid namespace lookup = %v", err)
	}
	nilOwnedHandle, err := state.Resources().Add(resource.KindNamespace, &ownedNamespace{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.LookupNamespace(nilOwnedHandle); !errors.Is(err, ErrInvalidBackendResult) {
		t.Fatalf("nil owned namespace lookup = %v", err)
	}
	if _, err := state.LookupNamespace(resource.Handle(^uint64(0))); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("unknown namespace lookup = %v", err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	if _, err := state.LookupNamespace(state.NamespaceHandle()); !errors.Is(err, resource.ErrClosed) {
		t.Fatalf("closed namespace lookup = %v", err)
	}
}

type panicInstanceHost struct {
	instance *wago.Instance
}

func (h *panicInstanceHost) Memory() []byte {
	if h == nil {
		panic("typed-nil Memory call")
	}
	return nil
}

func (h *panicInstanceHost) Instance() *wago.Instance {
	if h == nil {
		panic("typed-nil Instance call")
	}
	return h.instance
}

type unsupportedHost struct{}

func (unsupportedHost) Memory() []byte { return nil }

func TestManagerReadinessIsRightSizedToResourceQuota(t *testing.T) {
	config := DefaultConfig()
	config.Limits.Resources = 2
	config.Readiness.MaxRegistrations = 16
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	if manager.readiness.MaxRegistrations != 2 {
		t.Fatalf("right-sized registrations = %d, want 2", manager.readiness.MaxRegistrations)
	}
	config.Limits.Resources = 0
	manager, err = NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	if manager.readiness.MaxRegistrations != 1 {
		t.Fatalf("zero-resource registrations = %d, want 1", manager.readiness.MaxRegistrations)
	}
}

func TestManagerConfigurationIsValidatedAndPolicyIsImmutable(t *testing.T) {
	invalid := DefaultConfig()
	invalid.Readiness.MaxRegistrations = 0
	if _, err := NewManagerConfigured(invalid); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid readiness error = %v", err)
	}
	invalid = DefaultConfig()
	invalid.Policy.Rules = []policy.Rule{{}}
	if _, err := NewManagerConfigured(invalid); !errors.Is(err, policy.ErrInvalidRule) {
		t.Fatalf("invalid policy error = %v", err)
	}

	prefix := netip.MustParsePrefix("192.0.2.0/24")
	config := DefaultConfig()
	config.Policy.Rules = []policy.Rule{{
		Action:     policy.ActionAllow,
		Transports: []policy.Transport{policy.TransportUDP},
		Directions: []policy.Direction{policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{prefix},
	}}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Policy.Rules[0].Action = policy.ActionDeny
	config.Policy.Rules[0].Prefixes[0] = netip.MustParsePrefix("198.51.100.0/24")
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok || !state.Policy().CheckEndpoint(policy.OperationUDPSend, netip.MustParseAddr("192.0.2.1"), 53) {
		t.Fatal("compiled policy changed after caller mutation")
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
}

func TestManagerFromHostRejectsTypedNilAndUnsupportedModules(t *testing.T) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	want, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}

	var typedNil *panicInstanceHost
	if state, ok := manager.FromHost(typedNil); ok || state != nil {
		t.Fatalf("typed-nil host resolved state=%p ok=%v", state, ok)
	}
	if state, ok := manager.FromHost(unsupportedHost{}); ok || state != nil {
		t.Fatalf("unsupported host resolved state=%p ok=%v", state, ok)
	}
	if state, ok := manager.FromHost(&panicInstanceHost{instance: instance}); !ok || state != want {
		t.Fatalf("valid host resolved state=%p ok=%v, want %p", state, ok, want)
	}
	if state, ok := manager.FromHost(nil); ok || state != nil {
		t.Fatalf("nil host resolved state=%p ok=%v", state, ok)
	}
	var nilManager *Manager
	if state, ok := nilManager.FromHost(&panicInstanceHost{instance: instance}); ok || state != nil {
		t.Fatalf("nil manager resolved state=%p ok=%v", state, ok)
	}
	if state, ok := nilManager.FromHost(typedNil); ok || state != nil {
		t.Fatalf("nil manager and typed-nil host resolved state=%p ok=%v", state, ok)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
}

func TestDetachWaitsForInFlightAttachmentAndClosesPublishedState(t *testing.T) {
	config := DefaultConfig()
	started := make(chan struct{})
	release := make(chan struct{})
	backend := new(fakeNamespace)
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		close(started)
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
	<-started

	detachStarted := make(chan struct{})
	detachDone := make(chan error, 1)
	go func() {
		close(detachStarted)
		detachDone <- manager.Detach(instance)
	}()
	<-detachStarted
	select {
	case err := <-detachDone:
		t.Fatalf("Detach returned while namespace construction was blocked: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	if err := <-attachDone; err != nil {
		t.Fatalf("Attach error = %v", err)
	}
	if err := <-detachDone; err != nil {
		t.Fatalf("Detach error = %v", err)
	}
	if manager.Len() != 0 {
		t.Fatalf("manager length = %d, want 0", manager.Len())
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("backend close count = %d, want 1", backend.closed.Load())
	}
}

func TestConcurrentDuplicateAttachSkipsNamespaceConstruction(t *testing.T) {
	config := DefaultConfig()
	started := make(chan struct{})
	release := make(chan struct{})
	backend := new(fakeNamespace)
	var calls atomic.Int32
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		calls.Add(1)
		close(started)
		<-release
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	firstDone := make(chan error, 1)
	go func() { firstDone <- manager.Attach(instance) }()
	<-started
	if err := manager.Attach(instance); !errors.Is(err, ErrAlreadyAttached) {
		t.Fatalf("duplicate Attach error = %v, want ErrAlreadyAttached", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("namespace factory calls = %d, want 1", calls.Load())
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Attach error = %v", err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
}

func TestFailedAttachmentReleasesOwnershipAndAllowsRetry(t *testing.T) {
	factoryErr := errors.New("backend setup failed")
	config := DefaultConfig()
	var calls atomic.Int32
	var failedAccount *quota.Account
	backend := new(fakeNamespace)
	config.NamespaceFactory = func(_ *policy.Policy, account *quota.Account) (nscore.Namespace, error) {
		if calls.Add(1) == 1 {
			failedAccount = account
			return nil, factoryErr
		}
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); !errors.Is(err, factoryErr) {
		t.Fatalf("failed Attach error = %v", err)
	}
	if manager.Len() != 0 {
		t.Fatal("failed attachment published state")
	}
	usage, closed := failedAccount.Snapshot()
	if !closed || usage != (quota.Usage{}) {
		t.Fatalf("failed attachment quota usage=%+v closed=%v", usage, closed)
	}
	if err := manager.Attach(instance); err != nil {
		t.Fatalf("retry Attach error = %v", err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("retry backend close count = %d, want 1", backend.closed.Load())
	}
}

func TestPanickingAttachmentRollsBackAndAllowsRetry(t *testing.T) {
	panicValue := errors.New("readiness panic")
	config := DefaultConfig()
	var calls atomic.Int32
	var failedAccount *quota.Account
	backend := new(fakeNamespace)
	config.NamespaceFactory = func(_ *policy.Policy, account *quota.Account) (nscore.Namespace, error) {
		if calls.Add(1) == 1 {
			failedAccount = account
			panic(panicValue)
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
	if recovered != panicValue {
		t.Fatalf("recovered panic = %v, want %v", recovered, panicValue)
	}
	if manager.Len() != 0 {
		t.Fatal("panicking attachment published state")
	}
	usage, closed := failedAccount.Snapshot()
	if !closed || usage != (quota.Usage{}) {
		t.Fatalf("panic rollback usage=%+v closed=%v", usage, closed)
	}
	if err := manager.Attach(instance); err != nil {
		t.Fatalf("retry Attach error = %v", err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("retry backend close count = %d, want 1", backend.closed.Load())
	}
}

func TestAttachmentCompletionRetiresRecordAcrossRollbackClosePanic(t *testing.T) {
	manager := NewManager()
	instance := new(wago.Instance)
	attempt, err := manager.beginAttachment(instance)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPanic := errors.New("backend close panic")
	backend := &fakeNamespace{closePanic: cleanupPanic}
	state, account := newRollbackAttachmentState(t, manager, backend)
	originalPanic := errors.New("namespace construction panic")

	waiterDone := make(chan struct{})
	go func() {
		<-attempt.done
		close(waiterDone)
	}()
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		manager.completeAttachment(instance, attempt, state, false, originalPanic)
	}()
	if recovered != originalPanic {
		t.Fatalf("recovered panic = %v, want original %v", recovered, originalPanic)
	}
	<-waiterDone
	if backend.closed.Load() != 1 {
		t.Fatalf("rollback backend close count = %d, want 1", backend.closed.Load())
	}
	if usage, closed := account.Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("rollback quota usage=%+v closed=%v", usage, closed)
	}
	if manager.Len() != 0 {
		t.Fatalf("manager length = %d, want zero", manager.Len())
	}
	manager.mu.RLock()
	_, retained := manager.attaching[instance]
	manager.mu.RUnlock()
	if retained {
		t.Fatal("rollback panic retained attachment record")
	}
	if err := manager.Attach(instance); err != nil {
		t.Fatalf("retry Attach after rollback panic: %v", err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatalf("retry Detach after rollback panic: %v", err)
	}

	cleanupOnlyInstance := new(wago.Instance)
	cleanupOnlyAttempt, err := manager.beginAttachment(cleanupOnlyInstance)
	if err != nil {
		t.Fatal(err)
	}
	cleanupOnlyBackend := &fakeNamespace{closePanic: cleanupPanic}
	cleanupOnlyState, cleanupOnlyAccount := newRollbackAttachmentState(t, manager, cleanupOnlyBackend)
	recovered = nil
	func() {
		defer func() { recovered = recover() }()
		manager.completeAttachment(cleanupOnlyInstance, cleanupOnlyAttempt, cleanupOnlyState, false, nil)
	}()
	if recovered != cleanupPanic {
		t.Fatalf("cleanup-only panic = %v, want %v", recovered, cleanupPanic)
	}
	if usage, closed := cleanupOnlyAccount.Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("cleanup-only quota usage=%+v closed=%v", usage, closed)
	}
	manager.mu.RLock()
	_, retained = manager.attaching[cleanupOnlyInstance]
	manager.mu.RUnlock()
	if retained {
		t.Fatal("cleanup-only panic retained attachment record")
	}
}

func newRollbackAttachmentState(t testing.TB, manager *Manager, backend nscore.Namespace) (*State, *quota.Account) {
	t.Helper()
	table, err := resource.NewTable()
	if err != nil {
		t.Fatal(err)
	}
	poller, err := readiness.New(table, manager.readiness)
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(manager.limits)
	state := &State{
		resources:  table,
		readiness:  poller,
		quotas:     account,
		policy:     manager.policy,
		pollEvents: make([]readiness.Event, manager.readiness.MaxRegistrations),
	}
	if _, err := state.createNamespace(func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return backend, nil
	}); err != nil {
		t.Fatal(err)
	}
	return state, account
}

func TestDifferentInstancesAttachConcurrently(t *testing.T) {
	config := DefaultConfig()
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		started <- struct{}{}
		<-release
		return new(fakeNamespace), nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instances := []*wago.Instance{new(wago.Instance), new(wago.Instance)}
	attachDone := make(chan error, len(instances))
	for _, instance := range instances {
		go func(instance *wago.Instance) { attachDone <- manager.Attach(instance) }(instance)
	}
	for range instances {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("different-instance namespace construction was serialized")
		}
	}
	close(release)
	for range instances {
		if err := <-attachDone; err != nil {
			t.Fatalf("Attach error = %v", err)
		}
	}
	for _, instance := range instances {
		if err := manager.Detach(instance); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetachCoordinatesWaitersReattachmentAndUnrelatedInstances(t *testing.T) {
	closeErr := errors.New("backend close failed")
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	firstBackend := &fakeNamespace{closeErr: closeErr, closeStarted: closeStarted, closeRelease: closeRelease}
	secondBackend := new(fakeNamespace)
	thirdBackend := new(fakeNamespace)
	factoryCalls := make(chan int, 3)
	var calls atomic.Int32
	config := DefaultConfig()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		call := int(calls.Add(1))
		factoryCalls <- call
		switch call {
		case 1:
			return firstBackend, nil
		case 2:
			return secondBackend, nil
		case 3:
			return thirdBackend, nil
		default:
			return nil, errors.New("unexpected namespace factory call")
		}
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	if call := <-factoryCalls; call != 1 {
		t.Fatalf("initial factory call = %d, want 1", call)
	}
	oldState, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("initial state missing")
	}

	firstDetach := make(chan error, 1)
	go func() { firstDetach <- manager.Detach(instance) }()
	<-closeStarted
	if _, ok := manager.ForInstance(instance); ok {
		t.Fatal("state remained published during teardown")
	}

	secondDetach := make(chan error, 1)
	go func() { secondDetach <- manager.Detach(instance) }()
	reattachDone := make(chan error, 1)
	go func() { reattachDone <- manager.Attach(instance) }()
	select {
	case err := <-secondDetach:
		t.Fatalf("second Detach returned before shared teardown completed: %v", err)
	case call := <-factoryCalls:
		t.Fatalf("same-instance reattachment reached factory before teardown: call %d", call)
	case <-time.After(20 * time.Millisecond):
	}

	otherInstance := new(wago.Instance)
	if err := manager.Attach(otherInstance); err != nil {
		t.Fatalf("unrelated Attach error = %v", err)
	}
	if call := <-factoryCalls; call != 2 {
		t.Fatalf("unrelated factory call = %d, want 2", call)
	}
	if _, ok := manager.ForInstance(otherInstance); !ok {
		t.Fatal("unrelated instance did not publish while teardown was blocked")
	}

	close(closeRelease)
	if err := <-firstDetach; !errors.Is(err, closeErr) {
		t.Fatalf("first Detach error = %v, want %v", err, closeErr)
	}
	if err := <-secondDetach; !errors.Is(err, closeErr) {
		t.Fatalf("second Detach error = %v, want %v", err, closeErr)
	}
	if call := <-factoryCalls; call != 3 {
		t.Fatalf("reattachment factory call = %d, want 3", call)
	}
	if err := <-reattachDone; err != nil {
		t.Fatalf("reattachment error = %v", err)
	}
	newState, ok := manager.ForInstance(instance)
	if !ok || newState == oldState {
		t.Fatalf("reattached state = %p ok=%v, old=%p", newState, ok, oldState)
	}
	if firstBackend.closed.Load() != 1 {
		t.Fatalf("first backend close count = %d, want 1", firstBackend.closed.Load())
	}
	manager.mu.RLock()
	_, attaching := manager.attaching[instance]
	_, detaching := manager.detaching[instance]
	manager.mu.RUnlock()
	if attaching || detaching {
		t.Fatalf("completed lifecycle retained records attaching=%v detaching=%v", attaching, detaching)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatalf("detach reattached instance: %v", err)
	}
	if err := manager.Detach(otherInstance); err != nil {
		t.Fatalf("detach unrelated instance: %v", err)
	}
	if thirdBackend.closed.Load() != 1 || secondBackend.closed.Load() != 1 {
		t.Fatalf("replacement backend closes = reattached:%d unrelated:%d", thirdBackend.closed.Load(), secondBackend.closed.Load())
	}
}

func TestDetachUnpublishesBeforeSerializedTeardownCompletes(t *testing.T) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	started := make(chan struct{})
	release := make(chan struct{})
	operationDone := make(chan error, 1)
	go func() {
		operationDone <- state.WithLock(func(LockedState) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	detachDone := make(chan error, 1)
	go func() { detachDone <- manager.Detach(instance) }()
	deadline := time.After(time.Second)
	for {
		if _, ok := manager.ForInstance(instance); !ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("state remained published while teardown was blocked behind an in-flight operation")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-detachDone:
		t.Fatalf("Detach completed before locked operation released: %v", err)
	default:
	}
	close(release)
	if err := <-operationDone; err != nil {
		t.Fatalf("locked operation error = %v", err)
	}
	if err := <-detachDone; err != nil {
		t.Fatalf("Detach error = %v", err)
	}
	if err := state.WithLock(func(LockedState) error { return nil }); !errors.Is(err, resource.ErrClosed) {
		t.Fatalf("stale state WithLock error = %v, want ErrClosed", err)
	}
}

func TestPollVisitorSerializesDetachUntilVisitorReturns(t *testing.T) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	handle, err := state.Resources().Add(resource.KindPollable, fakePollable{})
	if err != nil {
		t.Fatalf("Add pollable: %v", err)
	}
	if err := state.Readiness().Register(handle, resource.KindPollable); err != nil {
		t.Fatalf("Register pollable: %v", err)
	}
	visitorStarted := make(chan struct{})
	visitorRelease := make(chan struct{})
	pollDone := make(chan error, 1)
	go func() {
		_, _, err := state.Poll(readiness.Budget{Scans: 1, Events: 1}, func(events []readiness.Event, report readiness.Report, progress nscore.Progress) error {
			if len(events) != 1 || report.Events != 1 || progress != nscore.ProgressDone {
				return errors.New("unexpected poll result")
			}
			close(visitorStarted)
			<-visitorRelease
			if events[0].Handle != handle || events[0].Readiness != namespace.ReadyReadable {
				return errors.New("visitor observed unstable readiness result")
			}
			return nil
		})
		pollDone <- err
	}()
	<-visitorStarted
	detachDone := make(chan error, 1)
	go func() { detachDone <- manager.Detach(instance) }()
	select {
	case err := <-detachDone:
		t.Fatalf("Detach completed before poll visitor returned: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(visitorRelease)
	if err := <-pollDone; err != nil {
		t.Fatalf("Poll error = %v", err)
	}
	if err := <-detachDone; err != nil {
		t.Fatalf("Detach error = %v", err)
	}
}

func TestConfiguredNamespacesAreQuotaOwnedIsolatedAndGenerationSafe(t *testing.T) {
	config := DefaultConfig()
	config.Limits.Resources = 1
	var created []*fakeNamespace
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		backend := new(fakeNamespace)
		created = append(created, backend)
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	firstInstance, secondInstance := new(wago.Instance), new(wago.Instance)
	if err := manager.Attach(firstInstance); err != nil {
		t.Fatal(err)
	}
	if err := manager.Attach(secondInstance); err != nil {
		t.Fatal(err)
	}
	first, _ := manager.ForInstance(firstInstance)
	second, _ := manager.ForInstance(secondInstance)
	if first == nil || second == nil || first.NamespaceHandle() == 0 || second.NamespaceHandle() == 0 || first.NamespaceHandle() == second.NamespaceHandle() {
		t.Fatalf("namespace state = %#v / %#v", first, second)
	}
	if _, err := second.Resources().Lookup(first.NamespaceHandle(), resource.KindNamespace); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("cross-instance namespace lookup = %v", err)
	}
	for _, state := range []*State{first, second} {
		usage, closed := state.Quotas().Snapshot()
		if closed || usage.Resources != 1 || state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
			t.Fatalf("configured state usage=%+v closed=%v resources=%d readiness=%+v", usage, closed, state.Resources().Len(), state.Readiness().Snapshot())
		}
	}
	stale := first.NamespaceHandle()
	if err := manager.Detach(firstInstance); err != nil {
		t.Fatal(err)
	}
	if created[0].closed.Load() != 1 {
		t.Fatalf("first backend close count = %d", created[0].closed.Load())
	}
	if _, err := first.Resources().Lookup(stale, resource.KindNamespace); !errors.Is(err, resource.ErrClosed) {
		t.Fatalf("closed table stale lookup = %v", err)
	}
	if err := manager.Detach(secondInstance); err != nil {
		t.Fatal(err)
	}
	if created[1].closed.Load() != 1 {
		t.Fatalf("second backend close count = %d", created[1].closed.Load())
	}
}

func TestNamespaceCloseErrorClearsRetiredHandleAndOwnership(t *testing.T) {
	closeErr := errors.New("backend close failed")
	backend := &fakeNamespace{closeErr: closeErr}
	config := DefaultConfig()
	config.Limits.Resources = 1
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
		t.Fatalf("CloseHandle error = %v, want backend close error", err)
	}
	if state.NamespaceHandle() != 0 {
		t.Fatalf("namespace handle = %v, want zero", state.NamespaceHandle())
	}
	if _, err := state.Resources().Lookup(handle, resource.KindNamespace); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("retired namespace lookup = %v, want ErrBadHandle", err)
	}
	if snapshot := state.Readiness().Snapshot(); snapshot.Registrations != 0 {
		t.Fatalf("readiness after close = %+v", snapshot)
	}
	if usage, closed := state.Quotas().Snapshot(); closed || usage != (quota.Usage{}) {
		t.Fatalf("quota after close usage=%+v closed=%v", usage, closed)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("backend close count = %d, want 1", backend.closed.Load())
	}
	if err := state.CloseHandle(handle, resource.KindNamespace); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("repeated CloseHandle error = %v, want ErrBadHandle", err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("repeated backend close count = %d, want 1", backend.closed.Load())
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatalf("Detach error = %v", err)
	}
}

func TestWrongKindClosePreservesNamespaceHandle(t *testing.T) {
	backend := new(fakeNamespace)
	config := DefaultConfig()
	config.Limits.Resources = 1
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
	if err := state.CloseHandle(handle, resource.KindUDPSocket); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind CloseHandle error = %v, want ErrBadHandle", err)
	}
	if state.NamespaceHandle() != handle {
		t.Fatalf("namespace handle = %v, want %v", state.NamespaceHandle(), handle)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("wrong-kind close mutated ownership: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
	if usage, closed := state.Quotas().Snapshot(); closed || usage.Resources != 1 {
		t.Fatalf("wrong-kind close quota usage=%+v closed=%v", usage, closed)
	}
	if backend.closed.Load() != 0 {
		t.Fatalf("wrong-kind backend close count = %d, want 0", backend.closed.Load())
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	if backend.closed.Load() != 1 {
		t.Fatalf("detach backend close count = %d, want 1", backend.closed.Load())
	}
}

func TestOutputScratchIsZeroedReusedAndReleased(t *testing.T) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, _ := manager.ForInstance(instance)
	var first *byte
	if err := state.WithLock(func(locked LockedState) error {
		scratch := locked.OutputScratch(8)
		first = &scratch[0]
		for i := range scratch {
			scratch[i] = byte(i + 1)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.WithLock(func(locked LockedState) error {
		scratch := locked.OutputScratch(4)
		if &scratch[0] != first {
			t.Fatal("scratch backing was not reused")
		}
		for i, value := range scratch {
			if value != 0 {
				t.Fatalf("scratch[%d] = %d", i, value)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	if state.outputScratch != nil {
		t.Fatal("detach retained output scratch")
	}
}

type fuzzManagerResource struct{ closed atomic.Int32 }

func (r *fuzzManagerResource) Close() error {
	r.closed.Add(1)
	return nil
}

func (r *fuzzManagerResource) Readiness() nscore.Readiness { return nscore.ReadyReadable }

func FuzzManagerExactInstanceLifecycle(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Add([]byte{0, 5, 3, 8, 1, 6, 0, 5})
	f.Fuzz(func(t *testing.T, operations []byte) {
		if len(operations) > 64 {
			operations = operations[:64]
		}
		manager := NewManager()
		instances := [2]*wago.Instance{new(wago.Instance), new(wago.Instance)}
		states := [2]*State{}
		handles := [2]resource.Handle{}
		resources := [2]*fuzzManagerResource{}
		seen := make(map[*State]struct{})
		var allResources []*fuzzManagerResource
		var staleHandles [2][]resource.Handle

		assertManagerLifecycleModel(t, manager, instances, states, handles, resources, staleHandles)
		for index, operation := range operations {
			slot := int(operation>>7) & 1
			switch operation % 5 {
			case 0:
				err := manager.Attach(instances[slot])
				if states[slot] != nil {
					if !errors.Is(err, ErrAlreadyAttached) {
						t.Fatalf("operation %d duplicate attach = %v", index, err)
					}
					break
				}
				if err != nil {
					t.Fatalf("operation %d attach = %v", index, err)
				}
				state, ok := manager.ForInstance(instances[slot])
				if !ok || state == nil {
					t.Fatalf("operation %d attached state missing", index)
				}
				if _, reused := seen[state]; reused {
					t.Fatalf("operation %d reused detached State pointer %p", index, state)
				}
				seen[state] = struct{}{}
				value := new(fuzzManagerResource)
				handle, err := state.Resources().Add(resource.KindPollable, value)
				if err != nil {
					t.Fatalf("operation %d add resource = %v", index, err)
				}
				if err := state.Readiness().Register(handle, resource.KindPollable); err != nil {
					t.Fatalf("operation %d register resource = %v", index, err)
				}
				for _, stale := range staleHandles[slot] {
					if handle == stale {
						t.Fatalf("operation %d reused stale handle %v", index, handle)
					}
				}
				states[slot], handles[slot], resources[slot] = state, handle, value
				allResources = append(allResources, value)
			case 1:
				state, value, handle := states[slot], resources[slot], handles[slot]
				if err := manager.Detach(instances[slot]); err != nil {
					t.Fatalf("operation %d detach = %v", index, err)
				}
				if state != nil {
					if value.closed.Load() != 1 {
						t.Fatalf("operation %d detached resource closes = %d", index, value.closed.Load())
					}
					if err := state.WithLock(func(LockedState) error { return nil }); failureOfManagerError(err) != nscore.FailureClosed {
						t.Fatalf("operation %d detached state remained usable: %v", index, err)
					}
					staleHandles[slot] = append(staleHandles[slot], handle)
					states[slot], handles[slot], resources[slot] = nil, 0, nil
				}
			case 2:
				got, ok := manager.ForInstance(instances[slot])
				if ok != (states[slot] != nil) || got != states[slot] {
					t.Fatalf("operation %d lookup = %p %v, want %p", index, got, ok, states[slot])
				}
			case 3:
				if states[slot] != nil {
					if err := states[slot].CloseHandle(handles[slot], resource.KindPollable); err != nil {
						t.Fatalf("operation %d close handle = %v", index, err)
					}
					if resources[slot].closed.Load() != 1 {
						t.Fatalf("operation %d handle closes = %d", index, resources[slot].closed.Load())
					}
					staleHandles[slot] = append(staleHandles[slot], handles[slot])
					value := new(fuzzManagerResource)
					handle, err := states[slot].Resources().Add(resource.KindPollable, value)
					if err != nil {
						t.Fatalf("operation %d replacement add = %v", index, err)
					}
					if err := states[slot].Readiness().Register(handle, resource.KindPollable); err != nil {
						t.Fatalf("operation %d replacement register = %v", index, err)
					}
					for _, stale := range staleHandles[slot] {
						if handle == stale {
							t.Fatalf("operation %d replacement reused stale handle %v", index, handle)
						}
					}
					handles[slot], resources[slot] = handle, value
					allResources = append(allResources, value)
				}
			case 4:
				if got, ok := manager.ForInstance(new(wago.Instance)); ok || got != nil {
					t.Fatalf("operation %d non-exact instance resolved %p", index, got)
				}
			}
			assertManagerLifecycleModel(t, manager, instances, states, handles, resources, staleHandles)
		}
		for slot := range instances {
			if err := manager.Detach(instances[slot]); err != nil {
				t.Fatal(err)
			}
			states[slot], handles[slot], resources[slot] = nil, 0, nil
		}
		assertManagerLifecycleModel(t, manager, instances, states, handles, resources, staleHandles)
		for index, value := range allResources {
			if value.closed.Load() != 1 {
				t.Fatalf("resource %d close calls = %d, want 1", index, value.closed.Load())
			}
		}
	})
}

func assertManagerLifecycleModel(t testing.TB, manager *Manager, instances [2]*wago.Instance, states [2]*State, handles [2]resource.Handle, resources [2]*fuzzManagerResource, staleHandles [2][]resource.Handle) {
	t.Helper()
	wantLen := 0
	for slot := range instances {
		state, ok := manager.ForInstance(instances[slot])
		if states[slot] == nil {
			if ok || state != nil || handles[slot] != 0 || resources[slot] != nil {
				t.Fatalf("slot %d detached model = state:%p lookup:%p/%v handle:%v resource:%p", slot, states[slot], state, ok, handles[slot], resources[slot])
			}
			continue
		}
		wantLen++
		if !ok || state != states[slot] {
			t.Fatalf("slot %d exact lookup = %p/%v, want %p", slot, state, ok, states[slot])
		}
		if resources[slot] == nil || resources[slot].closed.Load() != 0 {
			t.Fatalf("slot %d live resource = %p closes=%d", slot, resources[slot], resources[slot].closed.Load())
		}
		value, err := state.Resources().Lookup(handles[slot], resource.KindPollable)
		if err != nil || value != resources[slot] {
			t.Fatalf("slot %d live handle lookup = %T %v", slot, value, err)
		}
		if registrations := state.Readiness().Snapshot().Registrations; registrations != 1 {
			t.Fatalf("slot %d readiness registrations = %d", slot, registrations)
		}
		for _, stale := range staleHandles[slot] {
			if _, err := state.Resources().Lookup(stale, resource.KindPollable); !errors.Is(err, resource.ErrBadHandle) {
				t.Fatalf("slot %d stale handle %v lookup = %v", slot, stale, err)
			}
		}
	}
	if manager.Len() != wantLen {
		t.Fatalf("manager length = %d, want %d", manager.Len(), wantLen)
	}
	if states[0] != nil && states[1] != nil {
		if states[0] == states[1] {
			t.Fatal("two exact instances shared one State")
		}
		for slot := range states {
			other := 1 - slot
			if _, err := states[other].Resources().Lookup(handles[slot], resource.KindPollable); !errors.Is(err, resource.ErrBadHandle) {
				t.Fatalf("slot %d handle resolved in slot %d: %v", slot, other, err)
			}
		}
	}
}

func failureOfManagerError(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func TestNamespaceCreationRollsBackEveryOwnedStage(t *testing.T) {
	t.Run("quota denial skips backend", func(t *testing.T) {
		config := DefaultConfig()
		config.Limits.Resources = 0
		var calls atomic.Int32
		config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			calls.Add(1)
			return new(fakeNamespace), nil
		}
		manager, err := NewManagerConfigured(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Attach(new(wago.Instance)); !errors.Is(err, quota.ErrLimit) {
			t.Fatalf("quota denial error = %v", err)
		}
		if calls.Load() != 0 || manager.Len() != 0 {
			t.Fatalf("denied attach called backend %d times or published state", calls.Load())
		}
	})

	t.Run("factory failure releases reservation", func(t *testing.T) {
		factoryErr := errors.New("backend setup failed")
		config := DefaultConfig()
		config.Limits.Resources = 1
		config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return nil, factoryErr }
		manager, err := NewManagerConfigured(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Attach(new(wago.Instance)); !errors.Is(err, factoryErr) {
			t.Fatalf("factory failure = %v", err)
		}
		if manager.Len() != 0 {
			t.Fatal("failed factory published state")
		}
	})

	t.Run("typed nil factory result releases reservation", func(t *testing.T) {
		config := DefaultConfig()
		config.Limits.Resources = 1
		config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			var backend *fakeNamespace
			return backend, nil
		}
		manager, err := NewManagerConfigured(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Attach(new(wago.Instance)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("typed nil factory result = %v, want ErrInvalidConfig", err)
		}
		if manager.Len() != 0 {
			t.Fatal("typed nil factory result published state")
		}
	})

	t.Run("registration failure closes backend and releases quota", func(t *testing.T) {
		table, err := resource.NewTable()
		if err != nil {
			t.Fatal(err)
		}
		poller, err := readiness.New(table, readiness.Config{MaxRegistrations: 1})
		if err != nil {
			t.Fatal(err)
		}
		blocker, err := table.Add(resource.KindPollable, fakePollable{})
		if err != nil {
			t.Fatal(err)
		}
		if err := poller.Register(blocker, resource.KindPollable); err != nil {
			t.Fatal(err)
		}
		account := quota.NewAccount(quota.Limits{Resources: 1})
		compiled, err := policy.Compile(policy.Config{})
		if err != nil {
			t.Fatal(err)
		}
		state := &State{resources: table, readiness: poller, quotas: account, policy: compiled}
		backend := new(fakeNamespace)
		if _, err := state.createNamespace(func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return backend, nil }); !errors.Is(err, readiness.ErrLimit) {
			t.Fatalf("registration failure = %v", err)
		}
		usage, closed := account.Snapshot()
		if closed || usage != (quota.Usage{}) || backend.closed.Load() != 1 || table.Len() != 1 || state.NamespaceHandle() != 0 {
			t.Fatalf("rollback usage=%+v closed=%v backend=%d resources=%d handle=%v", usage, closed, backend.closed.Load(), table.Len(), state.NamespaceHandle())
		}
	})
}
