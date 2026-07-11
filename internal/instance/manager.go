// Package instance owns networking state attached to exact Wago instances.
package instance

import (
	"errors"
	"fmt"
	"sync"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

var (
	ErrInvalidInstance      = errors.New("net: invalid Wago instance")
	ErrAlreadyAttached      = errors.New("net: instance state already attached")
	ErrInvalidConfig        = errors.New("net: invalid instance manager config")
	ErrInvalidBackendResult = errors.New("net: invalid backend result")
)

// NamespaceFactory constructs one backend namespace for one exact instance.
// The returned value must not be shared with another instance. Policy and quota
// pointers belong to that exact state and let backend resources enforce common
// authority and accounting without exposing backend types above this layer.
type NamespaceFactory func(*policy.Policy, *quota.Account) (namespace.Namespace, error)

// Config fixes immutable policy, finite accounting, readiness storage, and an
// optional namespace factory for every state attached by a Manager.
type Config struct {
	Policy           policy.Config
	Limits           quota.Limits
	Readiness        readiness.Config
	NamespaceFactory NamespaceFactory
}

// DefaultConfig preserves the core extension's state-only behavior: finite
// default quotas and readiness storage with no automatically created namespace.
func DefaultConfig() Config {
	return Config{Limits: quota.DefaultLimits(), Readiness: readiness.DefaultConfig()}
}

// State is the networking ownership root for one exact Wago instance.
type State struct {
	mu sync.Mutex

	resources  *resource.Table
	readiness  *readiness.Coordinator
	quotas     *quota.Account
	policy     *policy.Policy
	pollEvents []readiness.Event
	namespace  resource.Handle
	closed     bool
}

// Resources returns the instance's generation-safe resource table.
func (s *State) Resources() *resource.Table {
	if s == nil {
		return nil
	}
	return s.resources
}

// Readiness returns the instance's bounded poll coordinator.
func (s *State) Readiness() *readiness.Coordinator {
	if s == nil {
		return nil
	}
	return s.readiness
}

// Quotas returns the instance's bounded accounting ledger.
func (s *State) Quotas() *quota.Account {
	if s == nil {
		return nil
	}
	return s.quotas
}

// Policy returns the immutable endpoint policy compiled for this instance.
func (s *State) Policy() *policy.Policy {
	if s == nil {
		return nil
	}
	return s.policy
}

// NamespaceHandle returns the automatically created namespace handle, or zero
// when the extension was configured without a namespace.
func (s *State) NamespaceHandle() resource.Handle {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.namespace
}

// Close stops polling before releasing resources so no readiness lookup can
// race teardown, then closes the ledger to discard failed-operation
// reservations that never reached a resource owner.
func (s *State) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.readiness != nil {
		errs = append(errs, s.readiness.Close())
	}
	if s.resources != nil {
		errs = append(errs, s.resources.Close())
	}
	if s.quotas != nil {
		s.quotas.Close()
	}
	clear(s.pollEvents)
	s.pollEvents = nil
	s.namespace = 0
	return errors.Join(errs...)
}

// Manager is an extension-local attachment map. It must be owned by an
// extension value; it is intentionally not a package-global registry.
type Manager struct {
	mu     sync.RWMutex
	states map[*wago.Instance]*State

	policy           *policy.Policy
	limits           quota.Limits
	readiness        readiness.Config
	namespaceFactory NamespaceFactory
}

// NewManager creates an empty extension-local manager with finite defaults and
// no automatically created namespace.
func NewManager() *Manager {
	manager, err := NewManagerConfigured(DefaultConfig())
	if err != nil {
		panic(err)
	}
	return manager
}

// NewManagerConfigured validates and deep-copies manager authority before any
// instance can be attached.
func NewManagerConfigured(config Config) (*Manager, error) {
	if config.Readiness.MaxRegistrations <= 0 {
		return nil, ErrInvalidConfig
	}
	compiled, err := policy.Compile(config.Policy)
	if err != nil {
		return nil, fmt.Errorf("compile endpoint policy: %w", err)
	}
	return &Manager{
		states:           make(map[*wago.Instance]*State),
		policy:           compiled,
		limits:           config.Limits,
		readiness:        config.Readiness,
		namespaceFactory: config.NamespaceFactory,
	}, nil
}

// AfterInstantiate is a Wago lifecycle hook that attaches fresh state after a
// Runtime instance has been created.
func (m *Manager) AfterInstantiate(_ *wago.InstantiateContext, instance *wago.Instance) error {
	return m.Attach(instance)
}

// BeforeClose is a Wago lifecycle hook that removes state before instance
// memory and runtime resources are invalidated. Wago close hooks cannot return
// errors, so all resources are attempted and cleanup errors are contained.
func (m *Manager) BeforeClose(context *wago.InstanceContext) {
	if context == nil {
		return
	}
	_ = m.Detach(context.Instance)
}

// Attach creates and publishes one isolated state for instance. An optional
// namespace is fully quota-owned, generation-safe, and poll-registered before
// publication; every failed stage is rolled back synchronously.
func (m *Manager) Attach(instance *wago.Instance) error {
	if m == nil || instance == nil {
		return ErrInvalidInstance
	}
	table, err := resource.NewTable()
	if err != nil {
		return fmt.Errorf("create resource table: %w", err)
	}
	poller, err := readiness.New(table, m.readiness)
	if err != nil {
		_ = table.Close()
		return fmt.Errorf("create readiness coordinator: %w", err)
	}
	state := &State{
		resources:  table,
		readiness:  poller,
		quotas:     quota.NewAccount(m.limits),
		policy:     m.policy,
		pollEvents: make([]readiness.Event, m.readiness.MaxRegistrations),
	}
	if m.namespaceFactory != nil {
		if _, err := state.createNamespace(m.namespaceFactory); err != nil {
			_ = state.Close()
			return fmt.Errorf("create instance namespace: %w", err)
		}
	}

	m.mu.Lock()
	if m.states == nil {
		m.states = make(map[*wago.Instance]*State)
	}
	if _, exists := m.states[instance]; exists {
		m.mu.Unlock()
		_ = state.Close()
		return ErrAlreadyAttached
	}
	m.states[instance] = state
	m.mu.Unlock()
	return nil
}

func (s *State) createNamespace(factory NamespaceFactory) (resource.Handle, error) {
	if s == nil || s.resources == nil || s.readiness == nil || s.quotas == nil || factory == nil {
		return 0, ErrInvalidConfig
	}
	reservation, err := s.quotas.ReserveResource(quota.ResourceOther, 1)
	if err != nil {
		return 0, err
	}
	backend, err := factory(s.policy, s.quotas)
	if err != nil {
		reservation.Rollback()
		return 0, err
	}
	if backend == nil {
		reservation.Rollback()
		return 0, ErrInvalidConfig
	}
	allocation, ok := reservation.Commit()
	if !ok {
		_ = backend.Close()
		return 0, quota.ErrClosed
	}
	owned := &ownedNamespace{Namespace: backend, allocation: allocation}
	handle, err := s.resources.Add(resource.KindNamespace, owned)
	if err != nil {
		_ = owned.Close()
		return 0, err
	}
	if err := s.readiness.Register(handle, resource.KindNamespace); err != nil {
		_ = s.resources.CloseHandle(handle, resource.KindNamespace)
		return 0, err
	}
	s.namespace = handle
	return handle, nil
}

// LookupNamespace resolves one exact namespace handle to its backend-neutral
// implementation while serializing the lookup against teardown. It is intended
// for trusted host-side link/service integration, never direct guest retention.
func (s *State) LookupNamespace(namespaceHandle resource.Handle) (namespace.Namespace, error) {
	if s == nil {
		return nil, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil {
		return nil, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(namespaceHandle, resource.KindNamespace)
	if err != nil {
		return nil, err
	}
	if owned, ok := value.(*ownedNamespace); ok && owned.Namespace != nil {
		return owned.Namespace, nil
	}
	backend, ok := value.(namespace.Namespace)
	if !ok {
		return nil, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return backend, nil
}

// BindUDP transactionally creates, owns, and poll-registers one backend UDP
// socket under namespaceHandle. Failed backend, table, and registration stages
// synchronously close the socket so its quota allocations are released.
func (s *State) BindUDP(namespaceHandle resource.Handle, local namespace.Endpoint) (resource.Handle, namespace.Progress, error) {
	if s == nil {
		return 0, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil || s.readiness == nil {
		return 0, 0, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(namespaceHandle, resource.KindNamespace)
	if err != nil {
		return 0, 0, err
	}
	backend, ok := value.(namespace.Namespace)
	if !ok {
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	socket, progress, err := backend.TryBindUDP(local)
	if err != nil {
		return 0, progress, err
	}
	if progress == namespace.ProgressWouldBlock {
		if socket != nil {
			_ = socket.Close()
			return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
		}
		return 0, progress, nil
	}
	if progress != namespace.ProgressDone || socket == nil {
		if socket != nil {
			_ = socket.Close()
		}
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	handle, err := s.resources.Add(resource.KindUDPSocket, socket)
	if err != nil {
		_ = socket.Close()
		return 0, 0, err
	}
	if err := s.readiness.Register(handle, resource.KindUDPSocket); err != nil {
		_ = s.resources.CloseHandle(handle, resource.KindUDPSocket)
		return 0, 0, err
	}
	return handle, namespace.ProgressDone, nil
}

// SendUDP performs one nonblocking datagram send through an exact live UDP
// handle while serializing the operation against instance teardown.
func (s *State) SendUDP(handle resource.Handle, payload []byte, remote namespace.Endpoint) (namespace.Progress, error) {
	if s == nil {
		return 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil {
		return 0, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(handle, resource.KindUDPSocket)
	if err != nil {
		return 0, err
	}
	socket, ok := value.(namespace.UDPSocket)
	if !ok {
		return 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return socket.TrySend(payload, remote)
}

// ReceiveUDP performs one nonblocking datagram receive through an exact live
// UDP handle while serializing the operation against instance teardown.
func (s *State) ReceiveUDP(handle resource.Handle, dst []byte) (namespace.DatagramResult, error) {
	if s == nil {
		return namespace.DatagramResult{}, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil {
		return namespace.DatagramResult{}, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(handle, resource.KindUDPSocket)
	if err != nil {
		return namespace.DatagramResult{}, err
	}
	socket, ok := value.(namespace.UDPSocket)
	if !ok {
		return namespace.DatagramResult{}, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	result, err := socket.TryReceive(dst)
	if err == nil && !result.Valid(len(dst)) {
		return namespace.DatagramResult{}, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return result, err
}

// ListenTCP transactionally creates, owns, and poll-registers one listener.
func (s *State) ListenTCP(namespaceHandle resource.Handle, local namespace.Endpoint) (resource.Handle, namespace.Progress, error) {
	if s == nil {
		return 0, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil || s.readiness == nil {
		return 0, 0, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(namespaceHandle, resource.KindNamespace)
	if err != nil {
		return 0, 0, err
	}
	backend, ok := value.(namespace.Namespace)
	if !ok {
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	listener, progress, err := backend.TryListenTCP(local)
	if err != nil {
		return 0, progress, err
	}
	if progress != namespace.ProgressDone || listener == nil {
		if listener != nil {
			_ = listener.Close()
		}
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	handle, err := s.resources.Add(resource.KindTCPListener, listener)
	if err != nil {
		_ = listener.Close()
		return 0, 0, err
	}
	if err := s.readiness.Register(handle, resource.KindTCPListener); err != nil {
		_ = s.resources.CloseHandle(handle, resource.KindTCPListener)
		return 0, 0, err
	}
	return handle, namespace.ProgressDone, nil
}

// ConnectTCP owns and poll-registers one immediate or in-progress stream.
func (s *State) ConnectTCP(namespaceHandle resource.Handle, remote namespace.Endpoint) (resource.Handle, namespace.Progress, error) {
	if s == nil {
		return 0, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil || s.readiness == nil {
		return 0, 0, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(namespaceHandle, resource.KindNamespace)
	if err != nil {
		return 0, 0, err
	}
	backend, ok := value.(namespace.Namespace)
	if !ok {
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	stream, progress, err := backend.TryConnectTCP(remote)
	if err != nil {
		return 0, progress, err
	}
	if (progress != namespace.ProgressDone && progress != namespace.ProgressInProgress) || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	handle, err := s.ownTCPStreamLocked(stream)
	if err != nil {
		return 0, 0, err
	}
	return handle, progress, nil
}

// AcceptTCP owns one fully established stream returned by a live listener.
func (s *State) AcceptTCP(listenerHandle resource.Handle) (resource.Handle, namespace.Progress, error) {
	if s == nil {
		return 0, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil || s.readiness == nil {
		return 0, 0, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(listenerHandle, resource.KindTCPListener)
	if err != nil {
		return 0, 0, err
	}
	listener, ok := value.(namespace.TCPListener)
	if !ok {
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	stream, progress, err := listener.TryAccept()
	if err != nil {
		return 0, progress, err
	}
	if progress == namespace.ProgressWouldBlock {
		if stream != nil {
			_ = stream.Close()
			return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
		}
		return 0, progress, nil
	}
	if progress != namespace.ProgressDone || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	handle, err := s.ownTCPStreamLocked(stream)
	if err != nil {
		return 0, 0, err
	}
	return handle, namespace.ProgressDone, nil
}

// ResolveDNS owns and poll-registers one immediate or in-progress DNS query.
func (s *State) ResolveDNS(namespaceHandle resource.Handle, request namespace.DNSRequest) (resource.Handle, namespace.Progress, error) {
	if s == nil {
		return 0, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil || s.readiness == nil {
		return 0, 0, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(namespaceHandle, resource.KindNamespace)
	if err != nil {
		return 0, 0, err
	}
	backend, ok := value.(namespace.Namespace)
	if !ok {
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	query, progress, err := backend.TryResolve(request)
	if err != nil {
		return 0, progress, err
	}
	if (progress != namespace.ProgressDone && progress != namespace.ProgressInProgress) || query == nil {
		if query != nil {
			_ = query.Close()
		}
		return 0, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	handle, err := s.resources.Add(resource.KindDNSQuery, query)
	if err != nil {
		_ = query.Close()
		return 0, 0, err
	}
	if err := s.readiness.Register(handle, resource.KindDNSQuery); err != nil {
		_ = s.resources.CloseHandle(handle, resource.KindDNSQuery)
		return 0, 0, err
	}
	return handle, progress, nil
}

// NextDNS performs one nonblocking copied-record read from an exact live query.
func (s *State) NextDNS(handle resource.Handle) (namespace.DNSRecord, namespace.DNSNext, error) {
	if s == nil {
		return namespace.DNSRecord{}, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	query, err := s.lookupDNSLocked(handle)
	if err != nil {
		return namespace.DNSRecord{}, 0, err
	}
	record, next, err := query.TryNext()
	if err == nil && next == namespace.DNSNextReady && !record.Valid() {
		return namespace.DNSRecord{}, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	if err == nil && next != namespace.DNSNextReady && next != namespace.DNSNextWouldBlock && next != namespace.DNSNextEOF {
		return namespace.DNSRecord{}, 0, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return record, next, err
}

// CancelDNS makes one unfinished query terminal without retiring its handle.
func (s *State) CancelDNS(handle resource.Handle) error {
	if s == nil {
		return ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	query, err := s.lookupDNSLocked(handle)
	if err != nil {
		return err
	}
	return query.Cancel()
}

func (s *State) lookupDNSLocked(handle resource.Handle) (namespace.DNSQuery, error) {
	if s.closed || s.resources == nil {
		return nil, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(handle, resource.KindDNSQuery)
	if err != nil {
		return nil, err
	}
	query, ok := value.(namespace.DNSQuery)
	if !ok {
		return nil, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return query, nil
}

func (s *State) ownTCPStreamLocked(stream namespace.TCPStream) (resource.Handle, error) {
	handle, err := s.resources.Add(resource.KindTCPStream, stream)
	if err != nil {
		_ = stream.Close()
		return 0, err
	}
	if err := s.readiness.Register(handle, resource.KindTCPStream); err != nil {
		_ = s.resources.CloseHandle(handle, resource.KindTCPStream)
		return 0, err
	}
	return handle, nil
}

// TCPStreamEndpoints returns backend-neutral local and remote endpoints for one
// exact live stream without exposing or retaining the backend resource.
func (s *State) TCPStreamEndpoints(handle resource.Handle) (namespace.Endpoint, namespace.Endpoint, error) {
	if s == nil {
		return namespace.Endpoint{}, namespace.Endpoint{}, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.lookupTCPStreamLocked(handle)
	if err != nil {
		return namespace.Endpoint{}, namespace.Endpoint{}, err
	}
	local, remote := stream.LocalEndpoint(), stream.RemoteEndpoint()
	if !local.Valid() || !remote.Valid() {
		return namespace.Endpoint{}, namespace.Endpoint{}, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return local, remote, nil
}

// FinishTCPConnect performs one nonblocking connection-completion check.
func (s *State) FinishTCPConnect(handle resource.Handle) (namespace.Progress, error) {
	if s == nil {
		return 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.lookupTCPStreamLocked(handle)
	if err != nil {
		return 0, err
	}
	return stream.TryFinishConnect()
}

// ReadTCP performs one bounded stream read into caller-owned memory.
func (s *State) ReadTCP(handle resource.Handle, dst []byte) (namespace.IOResult, error) {
	if s == nil {
		return namespace.IOResult{}, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.lookupTCPStreamLocked(handle)
	if err != nil {
		return namespace.IOResult{}, err
	}
	result, err := stream.TryRead(dst)
	if err == nil && !result.Valid(len(dst)) {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return result, err
}

// WriteTCP performs one bounded partial stream write from caller-owned memory.
func (s *State) WriteTCP(handle resource.Handle, src []byte) (namespace.IOResult, error) {
	if s == nil {
		return namespace.IOResult{}, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.lookupTCPStreamLocked(handle)
	if err != nil {
		return namespace.IOResult{}, err
	}
	result, err := stream.TryWrite(src)
	if err == nil && !result.Valid(len(src)) {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return result, err
}

// ShutdownTCPWrite initiates a nonblocking write-half close.
func (s *State) ShutdownTCPWrite(handle resource.Handle) (namespace.Progress, error) {
	if s == nil {
		return 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.lookupTCPStreamLocked(handle)
	if err != nil {
		return 0, err
	}
	return stream.TryShutdownWrite()
}

func (s *State) lookupTCPStreamLocked(handle resource.Handle) (namespace.TCPStream, error) {
	if s.closed || s.resources == nil {
		return nil, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(handle, resource.KindTCPStream)
	if err != nil {
		return nil, err
	}
	stream, ok := value.(namespace.TCPStream)
	if !ok {
		return nil, namespace.Fail(namespace.FailureIO, ErrInvalidBackendResult)
	}
	return stream, nil
}

// PollVisitor receives one bounded readiness result while State still owns its
// reusable event storage and lifecycle lock. The callback must not retain events.
type PollVisitor func(events []readiness.Event, report readiness.Report, progress namespace.Progress) error

// Poll performs one bounded nonblocking coordinator pass using per-instance
// scratch storage. The visitor runs before the lifecycle lock is released so no
// concurrent poll or teardown can overwrite or invalidate the result.
func (s *State) Poll(budget readiness.Budget, visit PollVisitor) (readiness.Report, namespace.Progress, error) {
	if s == nil {
		return readiness.Report{}, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.readiness == nil {
		return readiness.Report{}, 0, namespace.Fail(namespace.FailureClosed, resource.ErrClosed)
	}
	if !budget.Valid() || uint64(budget.Events) > uint64(len(s.pollEvents)) {
		return readiness.Report{}, 0, readiness.ErrInvalidBudget
	}
	events := s.pollEvents[:budget.Events]
	report, progress, err := s.readiness.TryPoll(events, budget)
	if err != nil {
		return report, progress, err
	}
	if visit != nil {
		if err := visit(events[:report.Events], report, progress); err != nil {
			return report, progress, err
		}
	}
	return report, progress, nil
}

// CloseHandle removes readiness before closing one exact kind-checked resource.
// A wrong-kind request cannot unregister a valid handle.
func (s *State) CloseHandle(handle resource.Handle, kind resource.Kind) error {
	if s == nil {
		return ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil || s.readiness == nil {
		return resource.ErrClosed
	}
	if _, err := s.resources.Lookup(handle, kind); err != nil {
		return err
	}
	s.readiness.Unregister(handle)
	err := s.resources.CloseHandle(handle, kind)
	if err == nil && kind == resource.KindNamespace && handle == s.namespace {
		s.namespace = 0
	}
	return err
}

type ownedNamespace struct {
	namespace.Namespace
	allocation *quota.Allocation
}

func (n *ownedNamespace) Close() error {
	if n == nil {
		return nil
	}
	var err error
	if n.Namespace != nil {
		err = n.Namespace.Close()
		n.Namespace = nil
	}
	if n.allocation != nil {
		n.allocation.Release()
		n.allocation = nil
	}
	return err
}

// Detach removes state before closing it, making repeated and concurrent
// detach calls exactly-once from the manager's perspective.
func (m *Manager) Detach(instance *wago.Instance) error {
	if m == nil || instance == nil {
		return ErrInvalidInstance
	}
	m.mu.Lock()
	state := m.states[instance]
	delete(m.states, instance)
	m.mu.Unlock()
	if state == nil {
		return nil
	}
	return state.Close()
}

// ForInstance returns state only for the exact attached instance pointer.
func (m *Manager) ForInstance(instance *wago.Instance) (*State, bool) {
	if m == nil || instance == nil {
		return nil, false
	}
	m.mu.RLock()
	state, ok := m.states[instance]
	m.mu.RUnlock()
	return state, ok
}

// FromHost resolves the exact calling instance through Wago's optional host
// module identity surface. HostModule-only mocks and low-level imports without
// Runtime lifecycle attachment fail closed.
func (m *Manager) FromHost(module wago.HostModule) (*State, bool) {
	identity, ok := module.(wago.InstanceHostModule)
	if !ok {
		return nil, false
	}
	return m.ForInstance(identity.Instance())
}

// Len returns the number of attached live instances.
func (m *Manager) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.states)
}
