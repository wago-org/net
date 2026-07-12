// Package instance owns networking state attached to exact Wago instances.
package core

import (
	"errors"
	"fmt"
	"sync"

	nscore "github.com/wago-org/net/internal/namespace/core"
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
type NamespaceFactory func(*policy.Policy, *quota.Account) (nscore.Namespace, error)

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
	// mu is the one attachment lifecycle mutex. Every published operation and
	// teardown path serializes through it. Manager.Detach removes a State from the
	// manager before closing it, so new lookups fail closed while any in-flight
	// operation finishes before teardown proceeds.
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
	config.Readiness.MaxRegistrations = rightSizeReadiness(config.Readiness.MaxRegistrations, config.Limits.Resources)
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

func rightSizeReadiness(configured int, resources uint64) int {
	if resources == 0 {
		return 1
	}
	if resources < uint64(configured) {
		return int(resources)
	}
	return configured
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
func (s *State) LookupNamespace(namespaceHandle resource.Handle) (nscore.Namespace, error) {
	if s == nil {
		return nil, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil {
		return nil, nscore.Fail(nscore.FailureClosed, resource.ErrClosed)
	}
	value, err := s.resources.Lookup(namespaceHandle, resource.KindNamespace)
	if err != nil {
		return nil, err
	}
	if owned, ok := value.(*ownedNamespace); ok && owned.Namespace != nil {
		return owned.Namespace, nil
	}
	backend, ok := value.(nscore.Namespace)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, ErrInvalidBackendResult)
	}
	return backend, nil
}

// LockedState exposes shared ownership primitives only while State holds its
// lifecycle mutex. Protocol operation packages must not retain these pointers.
type LockedState struct {
	Resources *resource.Table
	Readiness *readiness.Coordinator
}

// WithLock serializes one protocol operation against polling and teardown.
func (s *State) WithLock(operation func(LockedState) error) error {
	if s == nil || operation == nil {
		return ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.resources == nil || s.readiness == nil {
		return nscore.Fail(nscore.FailureClosed, resource.ErrClosed)
	}
	return operation(LockedState{Resources: s.resources, Readiness: s.readiness})
}

// PollVisitor receives one bounded readiness result while State still owns its
// reusable event storage and lifecycle lock. The callback must not retain events.
type PollVisitor func(events []readiness.Event, report readiness.Report, progress nscore.Progress) error

// Poll performs one bounded nonblocking coordinator pass using per-instance
// scratch storage. The visitor runs before the lifecycle lock is released so no
// concurrent poll or teardown can overwrite or invalidate the result.
func (s *State) Poll(budget readiness.Budget, visit PollVisitor) (readiness.Report, nscore.Progress, error) {
	if s == nil {
		return readiness.Report{}, 0, ErrInvalidConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.readiness == nil {
		return readiness.Report{}, 0, nscore.Fail(nscore.FailureClosed, resource.ErrClosed)
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
	nscore.Namespace
	allocation *quota.Allocation
}

func (n *ownedNamespace) NamespaceBackend() nscore.Namespace {
	if n == nil {
		return nil
	}
	return n.Namespace
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

// Detach unpublishes state before closing it, so fresh manager lookups fail
// closed immediately while any in-flight State operation still serializes on
// that State's lifecycle mutex until teardown completes. Repeated and
// concurrent detach calls are exactly-once from the manager's perspective.
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
