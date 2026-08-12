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
	ErrTeardownPanicked     = errors.New("net: instance teardown panicked")
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

// DefaultConfig preserves the core provider's state-only behavior: finite
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

	resources     *resource.Table
	readiness     *readiness.Coordinator
	quotas        *quota.Account
	policy        *policy.Policy
	pollEvents    []readiness.Event
	outputScratch []byte
	namespace     resource.Handle
	closed        bool
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
// when the network was configured without a namespace.
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
// reservations that never reached a resource owner. Teardown attempts every
// stage and restores all state invariants before re-propagating the first panic.
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
	var errs [2]error
	errCount := 0
	var firstPanic any
	panicked := false
	closePart := func(close func() error) {
		err, panicValue, closePanicked := runTeardownStep(close)
		if err != nil {
			errs[errCount] = err
			errCount++
		}
		if closePanicked && !panicked {
			firstPanic = panicValue
			panicked = true
		}
	}
	if s.readiness != nil {
		closePart(s.readiness.Close)
	}
	if s.resources != nil {
		closePart(s.resources.Close)
	}
	if s.quotas != nil {
		s.quotas.Close()
	}
	clear(s.pollEvents)
	s.pollEvents = nil
	clear(s.outputScratch)
	s.outputScratch = nil
	s.namespace = 0
	if panicked {
		panic(firstPanic)
	}
	switch errCount {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs[:]...)
	}
}

func runTeardownStep(step func() error) (err error, panicValue any, panicked bool) {
	completed := false
	defer func() {
		if !completed {
			panicValue = recover()
			panicked = true
		}
	}()
	err = step()
	completed = true
	return err, nil, false
}

// Manager is a provider-local attachment map. It must be owned by one Network;
// it is intentionally not a package-global registry.
type Manager struct {
	mu        sync.RWMutex
	states    map[instanceKey]*State
	attaching map[instanceKey]*attachmentAttempt
	detaching map[instanceKey]*detachmentAttempt

	policy           *policy.Policy
	limits           quota.Limits
	readiness        readiness.Config
	namespaceFactory NamespaceFactory
}

// instanceKey keeps the production opaque-identity path distinct from the
// direct-pointer path used by low-level repository fixtures.
type instanceKey struct {
	direct   *wago.Instance
	identity wago.InstanceIdentity
}

type attachmentAttempt struct {
	done chan struct{}
}

type detachmentAttempt struct {
	done chan struct{}
	err  error
}

// NewManager creates an empty provider-local manager with finite defaults and
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
		states:           make(map[instanceKey]*State),
		attaching:        make(map[instanceKey]*attachmentAttempt),
		detaching:        make(map[instanceKey]*detachmentAttempt),
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

// Attach creates and publishes one isolated state for instance. An optional
// namespace is fully quota-owned, generation-safe, and poll-registered before
// publication; every failed stage is rolled back synchronously.
func (m *Manager) Attach(instance *wago.Instance) error {
	if m == nil || instance == nil {
		return ErrInvalidInstance
	}
	return m.attach(instanceKey{direct: instance})
}

// AttachIdentity creates and publishes state for an opaque Runtime identity.
func (m *Manager) AttachIdentity(identity wago.InstanceIdentity) error {
	if m == nil || identity.IsZero() {
		return ErrInvalidInstance
	}
	return m.attach(instanceKey{identity: identity})
}

// SingleState returns the attached state only when the manager owns exactly
// one instance. It supports repository diagnostics without weakening the
// production caller-identity boundary.
func (m *Manager) SingleState() (*State, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.states) != 1 {
		return nil, false
	}
	for _, state := range m.states {
		return state, true
	}
	return nil, false
}

func (m *Manager) attach(key instanceKey) error {
	attempt, err := m.beginAttachment(key)
	if err != nil {
		return err
	}
	result := attachmentResult{}
	m.runAttachment(key, &result)
	m.completeAttachment(key, attempt, result.state, result.published, result.panicValue, result.panicked)
	return result.err
}

type attachmentResult struct {
	state      *State
	published  bool
	err        error
	panicValue any
	panicked   bool
}

// runAttachment converts a construction panic into data so lifecycle cleanup
// can finish before Attach re-panics from an ordinary call frame. In particular,
// this avoids relying on a recover-and-repanic cycle inside the same deferred
// function, which is not portable across all supported Go toolchains.
func (m *Manager) runAttachment(key instanceKey, result *attachmentResult) {
	completed := false
	defer func() {
		if !completed {
			result.panicValue = recover()
			result.panicked = true
		}
	}()
	result.err = m.attachState(key, &result.state, &result.published)
	completed = true
}

func (m *Manager) attachState(key instanceKey, state **State, published *bool) error {
	table, err := resource.NewTable()
	if err != nil {
		return fmt.Errorf("create resource table: %w", err)
	}
	*state = &State{resources: table}
	poller, err := readiness.New(table, m.readiness)
	if err != nil {
		return fmt.Errorf("create readiness coordinator: %w", err)
	}
	(*state).readiness = poller
	(*state).quotas = quota.NewAccount(m.limits)
	(*state).policy = m.policy
	(*state).pollEvents = make([]readiness.Event, m.readiness.MaxRegistrations)
	if m.namespaceFactory != nil {
		if _, err := (*state).createNamespace(m.namespaceFactory); err != nil {
			return fmt.Errorf("create instance namespace: %w", err)
		}
	}

	m.mu.Lock()
	if m.states == nil {
		m.states = make(map[instanceKey]*State)
	}
	m.states[key] = *state
	*published = true
	m.mu.Unlock()
	return nil
}

func (m *Manager) beginAttachment(key instanceKey) (*attachmentAttempt, error) {
	for {
		m.mu.Lock()
		if _, exists := m.states[key]; exists {
			m.mu.Unlock()
			return nil, ErrAlreadyAttached
		}
		if _, exists := m.attaching[key]; exists {
			m.mu.Unlock()
			return nil, ErrAlreadyAttached
		}
		if attempt := m.detaching[key]; attempt != nil {
			done := attempt.done
			m.mu.Unlock()
			<-done
			continue
		}
		if m.attaching == nil {
			m.attaching = make(map[instanceKey]*attachmentAttempt)
		}
		attempt := &attachmentAttempt{done: make(chan struct{})}
		m.attaching[key] = attempt
		m.mu.Unlock()
		return attempt, nil
	}
}

// completeAttachment retires the lifecycle record before re-propagating a
// panic. A construction panic takes precedence over a rollback-close panic;
// when construction returned normally, the rollback panic remains visible.
func (m *Manager) completeAttachment(key instanceKey, attempt *attachmentAttempt, state *State, published bool, originalPanic any, originalPanicked bool) {
	var cleanupPanic any
	if !published && state != nil {
		cleanupPanic = closeUnpublishedState(state)
	}
	m.finishAttachment(key, attempt)
	if originalPanicked {
		panic(originalPanic)
	}
	if cleanupPanic != nil {
		panic(cleanupPanic)
	}
}

// closeUnpublishedState contains only enough recovery to finish attachment
// bookkeeping. It always closes the private quota account, then returns the
// panic payload for completeAttachment to re-propagate.
func closeUnpublishedState(state *State) (panicValue any) {
	defer func() { panicValue = recover() }()
	if state.quotas != nil {
		defer state.quotas.Close()
	}
	_ = state.Close()
	return nil
}

func (m *Manager) finishAttachment(key instanceKey, attempt *attachmentAttempt) {
	m.mu.Lock()
	if m.attaching[key] == attempt {
		delete(m.attaching, key)
		close(attempt.done)
	}
	m.mu.Unlock()
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
	if resource.IsNil(backend) {
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
	if owned, ok := value.(*ownedNamespace); ok {
		if resource.IsNil(owned.Namespace) {
			return nil, nscore.Fail(nscore.FailureIO, ErrInvalidBackendResult)
		}
		return owned.Namespace, nil
	}
	backend, ok := value.(nscore.Namespace)
	if !ok || resource.IsNil(backend) {
		return nil, nscore.Fail(nscore.FailureIO, ErrInvalidBackendResult)
	}
	return backend, nil
}

// LockedState exposes shared ownership primitives only while State holds its
// lifecycle mutex. Protocol operation packages must not retain these pointers.
type LockedState struct {
	Resources     *resource.Table
	Readiness     *readiness.Coordinator
	outputScratch *[]byte
}

// OutputScratch returns zeroed instance-owned temporary output storage while
// the State lifecycle lock is held. Protocol operations must not retain the
// returned slice. Capacity grows lazily and is reused across checked calls so
// successful steady-state output paths do not add per-call garbage.
func (s LockedState) OutputScratch(size int) []byte {
	if s.outputScratch == nil || size < 0 {
		return nil
	}
	if cap(*s.outputScratch) < size {
		*s.outputScratch = make([]byte, size)
	} else {
		*s.outputScratch = (*s.outputScratch)[:size]
	}
	clear(*s.outputScratch)
	return *s.outputScratch
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
	return operation(LockedState{Resources: s.resources, Readiness: s.readiness, outputScratch: &s.outputScratch})
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
	if kind == resource.KindNamespace && handle == s.namespace {
		defer func() {
			_, lookupErr := s.resources.Lookup(handle, kind)
			if errors.Is(lookupErr, resource.ErrBadHandle) || errors.Is(lookupErr, resource.ErrClosed) {
				s.namespace = 0
			}
		}()
	}
	return s.resources.CloseHandle(handle, kind)
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
	backend := n.Namespace
	allocation := n.allocation
	n.Namespace = nil
	n.allocation = nil
	if allocation != nil {
		defer allocation.Release()
	}
	if backend != nil {
		return backend.Close()
	}
	return nil
}

// Detach unpublishes state before closing it, so fresh manager lookups fail
// closed immediately while any in-flight State operation still serializes on
// that State's lifecycle mutex until teardown completes. Repeated and
// concurrent detach calls are exactly-once from the manager's perspective.
func (m *Manager) Detach(instance *wago.Instance) error {
	if m == nil || instance == nil {
		return ErrInvalidInstance
	}
	return m.detach(instanceKey{direct: instance})
}

// DetachIdentity unpublishes and closes state for an opaque Runtime identity.
func (m *Manager) DetachIdentity(identity wago.InstanceIdentity) error {
	if m == nil || identity.IsZero() {
		return ErrInvalidInstance
	}
	return m.detach(instanceKey{identity: identity})
}

func (m *Manager) detach(key instanceKey) error {
	for {
		m.mu.Lock()
		if attempt := m.attaching[key]; attempt != nil {
			done := attempt.done
			m.mu.Unlock()
			<-done
			continue
		}
		if attempt := m.detaching[key]; attempt != nil {
			done := attempt.done
			m.mu.Unlock()
			<-done
			return attempt.err
		}
		state := m.states[key]
		if state == nil {
			m.mu.Unlock()
			return nil
		}
		delete(m.states, key)
		if m.detaching == nil {
			m.detaching = make(map[instanceKey]*detachmentAttempt)
		}
		attempt := &detachmentAttempt{done: make(chan struct{})}
		m.detaching[key] = attempt
		m.mu.Unlock()

		return m.closeDetachedState(key, attempt, state)
	}
}

func (m *Manager) closeDetachedState(key instanceKey, attempt *detachmentAttempt, state *State) error {
	result := detachmentResult{}
	runDetachedClose(state, &result)
	waiterErr := result.err
	if result.panicked {
		waiterErr = ErrTeardownPanicked
	}
	m.finishDetachment(key, attempt, waiterErr)
	if result.panicked {
		panic(result.panicValue)
	}
	return result.err
}

type detachmentResult struct {
	err        error
	panicValue any
	panicked   bool
}

func runDetachedClose(state *State, result *detachmentResult) {
	completed := false
	defer func() {
		if !completed {
			result.panicValue = recover()
			result.panicked = true
		}
	}()
	result.err = state.Close()
	completed = true
}

func (m *Manager) finishDetachment(key instanceKey, attempt *detachmentAttempt, closeErr error) {
	m.mu.Lock()
	if m.detaching[key] == attempt {
		attempt.err = closeErr
		delete(m.detaching, key)
		close(attempt.done)
	}
	m.mu.Unlock()
}

// ForInstance returns state only for the exact attached instance pointer.
func (m *Manager) ForInstance(instance *wago.Instance) (*State, bool) {
	if m == nil || instance == nil {
		return nil, false
	}
	return m.lookup(instanceKey{direct: instance})
}

// ForIdentity returns state only for the exact opaque Runtime identity.
func (m *Manager) ForIdentity(identity wago.InstanceIdentity) (*State, bool) {
	if m == nil || identity.IsZero() {
		return nil, false
	}
	return m.lookup(instanceKey{identity: identity})
}

func (m *Manager) lookup(key instanceKey) (*State, bool) {
	m.mu.RLock()
	state, ok := m.states[key]
	m.mu.RUnlock()
	return state, ok
}

// FromHost is a test-only bridge for host-module fixtures that expose a direct
// instance pointer. Production plugin calls resolve opaque identity through
// Wago's granted CallerResolver instead.
func (m *Manager) FromHost(module wago.HostModule) (*State, bool) {
	if m == nil || resource.IsNil(module) {
		return nil, false
	}
	identity, ok := module.(interface{ Instance() *wago.Instance })
	if !ok || resource.IsNil(identity) {
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
