// Package instance owns networking state attached to exact Wago instances.
package instance

import (
	"errors"
	"fmt"
	"sync"

	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

var (
	ErrInvalidInstance = errors.New("net: invalid Wago instance")
	ErrAlreadyAttached = errors.New("net: instance state already attached")
)

// State is the networking ownership root for one exact Wago instance.
type State struct {
	resources *resource.Table
}

// Resources returns the instance's generation-safe resource table.
func (s *State) Resources() *resource.Table {
	if s == nil {
		return nil
	}
	return s.resources
}

// Close releases all instance-owned resources.
func (s *State) Close() error {
	if s == nil || s.resources == nil {
		return nil
	}
	return s.resources.Close()
}

// Manager is an extension-local attachment map. It must be owned by an
// extension value; it is intentionally not a package-global registry.
type Manager struct {
	mu     sync.RWMutex
	states map[*wago.Instance]*State
}

// NewManager creates an empty extension-local manager.
func NewManager() *Manager {
	return &Manager{states: make(map[*wago.Instance]*State)}
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

// Attach creates and publishes one resource table for instance.
func (m *Manager) Attach(instance *wago.Instance) error {
	if m == nil || instance == nil {
		return ErrInvalidInstance
	}
	table, err := resource.NewTable()
	if err != nil {
		return fmt.Errorf("create resource table: %w", err)
	}
	state := &State{resources: table}

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
