// Package plugin provides the implementation-neutral protocol composition
// contract used by the root networking extension and its protocol subpackages.
package plugin

import (
	"errors"
	"sync"

	wago "github.com/wago-org/wago"
)

// ModuleKey is the stable identity used to reject duplicate protocol
// selection. The type lives behind Go's internal-package boundary so public
// protocol packages can share keys without expanding the root API.
type ModuleKey string

const (
	ModuleUDP ModuleKey = "udp"
	ModuleTCP ModuleKey = "tcp"
	ModuleDNS ModuleKey = "dns"
)

var (
	// ErrInvalidModule reports a protocol descriptor without a stable key or
	// registration callback.
	ErrInvalidModule = errors.New("wagonet: invalid protocol module")
	// ErrDuplicateModule reports a second registration for the same protocol.
	ErrDuplicateModule = errors.New("wagonet: protocol module already registered")
	// ErrFrozen reports registration attempted after Wago registration began.
	ErrFrozen = errors.New("wagonet: protocol registration is frozen")
)

// Module is an opaque, trusted protocol registration descriptor. Public
// protocol packages construct descriptors inside this module; ordinary users
// select them through tcp.Register, udp.Register, or dns.Register.
type Module struct {
	key     ModuleKey
	install func(*wago.Registry, Host)
}

// NewModule constructs one protocol descriptor. It is intentionally available
// only below github.com/wago-org/net's internal-package boundary.
func NewModule(key ModuleKey, install func(*wago.Registry, Host)) Module {
	return Module{key: key, install: install}
}

// Install contributes this module's capability and imports to a Wago registry
// using the exact shared instance host owned by the root network.
func (m Module) Install(registry *wago.Registry, host Host) {
	m.install(registry, host)
}

// Set records selected protocol modules until the network is frozen.
type Set struct {
	mu      sync.Mutex
	frozen  bool
	modules []Module
	keys    map[ModuleKey]struct{}
}

// Add selects one protocol module. Duplicate registration is rejected with a
// stable error rather than silently changing authority.
func (s *Set) Add(module Module) error {
	if module.key == "" || module.install == nil {
		return ErrInvalidModule
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frozen {
		return ErrFrozen
	}
	if _, exists := s.keys[module.key]; exists {
		return ErrDuplicateModule
	}
	if s.keys == nil {
		s.keys = make(map[ModuleKey]struct{})
	}
	s.keys[module.key] = struct{}{}
	s.modules = append(s.modules, module)
	return nil
}

// Freeze prevents further authority changes and returns an immutable
// registration-order snapshot.
func (s *Set) Freeze() []Module {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frozen = true
	return append([]Module(nil), s.modules...)
}
