// Package plugin provides the implementation-neutral protocol composition
// contract used by the root networking extension and its protocol subpackages.
package plugin

import (
	"errors"
	"sync"

	nscore "github.com/wago-org/net/internal/namespace/core"
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
	// ErrInvalidBackend reports an incomplete opaque backend contribution.
	ErrInvalidBackend = errors.New("wagonet: invalid protocol backend contribution")
	// ErrIncompatibleBackend reports a contribution for a different backend
	// family than the shared namespace selected by the root network.
	ErrIncompatibleBackend = errors.New("wagonet: incompatible protocol backend contribution")
)

// BackendFamily identifies one shared backend assembly contract. Protocol
// modules selected on one network must contribute to the same family.
type BackendFamily string

const (
	// BackendLnetoV1 is the first shared static IPv4 backend family.
	BackendLnetoV1 BackendFamily = "lneto.static-ipv4.v1"
)

// Backend is an opaque protocol-local contribution. Configure may add finite
// requirements to an unallocated shared backend config. Install attaches one
// service to the fully allocated exact-instance base namespace.
type Backend struct {
	enabled   bool
	family    BackendFamily
	configure func(any) error
	install   func(any) (nscore.Service, error)
}

// NewBackend constructs one trusted backend contribution below this module's
// internal-package boundary.
func NewBackend(family BackendFamily, configure func(any) error, install func(any) (nscore.Service, error)) Backend {
	return Backend{enabled: true, family: family, configure: configure, install: install}
}

func (b Backend) valid() bool { return b.family != "" && b.install != nil }

// Module is an opaque, trusted protocol registration descriptor. Public
// protocol packages construct descriptors inside this module; ordinary users
// select them through tcp.Register, udp.Register, or dns.Register.
type Module struct {
	key     ModuleKey
	install func(*wago.Registry, Host)
	backend Backend
}

// NewModule constructs one protocol descriptor. It is intentionally available
// only below github.com/wago-org/net's internal-package boundary.
func NewModule(key ModuleKey, install func(*wago.Registry, Host), backend ...Backend) Module {
	module := Module{key: key, install: install}
	if len(backend) == 1 {
		module.backend = backend[0]
	} else if len(backend) > 1 {
		module.backend = Backend{enabled: true, family: BackendFamily("invalid")}
	}
	return module
}

// Install contributes this module's capability and imports to a Wago registry
// using the exact shared instance host owned by the root network.
func (m Module) Install(registry *wago.Registry, host Host) {
	m.install(registry, host)
}

// ConfigureBackend contributes protocol-local requirements before the shared
// backend is allocated. Modules without backend state are ignored.
func (m Module) ConfigureBackend(family BackendFamily, target any) error {
	if !m.backend.enabled {
		return nil
	}
	if !m.backend.valid() {
		return ErrInvalidBackend
	}
	if m.backend.family != family {
		return ErrIncompatibleBackend
	}
	if m.backend.configure == nil {
		return nil
	}
	return m.backend.configure(target)
}

// InstallBackend attaches one protocol-local service to an exact shared base.
// The bool is false only for modules that own no backend state.
func (m Module) InstallBackend(family BackendFamily, base any) (nscore.Service, bool, error) {
	if !m.backend.enabled {
		return nscore.Service{}, false, nil
	}
	if !m.backend.valid() {
		return nscore.Service{}, false, ErrInvalidBackend
	}
	if m.backend.family != family {
		return nscore.Service{}, false, ErrIncompatibleBackend
	}
	service, err := m.backend.install(base)
	return service, true, err
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
	if module.backend.enabled && !module.backend.valid() {
		return ErrInvalidBackend
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
