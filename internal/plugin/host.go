package plugin

import (
	instance "github.com/wago-org/net/internal/instance/core"
	wago "github.com/wago-org/wago"
)

// Host is the protocol-neutral bridge from independently compiled guest
// bindings to the root network's exact-instance ownership manager. Its fields
// remain private so protocol modules cannot replace lifecycle ownership.
type Host struct {
	instances *instance.Manager
	callers   *wago.CallerResolver
}

// NewHost binds protocol modules to one fixture-local instance manager.
func NewHost(instances *instance.Manager) Host {
	return Host{instances: instances}
}

// NewRuntimeHost binds protocol modules to the opaque caller identity resolver
// granted to the owning Wago plugin.
func NewRuntimeHost(instances *instance.Manager, callers *wago.CallerResolver) Host {
	return Host{instances: instances, callers: callers}
}

// State resolves networking state only for the exact calling Runtime instance.
// HostModule-only mocks and detached instances fail closed.
func (h Host) State(module wago.HostModule) (*instance.State, bool) {
	if h.instances == nil || module == nil {
		return nil, false
	}
	if h.callers != nil {
		identity, err := h.callers.Resolve(module)
		if err != nil {
			return nil, false
		}
		return h.instances.ForIdentity(identity)
	}
	return h.instances.FromHost(module)
}
