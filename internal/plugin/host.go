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
}

// NewHost binds protocol modules to one extension-local instance manager.
func NewHost(instances *instance.Manager) Host {
	return Host{instances: instances}
}

// State resolves networking state only for the exact calling Runtime instance.
// HostModule-only mocks and detached instances fail closed.
func (h Host) State(module wago.HostModule) (*instance.State, bool) {
	if h.instances == nil || module == nil {
		return nil, false
	}
	return h.instances.FromHost(module)
}
