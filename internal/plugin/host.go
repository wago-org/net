package plugin

import (
	instance "github.com/wago-org/net/internal/instance/core"
	wago "github.com/wago-org/wago"
)

// Host is the protocol-neutral bridge from independently compiled guest
// bindings to the root network's exact-instance ownership manager. Its fields
// remain private so protocol modules cannot replace lifecycle ownership.
type Host struct {
	instances   *instance.Manager
	testResolve func(wago.HostModule) (*instance.State, bool)
}

// NewHost binds protocol modules to one extension-local instance manager.
func NewHost(instances *instance.Manager) Host {
	return Host{instances: instances}
}

// NewTestHost supplies a same-module regression resolver without weakening the
// production caller-identity path. It is used only by the root package's
// historical direct-binding tests, which need synthetic guest memory.
func NewTestHost(instances *instance.Manager, resolve func(wago.HostModule) (*instance.State, bool)) Host {
	return Host{instances: instances, testResolve: resolve}
}

// State resolves networking state only for the exact calling Runtime instance.
// HostModule-only mocks and detached instances fail closed.
func (h Host) State(module wago.HostModule) (*instance.State, bool) {
	if h.instances == nil || module == nil {
		return nil, false
	}
	if h.testResolve != nil {
		if state, ok := h.testResolve(module); ok {
			return state, true
		}
	}
	return h.instances.FromHost(module)
}
