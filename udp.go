package net

import (
	udpbinding "github.com/wago-org/net/internal/binding/udp"
	"github.com/wago-org/net/internal/guest"
	"github.com/wago-org/net/internal/instance"
	"github.com/wago-org/net/internal/plugin"
	wago "github.com/wago-org/wago"
)

// udpCompatibilityDescriptor keeps Init(Config) source-compatible while the
// aggregate compatibility constructor is moved out of the lightweight root.
// Selective callers use github.com/wago-org/net/udp, which constructs this
// descriptor without routing through a root-owned UDP implementation.
func udpCompatibilityDescriptor() plugin.Module {
	return udpbinding.Descriptor()
}

// udpBindings is retained for existing aggregate root-package tests during the
// compatibility migration. The implementation and six host functions live in
// the UDP-only binding package.
func (e *Extension) udpBindings() []binding {
	protocolBindings := udpbinding.Bindings(plugin.NewHost(e.instanceManager()))
	bindings := make([]binding, len(protocolBindings))
	for i, protocolBinding := range protocolBindings {
		bindings[i] = binding{
			name:       protocolBinding.Name,
			fn:         protocolBinding.Func,
			params:     protocolBinding.Params,
			results:    protocolBinding.Results,
			capability: protocolBinding.Capability,
			docs:       protocolBinding.Docs,
		}
	}
	return bindings
}

// The remaining helpers support the not-yet-extracted aggregate DNS shim.
func (e *Extension) poll(module wago.HostModule, params, results []uint64) {
	guest.Poll(plugin.NewHost(e.instanceManager()), module, params, results)
}

func (e *Extension) udpState(module wago.HostModule) (*instance.State, Status) {
	state, ok := plugin.NewHost(e.instanceManager()).State(module)
	if !ok || state == nil {
		return nil, StatusInvalidState
	}
	return state, StatusOK
}

func moduleMemory(module wago.HostModule) []byte {
	return guest.Memory(module)
}

func setStatus(results []uint64, status Status) {
	guest.SetStatus(results, status)
}
