package net

import (
	tcpbinding "github.com/wago-org/net/internal/binding/tcp"
	"github.com/wago-org/net/internal/plugin"
)

// tcpCompatibilityDescriptor keeps Init(Config) source-compatible while the
// aggregate compatibility constructor is moved out of the lightweight root.
// Selective callers use github.com/wago-org/net/tcp, which constructs this
// descriptor without routing through a root-owned TCP implementation.
func tcpCompatibilityDescriptor() plugin.Module {
	return tcpbinding.Descriptor()
}

// tcpBindings is retained for existing aggregate root-package tests during the
// compatibility migration. The implementation and eleven host functions live
// in the TCP-only binding package.
func (e *Extension) tcpBindings() []binding {
	protocolBindings := tcpbinding.Bindings(plugin.NewHost(e.instanceManager()))
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
