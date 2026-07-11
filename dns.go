package net

import (
	dnsbinding "github.com/wago-org/net/internal/binding/dns"
	"github.com/wago-org/net/internal/plugin"
	wago "github.com/wago-org/wago"
)

// dnsCompatibilityDescriptor keeps Init(Config) source-compatible while the
// aggregate compatibility constructor is moved out of the lightweight root.
// Selective callers use github.com/wago-org/net/dns, which constructs this
// descriptor without routing through a root-owned DNS implementation.
func dnsCompatibilityDescriptor() plugin.Module {
	return dnsbinding.Descriptor()
}

// dnsBindings is retained for existing aggregate root-package tests during the
// compatibility migration. The implementation and six host functions live in
// the DNS-only binding package.
func (e *Extension) dnsBindings() []binding {
	protocolBindings := dnsbinding.Bindings(plugin.NewHost(e.instanceManager()))
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

// The host-function forwarding methods retain the aggregate root test surface
// while DNS implementation ownership moves to internal/binding/dns.
func (e *Extension) dnsNamespaceDefault(module wago.HostModule, params, results []uint64) {
	dnsbinding.NamespaceDefault(plugin.NewHost(e.instanceManager()), module, params, results)
}

func (e *Extension) dnsResolve(module wago.HostModule, params, results []uint64) {
	dnsbinding.Resolve(plugin.NewHost(e.instanceManager()), module, params, results)
}

func (e *Extension) dnsNext(module wago.HostModule, params, results []uint64) {
	dnsbinding.Next(plugin.NewHost(e.instanceManager()), module, params, results)
}

func (e *Extension) dnsCancel(module wago.HostModule, params, results []uint64) {
	dnsbinding.Cancel(plugin.NewHost(e.instanceManager()), module, params, results)
}

func (e *Extension) dnsClose(module wago.HostModule, params, results []uint64) {
	dnsbinding.Close(plugin.NewHost(e.instanceManager()), module, params, results)
}

func (e *Extension) dnsPoll(module wago.HostModule, params, results []uint64) {
	dnsbinding.Poll(plugin.NewHost(e.instanceManager()), module, params, results)
}
