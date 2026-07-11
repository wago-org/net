package net

import (
	dnsbinding "github.com/wago-org/net/internal/binding/dns"
	tcpbinding "github.com/wago-org/net/internal/binding/tcp"
	udpbinding "github.com/wago-org/net/internal/binding/udp"
	"github.com/wago-org/net/internal/plugin"
	wago "github.com/wago-org/wago"
)

// Init and the helpers in this file preserve the historical aggregate surface
// only for the root package's same-package regression suite. Production callers
// use compat.Init or explicit protocol registration.
func Init(config Config) *Extension {
	extension := newExtension(config)
	if extension.configErr == nil {
		if err := extension.registerAllProtocols(); err != nil {
			extension.configErr = err
		}
	}
	return extension
}

func (e *Extension) registerAllProtocols() error {
	for _, descriptor := range []plugin.Module{
		udpbinding.Descriptor(),
		tcpbinding.Descriptor(),
		dnsbinding.Descriptor(),
	} {
		if err := e.RegisterModule(descriptor); err != nil {
			return err
		}
	}
	return nil
}

func (e *Extension) registerUDPModule() error { return e.RegisterModule(udpbinding.Descriptor()) }
func (e *Extension) registerTCPModule() error { return e.RegisterModule(tcpbinding.Descriptor()) }
func (e *Extension) registerDNSModule() error { return e.RegisterModule(dnsbinding.Descriptor()) }

func protocolTestBindings(bindings []plugin.Binding) []binding {
	converted := make([]binding, len(bindings))
	for i, protocolBinding := range bindings {
		converted[i] = binding{
			name:       protocolBinding.Name,
			fn:         protocolBinding.Func,
			params:     protocolBinding.Params,
			results:    protocolBinding.Results,
			capability: protocolBinding.Capability,
			docs:       protocolBinding.Docs,
		}
	}
	return converted
}

func (e *Extension) tcpBindings() []binding {
	return protocolTestBindings(tcpbinding.Bindings(plugin.NewHost(e.instanceManager())))
}

func (e *Extension) udpBindings() []binding {
	return protocolTestBindings(udpbinding.Bindings(plugin.NewHost(e.instanceManager())))
}

func (e *Extension) dnsBindings() []binding {
	return protocolTestBindings(dnsbinding.Bindings(plugin.NewHost(e.instanceManager())))
}

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
