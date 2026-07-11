package net

import (
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	dnsbackend "github.com/wago-org/net/internal/backend/lneto/dns"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	udpbackend "github.com/wago-org/net/internal/backend/lneto/udp"
	dnsbinding "github.com/wago-org/net/internal/binding/dns"
	tcpbinding "github.com/wago-org/net/internal/binding/tcp"
	udpbinding "github.com/wago-org/net/internal/binding/udp"
	instancestate "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/plugin"
	wago "github.com/wago-org/wago"
)

// Init and the helpers in this file preserve the historical aggregate surface
// only for the root package's same-package regression suite. Production callers
// use compat.Init or explicit protocol registration.
func Init(config Config) *Extension {
	extension := newExtension(config)
	extension.testResolve = func(module wago.HostModule) (*instancestate.State, bool) {
		identity, ok := module.(interface{ Instance() *wago.Instance })
		if !ok {
			return nil, false
		}
		return extension.instanceManager().ForInstance(identity.Instance())
	}
	if extension.configErr == nil {
		if err := extension.registerAllProtocols(); err != nil {
			extension.configErr = err
		}
	}
	return extension
}

func (e *Extension) registerAllProtocols() error {
	for _, descriptor := range aggregateTestDescriptors(e.config) {
		if err := e.RegisterModule(descriptor); err != nil {
			return err
		}
	}
	return nil
}

func (e *Extension) registerUDPModule() error { return e.RegisterModule(udpbinding.Descriptor()) }
func (e *Extension) registerTCPModule() error { return e.RegisterModule(tcpbinding.Descriptor()) }
func (e *Extension) registerDNSModule() error { return e.RegisterModule(dnsbinding.Descriptor()) }

func aggregateTestDescriptors(config Config) []plugin.Module {
	var udpConfig udpbackend.Config
	var tcpConfig tcpbackend.Config
	var dnsConfig dnsbackend.Config
	if config.StaticIPv4 != nil {
		udpConfig = udpbackend.Config(config.StaticIPv4.UDP)
		tcpConfig = tcpbackend.Config(config.StaticIPv4.TCP)
		dnsConfig = dnsbackend.Config(config.StaticIPv4.DNS)
	}
	udpContribution := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common, ok := base.(*lnetocore.Namespace)
		if !ok {
			return nscore.Service{}, plugin.ErrInvalidBackend
		}
		adapter, err := udpbackend.New(common, udpConfig)
		return nscore.Service{Key: udpns.ServiceKey, Value: adapter}, err
	})
	tcpContribution := plugin.NewBackend(plugin.BackendLnetoV1, func(target any) error {
		common, ok := target.(*lnetocore.Config)
		if !ok {
			return plugin.ErrInvalidBackend
		}
		common.MaxActiveTCPPorts = tcpConfig.MaxListeners + tcpConfig.MaxOutboundStreams
		return nil
	}, func(base any) (nscore.Service, error) {
		common, ok := base.(*lnetocore.Namespace)
		if !ok {
			return nscore.Service{}, plugin.ErrInvalidBackend
		}
		adapter, err := tcpbackend.New(common, tcpConfig)
		return nscore.Service{Key: tcpns.ServiceKey, Value: adapter}, err
	})
	dnsContribution := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common, ok := base.(*lnetocore.Namespace)
		if !ok {
			return nscore.Service{}, plugin.ErrInvalidBackend
		}
		adapter, err := dnsbackend.New(common, dnsConfig)
		return nscore.Service{Key: dnsns.ServiceKey, Value: adapter}, err
	})
	return []plugin.Module{
		udpbinding.Descriptor(udpContribution),
		tcpbinding.Descriptor(tcpContribution),
		dnsbinding.Descriptor(dnsContribution),
	}
}

func aggregateTestHost(extension *Extension) plugin.Host {
	manager := extension.instanceManager()
	resolve := extension.testResolve
	if resolve == nil {
		resolve = func(module wago.HostModule) (*instancestate.State, bool) {
			identity, ok := module.(interface{ Instance() *wago.Instance })
			if !ok {
				return nil, false
			}
			return manager.ForInstance(identity.Instance())
		}
	}
	return plugin.NewTestHost(manager, resolve)
}

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
	return protocolTestBindings(tcpbinding.Bindings(aggregateTestHost(e)))
}

func (e *Extension) udpBindings() []binding {
	return protocolTestBindings(udpbinding.Bindings(aggregateTestHost(e)))
}

func (e *Extension) dnsBindings() []binding {
	return protocolTestBindings(dnsbinding.Bindings(aggregateTestHost(e)))
}

func (e *Extension) dnsNamespaceDefault(module wago.HostModule, params, results []uint64) {
	dnsbinding.NamespaceDefault(aggregateTestHost(e), module, params, results)
}

func (e *Extension) dnsResolve(module wago.HostModule, params, results []uint64) {
	dnsbinding.Resolve(aggregateTestHost(e), module, params, results)
}

func (e *Extension) dnsNext(module wago.HostModule, params, results []uint64) {
	dnsbinding.Next(aggregateTestHost(e), module, params, results)
}

func (e *Extension) dnsCancel(module wago.HostModule, params, results []uint64) {
	dnsbinding.Cancel(aggregateTestHost(e), module, params, results)
}

func (e *Extension) dnsClose(module wago.HostModule, params, results []uint64) {
	dnsbinding.Close(aggregateTestHost(e), module, params, results)
}

func (e *Extension) dnsPoll(module wago.HostModule, params, results []uint64) {
	dnsbinding.Poll(aggregateTestHost(e), module, params, results)
}
