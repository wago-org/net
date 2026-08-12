// Package net provides the core of Wago's capability-gated networking plugin
// suite. The guest ABI is backend-neutral; lneto is the first backend and is
// not part of the public contract. Complete UDP, TCP, bounded DNS, ICMPv4 echo,
// explicit-clock NTP, bounded mDNS, DHCPv4, IPv4 link-local, configured IPv6,
// bounded ICMPv6/NDP, bounded initial DHCPv6 acquisition, and granular outbound
// TLS client modules are independently capability-gated. Runtime registration requires physical
// reinstantiation between class leases so instance-owned network state cannot
// survive an in-place Wasm memory reset.
package net

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"

	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	instancestate "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	wago "github.com/wago-org/wago"
	wagoplugin "github.com/wago-org/wago/plugin"
)

const PluginID = "github.com/wago-org/net"

// Service is the major-versioned cross-plugin networking seam. Implementations
// expose immutable topology and exact-caller readiness without leaking Runtime,
// instance, namespace, or resource ownership.
type Service interface {
	ImportModules() []string
	Ready(wago.HostModule) bool
}

// Contract is the typed v1 networking composition seam.
var Contract = wagoplugin.NewContract[Service](PluginID+"/service", 1)

var emptyConfigSchema = json.RawMessage(`{
  "type": "object",
  "additionalProperties": false
}`)

// ProviderSpec describes one explicitly linked networking composition. Modules
// is the exact Wasm host-import authority scope; Factory must return a fresh,
// fully configured protocol composition.
type ProviderSpec struct {
	ID          string
	Name        string
	Description string
	Modules     []string
	Factory     func() (*Network, error)
}

// Definition returns immutable metadata for one networking composition.
func Definition(spec ProviderSpec) wago.PluginDefinition {
	modules := append([]string(nil), spec.Modules...)
	sort.Strings(modules)
	return wago.PluginDefinition{
		ID: spec.ID, Name: spec.Name, Version: "0.1.0", Description: spec.Description,
		Stability:     wago.Experimental,
		Compatibility: wago.Compatibility{Engines: map[string]string{"wago": ">=0.1.0"}},
		Provenance: wago.PluginProvenance{
			Homepage: "https://github.com/wago-org/net#readme", Repository: "https://github.com/wago-org/net", License: "Apache-2.0",
			Authors: []string{"Wago contributors"},
		},
		Authorities: []wago.AuthorityRequest{
			{Name: wago.AuthorityHostImportDefine, Mode: wago.AuthorityRequired, Reason: "define the selected checked networking guest imports", Scope: wago.AuthorityScope{Modules: modules}},
			{Name: wago.AuthorityHostCallerIdentify, Mode: wago.AuthorityRequired, Reason: "resolve exact synchronous callers without instance authority"},
			{Name: wago.AuthorityInstanceInstantiateIntercept, Mode: wago.AuthorityRequired, Reason: "transactionally attach isolated network state before guest start"},
			{Name: wago.AuthorityInstanceCloseObserve, Mode: wago.AuthorityRequired, Reason: "detach network state before exact instance resources close"},
		},
		ConfigSchema: append(json.RawMessage(nil), emptyConfigSchema...),
		Provides:     []wago.ContractSpec{Contract.Spec()},
	}
}

// Provider is a side-effect-free catalog entry for an exact composition.
func Provider(spec ProviderSpec) wago.PluginProvider {
	modules := append([]string(nil), spec.Modules...)
	sort.Strings(modules)
	definitionSpec := spec
	definitionSpec.Modules = modules
	return wago.PluginProvider{
		Definition: Definition(definitionSpec),
		New: func() wago.Plugin {
			return &providerPlugin{factory: spec.Factory, modules: append([]string(nil), modules...)}
		},
		ValidateConfig: validateEmptyPluginConfig,
	}
}

type providerPlugin struct {
	factory func() (*Network, error)
	modules []string
}

func (p *providerPlugin) Register(reg *wago.Registrar) error {
	if p == nil || p.factory == nil {
		return fmt.Errorf("wagonet: nil provider factory")
	}
	var config struct{}
	if err := reg.Config(&config); err != nil {
		return err
	}
	network, err := p.factory()
	if err != nil {
		return err
	}
	if network == nil {
		return instancestate.ErrInvalidConfig
	}
	return network.registerPlugin(reg, p.modules)
}

func validateEmptyPluginConfig(raw json.RawMessage) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if err := validateConfigObject(raw); err != nil {
		return fmt.Errorf("wagonet: config: %w", err)
	}
	var config struct{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("wagonet: config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("wagonet: config has a trailing JSON value")
	}
	return nil
}

func validateConfigObject(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("must be a JSON object")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("field %q must not be null", key)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return fmt.Errorf("has a trailing JSON value")
		}
		return err
	}
	return nil
}

const (
	// Module is the core networking WebAssembly import module.
	Module = "wago_net"
	// UDPModule independently owns the complete guest UDP operation surface.
	UDPModule = "wago_net_udp"
	// TCPModule owns the complete guest TCP operation surface.
	TCPModule = "wago_net_tcp"
	// DNSModule owns the complete checked bounded DNS surface.
	DNSModule = "wago_net_dns"
	// ICMPv4Module owns the complete checked bounded ICMPv4 echo surface.
	ICMPv4Module = "wago_net_icmpv4"
	// NTPModule owns the complete checked bounded NTP client surface.
	NTPModule = "wago_net_ntp"
	// MDNSModule owns bounded multicast DNS query, response, and announcement operations.
	MDNSModule = "wago_net_mdns"
	// DHCPv4Module owns bounded client leases and explicitly configured server service.
	DHCPv4Module = "wago_net_dhcpv4"
	// LinkLocal4Module owns bounded RFC 3927 claim-and-defend operations.
	LinkLocal4Module = "wago_net_linklocal4"
	// IPv6Module owns configured IPv6 namespace introspection and bounded service.
	IPv6Module = "wago_net_ipv6"
	// ICMPv6Module owns bounded ICMPv6 echo and Neighbor Discovery.
	ICMPv6Module = "wago_net_icmpv6"
	// DHCPv6Module owns the bounded initial DHCPv6 acquisition subset.
	DHCPv6Module = "wago_net_dhcpv6"
	// TLSModule owns the outbound verified TLS client surface.
	TLSModule = "wago_net_tls"

	// ABIVersion1 encodes ABI version 1.0 as major in the upper 16 bits and minor
	// in the lower 16 bits.
	ABIVersion1 uint32 = 0x0001_0000

	// CapInfo permits a guest to inspect the networking ABI and interfaces.
	CapInfo wago.Capability = "net.info"
	// CapUDP permits checked nonblocking UDP namespace, socket, and poll access.
	CapUDP wago.Capability = "net.udp"
	// CapTCP permits checked nonblocking TCP listener, stream, and poll access.
	CapTCP wago.Capability = "net.tcp"
	// CapDNS permits checked nonblocking bounded DNS queries and poll access.
	CapDNS wago.Capability = "net.dns"
	// CapICMPv4 permits checked nonblocking bounded ICMPv4 echo and poll access.
	CapICMPv4 wago.Capability = "net.icmpv4"
	// CapNTP permits checked nonblocking bounded NTP synchronization and poll access.
	CapNTP wago.Capability = "net.ntp"
	// CapMDNS permits checked bounded multicast DNS operations and poll access.
	CapMDNS wago.Capability = "net.mdns"
	// CapDHCPv4 permits checked bounded DHCPv4 lease operations and poll access.
	CapDHCPv4 wago.Capability = "net.dhcpv4"
	// CapLinkLocal4 permits checked bounded IPv4 link-local claim operations and poll access.
	CapLinkLocal4 wago.Capability = "net.linklocal4"
	// CapIPv6 permits checked configured IPv6 namespace introspection and service.
	CapIPv6 wago.Capability = "net.ipv6"
	// CapICMPv6 permits checked bounded ICMPv6 echo and Neighbor Discovery.
	CapICMPv6 wago.Capability = "net.icmpv6"
	// CapDHCPv6 permits the checked bounded initial DHCPv6 acquisition subset.
	CapDHCPv6 wago.Capability = "net.dhcpv6"
	// CapTLS permits checked outbound verified TLS client streams.
	CapTLS wago.Capability = "net.tls"
)

// PolicyConfig and related aliases expose the backend-neutral authority model
// without making callers import an internal package.
type PolicyConfig = policy.Config
type PolicyRule = policy.Rule
type PolicyAction = policy.Action
type PolicyTransport = policy.Transport
type PolicyDirection = policy.Direction
type PolicyPortRange = policy.PortRange

const (
	PolicyDeny  = policy.ActionDeny
	PolicyAllow = policy.ActionAllow

	PolicyTransportUDP        = policy.TransportUDP
	PolicyTransportTCP        = policy.TransportTCP
	PolicyTransportDNS        = policy.TransportDNS
	PolicyTransportICMPv4     = policy.TransportICMPv4
	PolicyTransportNTP        = policy.TransportNTP
	PolicyTransportMDNS       = policy.TransportMDNS
	PolicyTransportDHCPv4     = policy.TransportDHCPv4
	PolicyTransportLinkLocal4 = policy.TransportLinkLocal4
	PolicyTransportIPv6       = policy.TransportIPv6
	PolicyTransportICMPv6     = policy.TransportICMPv6
	PolicyTransportDHCPv6     = policy.TransportDHCPv6
	PolicyTransportTLS        = policy.TransportTLS

	PolicyInbound  = policy.DirectionInbound
	PolicyOutbound = policy.DirectionOutbound
)

// QuotaLimits and ReadinessConfig are finite per-instance limits. Zero values
// deny the corresponding class; pointers in Config distinguish explicit zero
// limits from the network defaults.
type QuotaLimits = quota.Limits
type ReadinessConfig = readiness.Config

// PacketLinkConfig fixes packet ownership storage for one static namespace.
type PacketLinkConfig = packetlink.Config

// UDPConfig fixes per-socket buffers, queues, payload size, and the maximum
// number of lneto registrations available to one namespace. Zero MaxSockets
// disables UDP truthfully.
type UDPConfig struct {
	MaxSockets        uint16
	ReceiveBytes      int
	TransmitBytes     int
	ReceiveDatagrams  int
	TransmitDatagrams int
	MaxPayloadBytes   int
}

// TCPConfig fixes per-stream buffers, packet tracking, listener backlog, and
// finite lneto registration counts. Zero listener and outbound limits disable
// TCP without exposing guest imports.
type TCPConfig struct {
	MaxListeners       uint16
	MaxOutboundStreams uint16
	AcceptBacklog      uint16
	ReceiveBytes       int
	TransmitBytes      int
	TransmitPackets    int
}

// DNSConfig fixes one static IPv4 recursive resolver plus finite query,
// response, retry, and record-retention bounds. MaxQueries limits live guest
// query handles until close even after a terminal query has already retired its
// transport state. Zero MaxQueries disables DNS operations truthfully while
// leaving the capability-gated module inspectable.
type DNSConfig struct {
	Server               netip.Addr
	MaxQueries           uint16
	MaxRecords           uint16
	MaxResponseBytes     int
	MaxAttempts          uint16
	RetryServiceAttempts uint16
}

// StaticIPv4Config configures one isolated lneto-backed IPv4 namespace per
// Runtime instance without exposing lneto types in the host configuration.
type StaticIPv4Config struct {
	Hostname               string
	RandSeed               int64
	HardwareAddress        [6]byte
	GatewayHardwareAddress [6]byte
	IPv4Address            netip.Addr
	MTU                    uint16
	Link                   PacketLinkConfig
	UDP                    UDPConfig
	TCP                    TCPConfig
	DNS                    DNSConfig
}

// Config configures immutable authority and finite instance-owned networking
// state. A nil StaticIPv4 leaves the network state-only and guest-visible
// inspection remains unchanged.
type Config struct {
	Policy     PolicyConfig
	Limits     *QuotaLimits
	Readiness  *ReadinessConfig
	StaticIPv4 *StaticIPv4Config
}

var (
	// ErrInvalidProtocolRegistration reports a protocol descriptor or
	// compatibility selector without a stable implementation.
	ErrInvalidProtocolRegistration = plugin.ErrInvalidModule
	// ErrProtocolRegistrationFrozen reports protocol selection attempted after
	// Wago registration has frozen the network's authority surface.
	ErrProtocolRegistrationFrozen = plugin.ErrFrozen
	// ErrProtocolAlreadyRegistered reports duplicate selection of one protocol.
	ErrProtocolAlreadyRegistered = plugin.ErrDuplicateModule
)

// Option configures shared network composition. Protocol-specific options live
// in the tcp, tls, udp, dns, icmpv4, ntp, mdns, dhcpv4, linklocal4, ipv6,
// icmpv6, and dhcpv6 packages rather than in the root package.
type Option interface {
	applyNetwork(*Config) error
}

type optionFunc func(*Config) error

func (option optionFunc) applyNetwork(config *Config) error { return option(config) }

// WithConfig preserves the aggregate advanced configuration path while the
// selective protocol packages become the primary API.
func WithConfig(config Config) Option {
	return optionFunc(func(target *Config) error {
		*target = config
		return nil
	})
}

// Network is the shared Wago networking composition and lifecycle builder.
type Network struct {
	config    Config
	configErr error
	modules   plugin.Set

	stateOnce sync.Once
	instances *instancestate.Manager
	stateErr  error
}

// New constructs an initially protocol-free network. Protocol packages select
// their exact capability and import surface before the network is passed to
// Wago. Registration freezes on the first Wago Register call.
func New(options ...Option) *Network {
	var config Config
	for _, option := range options {
		if option == nil {
			return &Network{configErr: instancestate.ErrInvalidConfig}
		}
		if err := option.applyNetwork(&config); err != nil {
			return &Network{config: config, configErr: err}
		}
	}
	return newNetwork(config)
}

func newNetwork(config Config) *Network {
	return &Network{config: cloneConfig(config)}
}

func cloneConfig(config Config) Config {
	cloned := config
	cloned.Policy = policy.Merge(config.Policy)
	if config.Limits != nil {
		limits := *config.Limits
		cloned.Limits = &limits
	}
	if config.Readiness != nil {
		readiness := *config.Readiness
		cloned.Readiness = &readiness
	}
	if config.StaticIPv4 != nil {
		staticIPv4 := *config.StaticIPv4
		cloned.StaticIPv4 = &staticIPv4
	}
	return cloned
}

func (e *Network) initialize(modules []plugin.Module) (*instancestate.Manager, error) {
	if e == nil {
		return nil, instancestate.ErrInvalidConfig
	}
	e.stateOnce.Do(func() {
		if e.instances != nil {
			return
		}
		e.instances, e.stateErr = e.buildManager(modules)
	})
	return e.instances, e.stateErr
}

func (e *Network) buildManager(modules []plugin.Module) (*instancestate.Manager, error) {
	managerConfig := instancestate.DefaultConfig()
	managerConfig.Policy = policy.Merge(e.config.Policy)
	for _, module := range modules {
		if err := module.ConfigureAuthority(&managerConfig.Policy); err != nil {
			return nil, err
		}
	}
	if e.config.Limits != nil {
		managerConfig.Limits = *e.config.Limits
	}
	if e.config.Readiness != nil {
		managerConfig.Readiness = *e.config.Readiness
	}
	if e.config.StaticIPv4 != nil {
		backendConfig := lnetoCoreConfig(*e.config.StaticIPv4)
		for _, module := range modules {
			if err := module.ConfigureBackend(plugin.BackendLnetoV1, &backendConfig); err != nil {
				return nil, err
			}
		}
		if err := lnetocore.ValidateConfig(backendConfig); err != nil {
			return nil, err
		}
		managerConfig.NamespaceFactory = func(compiled *policy.Policy, account *quota.Account) (nscore.Namespace, error) {
			instanceConfig := backendConfig
			instanceConfig.Policy = compiled
			instanceConfig.Quotas = account
			common, err := lnetocore.New(instanceConfig)
			if err != nil {
				return nil, err
			}
			composed, err := installNamespaceServices(common, modules)
			if err != nil {
				_ = common.Close()
				return nil, err
			}
			return composed, nil
		}
	}
	return instancestate.NewManagerConfigured(managerConfig)
}

func installNamespaceServices(common nscore.Namespace, modules []plugin.Module) (nscore.Namespace, error) {
	var inline [nscore.InlineServiceCapacity]nscore.Service
	services := inline[:0]
	for _, module := range modules {
		service, installed, err := module.InstallBackend(plugin.BackendLnetoV1, common)
		if err != nil {
			return nil, err
		}
		if installed {
			services = append(services, service)
		}
	}
	return nscore.ComposeNamespace(common, services...)
}

// RegisterModule installs one opaque protocol descriptor. The internal type in
// this signature deliberately limits direct use to this module's public
// protocol packages.
func (e *Network) RegisterModule(module plugin.Module) error {
	if e == nil {
		return instancestate.ErrInvalidConfig
	}
	return e.modules.Add(module)
}

// registerPlugin declares the exact networking imports and lifecycle owned by
// one explicit provider.
func (e *Network) registerPlugin(reg *wago.Registrar, declaredModules []string) error {
	if e == nil || e.configErr != nil {
		if e == nil {
			return instancestate.ErrInvalidConfig
		}
		return e.configErr
	}
	modules := e.modules.Freeze()
	if len(modules) == 0 {
		return fmt.Errorf("wagonet: provider selected no protocol modules")
	}
	instances, err := e.initialize(modules)
	if err != nil {
		return err
	}
	imports, err := reg.HostImports()
	if err != nil {
		return err
	}
	callers, err := reg.HostCallers()
	if err != nil {
		return err
	}
	instantiate, err := reg.InstanceInstantiateInterceptor()
	if err != nil {
		return err
	}
	if err := instantiate.After(func(event wago.InstantiationEvent) error {
		return instances.AttachIdentity(event.Instance)
	}); err != nil {
		return err
	}
	closeObserver, err := reg.InstanceCloseObserver()
	if err != nil {
		return err
	}
	if err := closeObserver.Before(func(event wago.InstanceCloseEvent) {
		_ = instances.DetachIdentity(event.Instance)
	}); err != nil {
		return err
	}
	if err := reg.GuestCapability(CapInfo, wago.CapabilityDocs("inspect the Wago networking ABI and interfaces")); err != nil {
		return err
	}
	coreModule, err := imports.Module(Module)
	if err != nil {
		return err
	}
	registerBindings(coreModule, e.bindings())
	host := plugin.NewRuntimeHost(instances, callers)
	for _, module := range modules {
		if err := module.Install(reg, imports, host); err != nil {
			return err
		}
	}
	service := &networkService{modules: append([]string(nil), declaredModules...), instances: instances, callers: callers}
	return wagoplugin.Provide(reg, Contract, Service(service))
}

type networkService struct {
	modules   []string
	instances *instancestate.Manager
	callers   *wago.CallerResolver
}

func (s *networkService) ImportModules() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.modules...)
}

func (s *networkService) Ready(caller wago.HostModule) bool {
	if s == nil || s.instances == nil || s.callers == nil {
		return false
	}
	identity, err := s.callers.Resolve(caller)
	if err != nil {
		return false
	}
	_, ok := s.instances.ForIdentity(identity)
	return ok
}

// InfoImports returns the explicit stateless core host imports for Wago's
// low-level Instantiate path. It is limited to shared inspection helpers such
// as abi_version; resource-owning protocol imports require the Runtime
// provider path so per-instance lifecycle state can be attached and cleaned.
func InfoImports() wago.Imports {
	imports := make(wago.Imports)
	for _, binding := range newNetwork(Config{}).bindings() {
		imports[Module+"."+binding.name] = binding.fn
	}
	return imports
}

// Imports preserves the historical low-level helper surface. Only the zero
// configuration is accepted because low-level imports cannot own configured
// protocol resources or lifecycle state; configured callers must fail closed
// and use the Runtime provider path instead.
func Imports(config Config) wago.Imports {
	if !lowLevelImportsAllowed(config) {
		return nil
	}
	return InfoImports()
}

func lowLevelImportsAllowed(config Config) bool {
	if config.Limits != nil || config.Readiness != nil || config.StaticIPv4 != nil {
		return false
	}
	return !policyConfigConfigured(config.Policy)
}

func policyConfigConfigured(config policy.Config) bool {
	return len(config.Rules) != 0 ||
		config.AllowWildcardBind || config.AllowLoopback || config.AllowMulticast || config.AllowBroadcast || config.AllowPrivilegedBind ||
		len(config.WildcardBindTransports) != 0 || len(config.LoopbackTransports) != 0 || len(config.MulticastTransports) != 0 ||
		len(config.BroadcastTransports) != 0 || len(config.PrivilegedBindTransports) != 0
}

func registerBindings(module *wago.ImportModuleBuilder, bindings []binding) {
	for _, binding := range bindings {
		module.Func(binding.name, binding.fn).
			Params(binding.params...).
			Results(binding.results...).
			Capability(binding.capability).
			Docs(binding.docs)
	}
}

type binding struct {
	name       string
	fn         wago.HostFunc
	params     []wago.ValType
	results    []wago.ValType
	capability wago.Capability
	docs       string
}

func (e *Network) bindings() []binding {
	return []binding{
		{
			name:       "abi_version",
			fn:         abiVersion,
			results:    []wago.ValType{wago.ValI32},
			capability: CapInfo,
			docs:       "return the supported wago_net ABI version",
		},
	}
}

func abiVersion(_ wago.HostModule, params, results []uint64) {
	if len(params) != 0 || len(results) != 1 {
		return
	}
	results[0] = uint64(ABIVersion1)
}

func (e *Network) instanceManager() *instancestate.Manager {
	if e == nil || e.configErr != nil {
		return nil
	}
	if e.instances != nil {
		return e.instances
	}
	manager, _ := e.initialize(e.modules.Freeze())
	return manager
}

func lnetoCoreConfig(config StaticIPv4Config) lnetocore.Config {
	return lnetocore.Config{
		Hostname:               config.Hostname,
		RandSeed:               config.RandSeed,
		HardwareAddress:        config.HardwareAddress,
		GatewayHardwareAddress: config.GatewayHardwareAddress,
		IPv4Address:            config.IPv4Address,
		MTU:                    config.MTU,
		Link:                   config.Link,
	}
}
