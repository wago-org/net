// Package net provides the core of Wago's capability-gated networking plugin
// suite. The guest ABI is backend-neutral; lneto is the first backend and is
// not part of the public contract. Complete UDP, TCP, and bounded DNS modules
// are independently capability-gated. Runtime registration requires physical
// reinstantiation between class leases so instance-owned network state cannot
// survive an in-place Wasm memory reset.
package net

import (
	"embed"
	"encoding/json"
	"net/netip"
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
)

const (
	// Module is the core networking WebAssembly import module.
	Module = "wago_net"
	// UDPModule independently owns the complete guest UDP operation surface.
	UDPModule = "wago_net_udp"
	// TCPModule owns the complete guest TCP operation surface.
	TCPModule = "wago_net_tcp"
	// DNSModule owns the complete checked bounded DNS surface.
	DNSModule = "wago_net_dns"

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

	PolicyTransportUDP = policy.TransportUDP
	PolicyTransportTCP = policy.TransportTCP
	PolicyTransportDNS = policy.TransportDNS

	PolicyInbound  = policy.DirectionInbound
	PolicyOutbound = policy.DirectionOutbound
)

// QuotaLimits and ReadinessConfig are finite per-instance limits. Zero values
// deny the corresponding class; pointers in Config distinguish explicit zero
// limits from the extension defaults.
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
// state. A nil StaticIPv4 leaves the extension state-only and guest-visible
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
// in the tcp, udp, and dns packages rather than in the root package.
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

// Extension implements the shared Wago networking composition and lifecycle
// layer. Network is its selective-API name.
type Extension struct {
	config    Config
	configErr error
	modules   plugin.Set

	stateOnce sync.Once
	instances *instancestate.Manager
	stateErr  error
}

// Network is the shared builder passed to protocol registration packages.
type Network = Extension

// New constructs an initially protocol-free network. Protocol packages select
// their exact capability and import surface before the network is passed to
// Wago. Registration freezes on the first Wago Register call.
func New(options ...Option) *Network {
	var config Config
	for _, option := range options {
		if option == nil {
			return &Extension{configErr: instancestate.ErrInvalidConfig}
		}
		if err := option.applyNetwork(&config); err != nil {
			return &Extension{config: config, configErr: err}
		}
	}
	return newExtension(config)
}

func newExtension(config Config) *Extension {
	return &Extension{config: cloneConfig(config)}
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

func (e *Extension) initialize(modules []plugin.Module) (*instancestate.Manager, error) {
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

func (e *Extension) buildManager(modules []plugin.Module) (*instancestate.Manager, error) {
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
			services := make([]nscore.Service, 0, len(modules))
			for _, module := range modules {
				service, installed, installErr := module.InstallBackend(plugin.BackendLnetoV1, common)
				if installErr != nil {
					_ = common.Close()
					return nil, installErr
				}
				if installed {
					services = append(services, service)
				}
			}
			composed, err := nscore.ComposeNamespace(common, services...)
			if err != nil {
				_ = common.Close()
				return nil, err
			}
			return composed, nil
		}
	}
	return instancestate.NewManagerConfigured(managerConfig)
}

// RegisterModule installs one opaque protocol descriptor. The internal type in
// this signature deliberately limits direct use to this module's public
// protocol packages.
func (e *Extension) RegisterModule(module plugin.Module) error {
	if e == nil {
		return instancestate.ErrInvalidConfig
	}
	return e.modules.Add(module)
}

// Info returns extension metadata loaded from wago.json.
func (e *Extension) Info() wago.ExtensionInfo { return extensionInfo }

// Register declares the core networking capability and host imports.
func (e *Extension) Register(reg *wago.Registry) error {
	if e == nil || e.configErr != nil {
		if e == nil {
			return instancestate.ErrInvalidConfig
		}
		return e.configErr
	}
	modules := e.modules.Freeze()
	instances, err := e.initialize(modules)
	if err != nil {
		return err
	}
	reg.RequireReinstantiation()
	reg.Hooks().AfterInstantiate(instances.AfterInstantiate)
	reg.Hooks().BeforeClose(instances.BeforeClose)
	if len(modules) == 0 {
		return nil
	}
	reg.Capability(CapInfo, wago.CapabilityDocs("inspect the Wago networking ABI and interfaces"))
	registerBindings(reg.ImportModule(Module), e.bindings())
	host := plugin.NewHost(instances)
	for _, module := range modules {
		module.Install(reg, host)
	}
	return nil
}

// Imports returns the stateless core host imports for Wago's low-level
// Instantiate path. Resource-owning protocol imports require the Runtime
// extension path so per-instance lifecycle state can be attached and cleaned.
func Imports(config Config) wago.Imports {
	ext := New(WithConfig(config))
	imports := make(wago.Imports)
	for _, binding := range ext.bindings() {
		imports[Module+"."+binding.name] = binding.fn
	}
	return imports
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

func (e *Extension) bindings() []binding {
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

func (e *Extension) instanceManager() *instancestate.Manager {
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

type manifest struct {
	Module      string            `json:"module"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Stability   string            `json:"stability"`
	License     string            `json:"license"`
	Homepage    string            `json:"homepage"`
	Repository  string            `json:"repository"`
	Authors     []string          `json:"authors"`
	Keywords    []string          `json:"keywords"`
	Engines     map[string]string `json:"engines"`
	Platforms   []string          `json:"platforms"`
	Private     bool              `json:"private"`
}

//go:embed wago.json
var manifestFiles embed.FS

var extensionInfo = loadExtensionInfo()

func loadExtensionInfo() wago.ExtensionInfo {
	data, err := manifestFiles.ReadFile("wago.json")
	if err != nil {
		panic("wagonet: reading wago.json: " + err.Error())
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		panic("wagonet: parsing wago.json: " + err.Error())
	}
	return wago.ExtensionInfo{
		ID:          m.Module,
		Name:        m.Name,
		Version:     m.Version,
		Description: m.Description,
		Stability:   wago.Stability(m.Stability),
		License:     m.License,
		Homepage:    m.Homepage,
		Repository:  m.Repository,
		Authors:     append([]string(nil), m.Authors...),
		Tags:        append([]string(nil), m.Keywords...),
		Private:     m.Private,
		Compat: wago.Compatibility{
			Engines:   m.Engines,
			Platforms: append([]string(nil), m.Platforms...),
		},
	}
}
