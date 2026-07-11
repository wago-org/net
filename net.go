// Package net provides the core of Wago's capability-gated networking plugin
// suite. The guest ABI is backend-neutral; lneto is the first planned backend,
// not part of the public contract.
package net

import (
	"embed"
	"encoding/json"
	"net/netip"
	"sync"

	lnetobackend "github.com/wago-org/net/internal/backend/lneto"
	instancestate "github.com/wago-org/net/internal/instance"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	wago "github.com/wago-org/wago"
)

const (
	// Module is the core networking WebAssembly import module.
	Module = "wago_net"

	// ABIVersion1 encodes ABI version 1.0 as major in the upper 16 bits and minor
	// in the lower 16 bits.
	ABIVersion1 uint32 = 0x0001_0000

	// CapInfo permits a guest to inspect the networking ABI and interfaces.
	CapInfo wago.Capability = "net.info"
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

// Extension implements the core Wago networking extension.
type Extension struct {
	config    Config
	configErr error

	stateOnce sync.Once
	instances *instancestate.Manager
}

// Init constructs the core networking extension. Configuration errors are
// returned by Register so Init remains compatible with Wago extension setup.
func Init(config Config) *Extension {
	managerConfig := instancestate.DefaultConfig()
	managerConfig.Policy = config.Policy
	if config.Limits != nil {
		managerConfig.Limits = *config.Limits
	}
	if config.Readiness != nil {
		managerConfig.Readiness = *config.Readiness
	}
	if config.StaticIPv4 != nil {
		backendConfig := lnetoConfig(*config.StaticIPv4)
		if err := lnetobackend.ValidateConfig(backendConfig); err != nil {
			return &Extension{config: config, configErr: err}
		}
		managerConfig.NamespaceFactory = func(compiled *policy.Policy, account *quota.Account) (namespace.Namespace, error) {
			instanceConfig := backendConfig
			instanceConfig.Policy = compiled
			instanceConfig.Quotas = account
			return lnetobackend.New(instanceConfig)
		}
	}
	manager, err := instancestate.NewManagerConfigured(managerConfig)
	return &Extension{config: config, configErr: err, instances: manager}
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
	instances := e.instanceManager()
	reg.Hooks().AfterInstantiate(instances.AfterInstantiate)
	reg.Hooks().BeforeClose(instances.BeforeClose)
	reg.Capability(CapInfo, wago.CapabilityDocs("inspect the Wago networking ABI and interfaces"))
	module := reg.ImportModule(Module)
	for _, binding := range e.bindings() {
		module.Func(binding.name, binding.fn).
			Params(binding.params...).
			Results(binding.results...).
			Capability(binding.capability).
			Docs(binding.docs)
	}
	return nil
}

// Imports returns the stateless core host imports for Wago's low-level
// Instantiate path. Resource-owning protocol imports require the Runtime
// extension path so per-instance lifecycle state can be attached and cleaned.
func Imports(config Config) wago.Imports {
	ext := Init(config)
	imports := make(wago.Imports)
	for _, binding := range ext.bindings() {
		imports[Module+"."+binding.name] = binding.fn
	}
	return imports
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

func abiVersion(_ wago.HostModule, _ []uint64, results []uint64) {
	results[0] = uint64(ABIVersion1)
}

func (e *Extension) instanceManager() *instancestate.Manager {
	if e == nil {
		return nil
	}
	e.stateOnce.Do(func() {
		if e.instances == nil && e.configErr == nil {
			e.instances = instancestate.NewManager()
		}
	})
	return e.instances
}

func lnetoConfig(config StaticIPv4Config) lnetobackend.Config {
	return lnetobackend.Config{
		Hostname:               config.Hostname,
		RandSeed:               config.RandSeed,
		HardwareAddress:        config.HardwareAddress,
		GatewayHardwareAddress: config.GatewayHardwareAddress,
		IPv4Address:            config.IPv4Address,
		MTU:                    config.MTU,
		Link:                   config.Link,
		UDP: lnetobackend.UDPConfig{
			MaxSockets:        config.UDP.MaxSockets,
			ReceiveBytes:      config.UDP.ReceiveBytes,
			TransmitBytes:     config.UDP.TransmitBytes,
			ReceiveDatagrams:  config.UDP.ReceiveDatagrams,
			TransmitDatagrams: config.UDP.TransmitDatagrams,
			MaxPayloadBytes:   config.UDP.MaxPayloadBytes,
		},
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
