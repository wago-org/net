// Package net provides the core of Wago's capability-gated networking plugin
// suite. The guest ABI is backend-neutral; lneto is the first planned backend,
// not part of the public contract.
package net

import (
	"embed"
	"encoding/json"
	"sync"

	instancestate "github.com/wago-org/net/internal/instance"
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

// Config configures the core networking extension. It is intentionally empty
// until a core option has implemented behavior and tests.
type Config struct{}

// Extension implements the core Wago networking extension.
type Extension struct {
	config Config

	stateOnce sync.Once
	instances *instancestate.Manager
}

// Init constructs the core networking extension.
func Init(config Config) *Extension {
	return &Extension{config: config, instances: instancestate.NewManager()}
}

// Info returns extension metadata loaded from wago.json.
func (e *Extension) Info() wago.ExtensionInfo { return extensionInfo }

// Register declares the core networking capability and host imports.
func (e *Extension) Register(reg *wago.Registry) error {
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
	e.stateOnce.Do(func() {
		if e.instances == nil {
			e.instances = instancestate.NewManager()
		}
	})
	return e.instances
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
