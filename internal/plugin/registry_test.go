package plugin

import (
	"errors"
	"runtime"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	wago "github.com/wago-org/wago"
)

func TestSetRejectsInvalidDuplicateAndFrozenModules(t *testing.T) {
	install := func(*wago.Registry, Host) {}
	var set Set
	if err := set.Add(NewModule("", install)); !errors.Is(err, ErrInvalidModule) {
		t.Fatalf("empty key = %v", err)
	}
	if err := set.Add(NewModule(ModuleTCP, nil)); !errors.Is(err, ErrInvalidModule) {
		t.Fatalf("nil installer = %v", err)
	}
	if err := set.Add(NewModule(ModuleTCP, install)); err != nil {
		t.Fatalf("Add TCP: %v", err)
	}
	if err := set.Add(NewModule(ModuleTCP, install)); !errors.Is(err, ErrDuplicateModule) {
		t.Fatalf("duplicate TCP = %v", err)
	}
	set.Freeze()
	if err := set.Add(NewModule(ModuleUDP, install)); !errors.Is(err, ErrFrozen) {
		t.Fatalf("Add after Freeze = %v", err)
	}
}

func TestBackendContributionConfigurationAndInstallation(t *testing.T) {
	type backendConfig struct{ count int }
	base := new(int)
	serviceValue := new(string)
	backend := NewBackend(BackendLnetoV1,
		func(target any) error {
			config, ok := target.(*backendConfig)
			if !ok {
				return ErrInvalidBackend
			}
			config.count++
			return nil
		},
		func(got any) (nscore.Service, error) {
			if got != base {
				return nscore.Service{}, ErrInvalidBackend
			}
			return nscore.Service{Key: "tcp", Value: serviceValue}, nil
		},
	)
	module := NewModule(ModuleTCP, func(*wago.Registry, Host) {}, backend)
	var config backendConfig
	if err := module.ConfigureBackend(BackendLnetoV1, &config); err != nil || config.count != 1 {
		t.Fatalf("ConfigureBackend = %v, config=%+v", err, config)
	}
	service, installed, err := module.InstallBackend(BackendLnetoV1, base)
	if err != nil || !installed || service.Key != "tcp" || service.Value != serviceValue {
		t.Fatalf("InstallBackend = %+v %v %v", service, installed, err)
	}
	if err := module.ConfigureBackend("other", &config); !errors.Is(err, ErrIncompatibleBackend) {
		t.Fatalf("incompatible configure = %v", err)
	}
	if _, _, err := module.InstallBackend("other", base); !errors.Is(err, ErrIncompatibleBackend) {
		t.Fatalf("incompatible install = %v", err)
	}

	stateless := NewModule(ModuleDNS, func(*wago.Registry, Host) {})
	if err := stateless.ConfigureBackend(BackendLnetoV1, &config); err != nil {
		t.Fatalf("stateless configure = %v", err)
	}
	if service, installed, err := stateless.InstallBackend(BackendLnetoV1, base); err != nil || installed || service != (nscore.Service{}) {
		t.Fatalf("stateless install = %+v %v %v", service, installed, err)
	}
}

func TestAuthorityContributionCopiesAndComposes(t *testing.T) {
	input := policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP},
		Directions: []policy.Direction{policy.DirectionOutbound},
	}}, AllowLoopback: true}
	module := NewModule(ModuleTCP, func(*wago.Registry, Host) {}).WithAuthority(NewAuthority(input))
	input.Rules[0].Transports[0] = policy.TransportUDP
	input.AllowLoopback = false

	target := policy.Config{Rules: []policy.Rule{{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportTCP}}}}
	if err := module.ConfigureAuthority(&target); err != nil {
		t.Fatal(err)
	}
	if len(target.Rules) != 2 || target.Rules[1].Transports[0] != policy.TransportTCP || !target.AllowLoopback {
		t.Fatalf("composed authority = %+v", target)
	}
	if err := module.ConfigureAuthority(nil); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("nil authority target = %v", err)
	}
}

func TestSetRejectsInvalidBackendContributions(t *testing.T) {
	install := func(*wago.Registry, Host) {}
	for _, module := range []Module{
		NewModule(ModuleTCP, install, NewBackend("", nil, func(any) (nscore.Service, error) { return nscore.Service{}, nil })),
		NewModule(ModuleTCP, install, NewBackend(BackendLnetoV1, nil, nil)),
		NewModule(ModuleTCP, install, NewBackend(BackendLnetoV1, nil, func(any) (nscore.Service, error) { return nscore.Service{}, nil }), NewBackend(BackendLnetoV1, nil, func(any) (nscore.Service, error) { return nscore.Service{}, nil })),
	} {
		var set Set
		if err := set.Add(module); !errors.Is(err, ErrInvalidBackend) {
			t.Fatalf("invalid backend = %v", err)
		}
	}
}

type exactHostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m exactHostModule) Memory() []byte           { return m.memory }
func (m exactHostModule) Instance() *wago.Instance { return m.instance }

func TestHostFacadeResolvesOnlyExactAttachedInstances(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	host := NewHost(manager)
	module := exactHostModule{instance: instance}
	state, ok := host.State(module)
	if !ok || state == nil {
		t.Fatal("exact attached instance did not resolve")
	}
	if got, attached := manager.ForInstance(instance); !attached || got != state {
		t.Fatal("host facade returned a non-owned state")
	}
	for name, candidate := range map[string]Host{
		"zero host":   {},
		"nil manager": NewHost(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := candidate.State(module); ok || got != nil {
				t.Fatalf("State = %p, %v", got, ok)
			}
		})
	}
	if got, ok := host.State(nil); ok || got != nil {
		t.Fatalf("nil module State = %p, %v", got, ok)
	}
	if got, ok := host.State(exactHostModule{instance: new(wago.Instance)}); ok || got != nil {
		t.Fatalf("unattached instance State = %p, %v", got, ok)
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	if got, ok := host.State(module); ok || got != nil {
		t.Fatalf("detached instance State = %p, %v", got, ok)
	}
}

func TestHostFacadeExactAttachedLookupDoesNotAllocate(t *testing.T) {
	if runtime.Compiler == "tinygo" {
		return
	}
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	host := NewHost(manager)
	var module wago.HostModule = exactHostModule{instance: instance}
	var state *instancecore.State
	var found bool
	allocs := testing.AllocsPerRun(1000, func() {
		state, found = host.State(module)
	})
	if allocs != 0 {
		t.Fatalf("Host.State allocations = %v, want 0", allocs)
	}
	if !found || state == nil {
		t.Fatal("exact attached instance did not resolve")
	}
}

func TestModuleInstallForwardsExactHostFacade(t *testing.T) {
	manager := instancecore.NewManager()
	host := NewHost(manager)
	called := false
	module := NewModule(ModuleICMPv4, func(registry *wago.Registry, got Host) {
		called = true
		if registry == nil || got.instances != manager {
			t.Fatalf("Install host = %+v registry=%p", got, registry)
		}
	})
	module.Install(new(wago.Registry), host)
	if !called {
		t.Fatal("module installer was not called")
	}
}

func BenchmarkHostStateAttached(b *testing.B) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		b.Fatal(err)
	}
	defer manager.Detach(instance)
	host := NewHost(manager)
	var module wago.HostModule = exactHostModule{instance: instance}
	var state *instancecore.State
	var found bool
	b.ReportAllocs()
	for b.Loop() {
		state, found = host.State(module)
	}
	if !found || state == nil {
		b.Fatal("exact attached instance did not resolve")
	}
}

func BenchmarkHostStateUnattached(b *testing.B) {
	host := NewHost(instancecore.NewManager())
	var module wago.HostModule = exactHostModule{instance: new(wago.Instance)}
	var state *instancecore.State
	var found bool
	b.ReportAllocs()
	for b.Loop() {
		state, found = host.State(module)
	}
	if found || state != nil {
		b.Fatal("unattached instance resolved")
	}
}

func TestFreezeReturnsIndependentStableSnapshots(t *testing.T) {
	install := func(*wago.Registry, Host) {}
	var set Set
	if err := set.Add(NewModule(ModuleTCP, install)); err != nil {
		t.Fatalf("Add TCP: %v", err)
	}
	first := set.Freeze()
	if len(first) != 1 || first[0].key != ModuleTCP {
		t.Fatalf("first snapshot = %+v", first)
	}
	first[0] = Module{}
	second := set.Freeze()
	if len(second) != 1 || second[0].key != ModuleTCP || second[0].install == nil {
		t.Fatalf("second snapshot changed through caller mutation: %+v", second)
	}
}
