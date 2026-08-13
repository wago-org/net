package net

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	wago "github.com/wago-org/wago"
	wagoplugin "github.com/wago-org/wago/plugin"
)

type registerFunc func(*wago.Registrar) error

func (f registerFunc) Register(reg *wago.Registrar) error { return f(reg) }

var errRejectedInstance = errors.New("reject instance after networking attaches")

type contractConsumer struct {
	ref      *wagoplugin.Ref[Service]
	ready    bool
	stopUsed bool
}

func consumerProvider(consumer *contractConsumer, networkID string) wago.PluginProvider {
	definition := wago.PluginDefinition{
		ID: "example.com/wagonet/consumer", Version: "1.0.0",
		Provenance: wago.PluginProvenance{Repository: "https://example.com/wagonet/consumer", License: "MIT"},
		Requires:   []wago.PluginRequirement{{ID: networkID, Version: "^0.1.0"}},
		Authorities: []wago.AuthorityRequest{{
			Name: wago.AuthorityHostImportDefine, Mode: wago.AuthorityRequired,
			Reason: "exercise the network service from an exact guest caller",
			Scope:  wago.AuthorityScope{Modules: []string{"net_consumer"}},
		}},
		Consumes: []wago.ContractRequirement{{ID: Contract.ID(), Major: Contract.Major(), Mode: wago.ContractRequired}},
	}
	return wago.PluginProvider{Definition: definition, New: func() wago.Plugin {
		return registerFunc(func(reg *wago.Registrar) error {
			var err error
			consumer.ref, err = wagoplugin.Require(reg, Contract)
			if err != nil {
				return err
			}
			imports, err := reg.HostImports()
			if err != nil {
				return err
			}
			module, err := imports.Module("net_consumer")
			if err != nil {
				return err
			}
			module.Func("ready", func(caller wago.HostModule, _, results []uint64) {
				if len(results) != 1 {
					return
				}
				_ = consumer.ref.With(func(service Service) error {
					consumer.ready = service.Ready(caller)
					if consumer.ready {
						results[0] = 1
					}
					return nil
				})
			}).Results(wago.ValI32)
			return reg.Lifecycle(wago.PluginLifecycle{Stop: func(context.Context) error {
				return consumer.ref.With(func(service Service) error {
					consumer.stopUsed = len(service.ImportModules()) != 0
					return nil
				})
			}})
		})
	}}
}

func pluginSet(t *testing.T, providers ...wago.PluginProvider) wago.PluginSet {
	t.Helper()
	set := wago.PluginSet{Providers: providers}
	for _, provider := range providers {
		digest, err := wago.DefinitionDigest(provider.Definition)
		if err != nil {
			t.Fatal(err)
		}
		selection := wago.PluginSelection{
			ID: provider.Definition.ID, DefinitionDigest: digest, Direct: true,
			Dependencies: map[string]string{},
		}
		for _, requirement := range provider.Definition.Requires {
			selection.Dependencies[requirement.ID] = requirement.Version
		}
		for _, authority := range provider.Definition.Authorities {
			selection.Grants = append(selection.Grants, wago.AuthorityGrant{Name: authority.Name, Scope: authority.Scope})
		}
		for _, requirement := range provider.Definition.Consumes {
			var owners []string
			for _, candidate := range providers {
				for _, provided := range candidate.Definition.Provides {
					if provided.ID == requirement.ID && provided.Major == requirement.Major {
						owners = append(owners, candidate.Definition.ID)
					}
				}
			}
			sort.Strings(owners)
			selection.Contracts = append(selection.Contracts, wago.ContractBinding{ID: requirement.ID, Major: requirement.Major, Providers: owners})
		}
		set.Selections = append(set.Selections, selection)
	}
	return set
}

func TestNetworkContractGraphCallerIdentityInFlightAndRevocation(t *testing.T) {
	networkID := "example.com/wagonet/provider"
	network := Init(Config{})
	provider := Provider(ProviderSpec{
		ID: networkID, Name: "Networking test provider", Description: "exact test network",
		Modules: []string{Module, UDPModule, TCPModule, DNSModule},
		Factory: func() (*Network, error) { return network, nil },
	})
	consumer := new(contractConsumer)
	runtime := wago.NewRuntime()
	// Reverse the graph to prove the package and reviewed contract edges order
	// the network provider before its consumer.
	if err := runtime.LoadPlugins(context.Background(), pluginSet(t, consumerProvider(consumer, networkID), provider)); err != nil {
		t.Fatal(err)
	}
	module, err := compileImportHarness(runtime, "net_consumer")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	results, err := instance.Invoke("ready")
	if err != nil || len(results) != 1 || results[0] != 1 || !consumer.ready {
		t.Fatalf("cross-plugin ready = %v, %v, ready=%v", results, err, consumer.ready)
	}
	if err := consumer.ref.With(func(service Service) error {
		modules := service.ImportModules()
		modules[0] = "mutated"
		if service.ImportModules()[0] == "mutated" {
			return errors.New("network service leaked mutable topology")
		}
		forged := udpHostModule{instance: instance, memory: instance.Memory().Bytes()}
		if service.Ready(forged) {
			return errors.New("network service accepted a forged caller module")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	callDone := make(chan error, 1)
	go func() {
		callDone <- consumer.ref.With(func(service Service) error {
			if got := service.ImportModules(); len(got) != 4 {
				return errors.New("unexpected immutable import topology")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.CloseContext(context.Background()) }()
	select {
	case err := <-closeDone:
		t.Fatalf("runtime closed before leased call returned: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-callDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if !consumer.stopUsed {
		t.Fatal("consumer Stop could not use the network provider before revocation")
	}
	if err := consumer.ref.With(func(Service) error { return nil }); !errors.Is(err, wago.ErrPermissionDenied) {
		t.Fatalf("contract after revocation = %v", err)
	}
}

func TestProviderStrictConfigAndMissingAuthorityFailClosed(t *testing.T) {
	provider := Provider(ProviderSpec{
		ID: "example.com/wagonet/provider", Name: "Networking test provider", Description: "exact test network",
		Modules: []string{Module, UDPModule},
		Factory: func() (*Network, error) { return Init(Config{}), nil },
	})
	if err := provider.ValidateConfig(json.RawMessage(`{"unknown":1,"unknown":2}`)); err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("duplicate config fields error = %v", err)
	}
	for _, config := range []json.RawMessage{
		json.RawMessage(`null`),
		json.RawMessage(`[]`),
		json.RawMessage(`{"unknown":null}`),
		json.RawMessage(`{"unknown":1,"unknown":2}`),
		json.RawMessage(`{"unknown":true}`),
		json.RawMessage(`{} {}`),
	} {
		set := pluginSet(t, provider)
		set.Selections[0].Config = config
		if err := wago.ValidatePluginSet(set); err == nil {
			t.Fatalf("invalid config %s was accepted", config)
		}
	}
	set := pluginSet(t, provider)
	set.Selections[0].Grants = set.Selections[0].Grants[1:]
	if err := wago.ValidatePluginSet(set); err == nil {
		t.Fatal("missing required host-import authority was accepted")
	}
}

func TestProviderInspectionIsSideEffectFreeAndSnapshotsAuthorityModules(t *testing.T) {
	network := New()
	if err := network.registerUDPModule(); err != nil {
		t.Fatal(err)
	}
	modules := []string{Module, UDPModule}
	factoryCalls := 0
	provider := Provider(ProviderSpec{
		ID: "example.com/wagonet/provider", Name: "Networking test provider", Description: "exact test network",
		Modules: modules, Factory: func() (*Network, error) {
			factoryCalls++
			return network, nil
		},
	})
	modules[1] = "unreviewed_mutation"
	set := pluginSet(t, provider)
	plan, err := wago.InspectPluginPlan(set)
	if err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 0 || len(plan.Plugins) != 1 {
		t.Fatalf("inspection factory calls=%d plan=%+v", factoryCalls, plan)
	}
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.LoadPlugins(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 1 {
		t.Fatalf("load factory calls=%d, want 1", factoryCalls)
	}
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module != Module && spec.Module != UDPModule {
			t.Fatalf("mutated authority module reached registration: %+v", spec)
		}
	}
}

func TestConsumerRequiresProviderAndReviewedContractBinding(t *testing.T) {
	consumer := new(contractConsumer)
	consumerOnly := pluginSet(t, consumerProvider(consumer, "example.com/wagonet/missing"))
	if err := wago.ValidatePluginSet(consumerOnly); err == nil {
		t.Fatal("consumer without its required network provider was accepted")
	}

	networkID := "example.com/wagonet/provider"
	provider := Provider(ProviderSpec{
		ID: networkID, Name: "Networking test provider", Description: "exact test network",
		Modules: []string{Module, UDPModule},
		Factory: func() (*Network, error) {
			network := New()
			if err := network.registerUDPModule(); err != nil {
				return nil, err
			}
			return network, nil
		},
	})
	set := pluginSet(t, provider, consumerProvider(consumer, networkID))
	set.Selections[1].Contracts = nil
	if err := wago.ValidatePluginSet(set); err == nil {
		t.Fatal("consumer without its reviewed network Contract binding was accepted")
	}
}

func TestNarrowGrantRejectsUnreviewedImportContribution(t *testing.T) {
	provider := Provider(ProviderSpec{
		ID: "example.com/wagonet/provider", Name: "Networking test provider", Description: "exact test network",
		Modules: []string{Module, UDPModule},
		Factory: func() (*Network, error) {
			network := New()
			if err := network.registerUDPModule(); err != nil {
				return nil, err
			}
			return network, nil
		},
	})
	set := pluginSet(t, provider)
	for i := range set.Selections[0].Grants {
		if set.Selections[0].Grants[i].Name == wago.AuthorityHostImportDefine {
			set.Selections[0].Grants[i].Scope.Modules = []string{Module}
		}
	}
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.LoadPlugins(context.Background(), set); err == nil {
		t.Fatal("UDP contribution outside the narrowed import grant was accepted")
	}
}

func TestLaterInstantiateFailureRollsBackAttachedNetworkState(t *testing.T) {
	networkID := "example.com/wagonet/provider"
	network := New()
	if err := network.registerUDPModule(); err != nil {
		t.Fatal(err)
	}
	provider := Provider(ProviderSpec{
		ID: networkID, Name: "Networking test provider", Description: "exact test network",
		Modules: []string{Module, UDPModule}, Factory: func() (*Network, error) { return network, nil },
	})
	rejectDefinition := wago.PluginDefinition{
		ID: "example.com/wagonet/reject-instance", Name: "Reject instance", Version: "1.0.0",
		Description: "exercise transactional instance rollback", Stability: wago.Experimental,
		Provenance: wago.PluginProvenance{Repository: "https://example.com/wagonet/reject-instance", License: "MIT"},
		Requires:   []wago.PluginRequirement{{ID: networkID, Version: "^0.1.0"}},
		Authorities: []wago.AuthorityRequest{{
			Name: wago.AuthorityInstanceInstantiateIntercept, Mode: wago.AuthorityRequired,
			Reason: "reject after the network interceptor attached state",
		}},
	}
	reject := wago.PluginProvider{Definition: rejectDefinition, New: func() wago.Plugin {
		return registerFunc(func(reg *wago.Registrar) error {
			interceptor, err := reg.InstanceInstantiateInterceptor()
			if err != nil {
				return err
			}
			interceptor.After(func(wago.InstantiationEvent) error { return errRejectedInstance })
			return nil
		})
	}}
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.LoadPlugins(context.Background(), pluginSet(t, provider, reject)); err != nil {
		t.Fatal(err)
	}
	module := emptyModule(t, runtime)
	instance, err := runtime.Instantiate(context.Background(), module)
	if instance != nil {
		_ = instance.Close()
		t.Fatal("failed instantiation returned a live instance")
	}
	if !errors.Is(err, errRejectedInstance) {
		t.Fatalf("instantiate failure = %v", err)
	}
	if got := network.instanceManager().Len(); got != 0 {
		t.Fatalf("network states after failed instantiation = %d", got)
	}
}

func TestRuntimeShutdownClosesDirectInstanceAndDetachesState(t *testing.T) {
	network := New()
	if err := network.registerUDPModule(); err != nil {
		t.Fatal(err)
	}
	provider := Provider(ProviderSpec{
		ID: "example.com/wagonet/provider", Name: "Networking test provider", Description: "exact test network",
		Modules: []string{Module, UDPModule}, Factory: func() (*Network, error) { return network, nil },
	})
	runtime := wago.NewRuntime()
	if err := runtime.LoadPlugins(context.Background(), pluginSet(t, provider)); err != nil {
		t.Fatal(err)
	}
	module, err := compileImportHarness(runtime, UDPModule)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	if got := network.instanceManager().Len(); got != 1 {
		t.Fatalf("attached network states = %d, want 1", got)
	}
	if err := runtime.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := network.instanceManager().Len(); got != 0 {
		t.Fatalf("network states after Runtime.CloseContext = %d, want 0", got)
	}
	results, err := instance.Invoke("namespace_default", 0)
	if err == nil || len(results) != 0 {
		t.Fatalf("closed instance call after Runtime.CloseContext = %v, %v; want error", results, err)
	}
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
}
