package ipv6

import (
	"errors"
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeBase struct {
	closed     bool
	closeCalls int
}

func (b *fakeBase) Close() error {
	b.closed = true
	b.closeCalls++
	return nil
}
func (b *fakeBase) Readiness() nscore.Readiness {
	if b.closed {
		return nscore.ReadyClosed
	}
	return 0
}
func (*fakeBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeNamespace struct {
	configuration ipv6ns.Configuration
	calls         int
}

func (n *fakeNamespace) Configuration() ipv6ns.Configuration {
	n.calls++
	return n.configuration
}

type serviceCarrier struct {
	fakeBase
	service any
}

func (c *serviceCarrier) NamespaceService(key nscore.ServiceKey) (any, bool) {
	if key != ipv6ns.ServiceKey {
		return nil, false
	}
	return c.service, true
}

func TestConfigurationExactNamespaceLifecycle(t *testing.T) {
	backend := &fakeNamespace{configuration: validConfiguration()}
	state, manager, instance, base := attachState(t, backend)
	handle := state.NamespaceHandle()

	configuration, err := Configuration(state, handle)
	if err != nil || configuration != backend.configuration || backend.calls != 1 {
		t.Fatalf("Configuration = %+v, %v, calls=%d", configuration, err, backend.calls)
	}
	other, err := state.Resources().Add(resource.KindUDPSocket, &fakeBase{})
	if err != nil {
		t.Fatal(err)
	}
	if configuration, err := Configuration(state, other); !errors.Is(err, resource.ErrBadHandle) || configuration != (ipv6ns.Configuration{}) {
		t.Fatalf("wrong-kind configuration = %+v, %v", configuration, err)
	}
	if err := state.CloseHandle(handle, resource.KindNamespace); err != nil || !base.closed || base.closeCalls != 1 || state.NamespaceHandle() != 0 {
		t.Fatalf("CloseHandle = %v, base=%+v namespace=%v", err, base, state.NamespaceHandle())
	}
	if configuration, err := Configuration(state, handle); !errors.Is(err, resource.ErrBadHandle) || configuration != (ipv6ns.Configuration{}) {
		t.Fatalf("stale configuration = %+v, %v", configuration, err)
	}
	if err := manager.Detach(instance); err != nil || base.closeCalls != 1 {
		t.Fatalf("Detach = %v, close calls=%d", err, base.closeCalls)
	}
	if configuration, err := Configuration(state, handle); failureOf(err) != nscore.FailureClosed || configuration != (ipv6ns.Configuration{}) {
		t.Fatalf("detached configuration = %+v, %v", configuration, err)
	}
}

func TestConfigurationRejectsMissingTypedNilAndInvalidServices(t *testing.T) {
	state, manager, instance, _ := attachState(t, nil)
	if configuration, err := Configuration(state, state.NamespaceHandle()); failureOf(err) != nscore.FailureNotSupported || configuration != (ipv6ns.Configuration{}) {
		t.Fatalf("missing service = %+v, %v", configuration, err)
	}
	_ = manager.Detach(instance)

	var typedNil *fakeNamespace
	state, manager, instance = attachCarrierState(t, typedNil)
	if configuration, err := Configuration(state, state.NamespaceHandle()); failureOf(err) != nscore.FailureNotSupported || configuration != (ipv6ns.Configuration{}) {
		t.Fatalf("typed nil service = %+v, %v", configuration, err)
	}
	_ = manager.Detach(instance)

	backend := &fakeNamespace{configuration: ipv6ns.Configuration{Address: netip.MustParseAddr("2001:db8::7"), PrefixBits: 64, MTU: 1500}}
	state, manager, instance, _ = attachState(t, backend)
	defer manager.Detach(instance)
	if configuration, err := Configuration(state, state.NamespaceHandle()); failureOf(err) != nscore.FailureIO || configuration != (ipv6ns.Configuration{}) || backend.calls != 1 {
		t.Fatalf("invalid service result = %+v, %v, calls=%d", configuration, err, backend.calls)
	}
}

func TestDetachClosesIPv6NamespaceExactlyOnce(t *testing.T) {
	backend := &fakeNamespace{configuration: validConfiguration()}
	state, manager, instance, base := attachState(t, backend)
	handle := state.NamespaceHandle()
	if err := manager.Detach(instance); err != nil || !base.closed || base.closeCalls != 1 {
		t.Fatalf("Detach = %v, base=%+v", err, base)
	}
	if err := manager.Detach(instance); err != nil || base.closeCalls != 1 {
		t.Fatalf("second Detach = %v, close calls=%d", err, base.closeCalls)
	}
	if configuration, err := Configuration(state, handle); failureOf(err) != nscore.FailureClosed || configuration != (ipv6ns.Configuration{}) {
		t.Fatalf("closed configuration = %+v, %v", configuration, err)
	}
}

func attachState(t testing.TB, backend ipv6ns.Namespace) (*instancecore.State, *instancecore.Manager, *wago.Instance, *fakeBase) {
	t.Helper()
	base := new(fakeBase)
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		if backend == nil {
			return nscore.ComposeNamespace(base)
		}
		return nscore.ComposeNamespace(base, nscore.Service{Key: ipv6ns.ServiceKey, Value: backend})
	}
	manager, err := instancecore.NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("state not attached")
	}
	return state, manager, instance, base
}

func attachCarrierState(t testing.TB, service any) (*instancecore.State, *instancecore.Manager, *wago.Instance) {
	t.Helper()
	carrier := &serviceCarrier{service: service}
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return carrier, nil }
	manager, err := instancecore.NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("state not attached")
	}
	return state, manager, instance
}

func validConfiguration() ipv6ns.Configuration {
	return ipv6ns.Configuration{
		Address: netip.MustParseAddr("2001:db8:42::7"), PrefixBits: 64, MTU: 1500,
		Transports: ipv6ns.TransportTCPConnect | ipv6ns.TransportTCPListen,
	}
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func BenchmarkConfiguration(b *testing.B) {
	backend := &fakeNamespace{configuration: validConfiguration()}
	state, manager, instance, _ := attachState(b, backend)
	defer manager.Detach(instance)
	handle := state.NamespaceHandle()
	if _, err := Configuration(state, handle); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = Configuration(state, handle)
	}
}
