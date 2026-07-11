package instance

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct {
	closed atomic.Int32
}

func (n *fakeNamespace) Close() error {
	n.closed.Add(1)
	return nil
}

func (n *fakeNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (n *fakeNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type fakePollable struct{}

func (fakePollable) Close() error                   { return nil }
func (fakePollable) Readiness() namespace.Readiness { return namespace.ReadyReadable }

func TestManagerConfigurationIsValidatedAndPolicyIsImmutable(t *testing.T) {
	invalid := DefaultConfig()
	invalid.Readiness.MaxRegistrations = 0
	if _, err := NewManagerConfigured(invalid); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid readiness error = %v", err)
	}
	invalid = DefaultConfig()
	invalid.Policy.Rules = []policy.Rule{{}}
	if _, err := NewManagerConfigured(invalid); !errors.Is(err, policy.ErrInvalidRule) {
		t.Fatalf("invalid policy error = %v", err)
	}

	prefix := netip.MustParsePrefix("192.0.2.0/24")
	config := DefaultConfig()
	config.Policy.Rules = []policy.Rule{{
		Action:     policy.ActionAllow,
		Transports: []policy.Transport{policy.TransportUDP},
		Directions: []policy.Direction{policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{prefix},
	}}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Policy.Rules[0].Action = policy.ActionDeny
	config.Policy.Rules[0].Prefixes[0] = netip.MustParsePrefix("198.51.100.0/24")
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok || !state.Policy().CheckEndpoint(policy.OperationUDPSend, netip.MustParseAddr("192.0.2.1"), 53) {
		t.Fatal("compiled policy changed after caller mutation")
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredNamespacesAreQuotaOwnedIsolatedAndGenerationSafe(t *testing.T) {
	config := DefaultConfig()
	config.Limits.Resources = 1
	var created []*fakeNamespace
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (namespace.Namespace, error) {
		backend := new(fakeNamespace)
		created = append(created, backend)
		return backend, nil
	}
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	firstInstance, secondInstance := new(wago.Instance), new(wago.Instance)
	if err := manager.Attach(firstInstance); err != nil {
		t.Fatal(err)
	}
	if err := manager.Attach(secondInstance); err != nil {
		t.Fatal(err)
	}
	first, _ := manager.ForInstance(firstInstance)
	second, _ := manager.ForInstance(secondInstance)
	if first == nil || second == nil || first.NamespaceHandle() == 0 || second.NamespaceHandle() == 0 || first.NamespaceHandle() == second.NamespaceHandle() {
		t.Fatalf("namespace state = %#v / %#v", first, second)
	}
	if _, err := second.Resources().Lookup(first.NamespaceHandle(), resource.KindNamespace); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("cross-instance namespace lookup = %v", err)
	}
	for _, state := range []*State{first, second} {
		usage, closed := state.Quotas().Snapshot()
		if closed || usage.Resources != 1 || state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
			t.Fatalf("configured state usage=%+v closed=%v resources=%d readiness=%+v", usage, closed, state.Resources().Len(), state.Readiness().Snapshot())
		}
	}
	stale := first.NamespaceHandle()
	if err := manager.Detach(firstInstance); err != nil {
		t.Fatal(err)
	}
	if created[0].closed.Load() != 1 {
		t.Fatalf("first backend close count = %d", created[0].closed.Load())
	}
	if _, err := first.Resources().Lookup(stale, resource.KindNamespace); !errors.Is(err, resource.ErrClosed) {
		t.Fatalf("closed table stale lookup = %v", err)
	}
	if err := manager.Detach(secondInstance); err != nil {
		t.Fatal(err)
	}
	if created[1].closed.Load() != 1 {
		t.Fatalf("second backend close count = %d", created[1].closed.Load())
	}
}

func TestNamespaceCreationRollsBackEveryOwnedStage(t *testing.T) {
	t.Run("quota denial skips backend", func(t *testing.T) {
		config := DefaultConfig()
		config.Limits.Resources = 0
		var calls atomic.Int32
		config.NamespaceFactory = func(*policy.Policy, *quota.Account) (namespace.Namespace, error) {
			calls.Add(1)
			return new(fakeNamespace), nil
		}
		manager, err := NewManagerConfigured(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Attach(new(wago.Instance)); !errors.Is(err, quota.ErrLimit) {
			t.Fatalf("quota denial error = %v", err)
		}
		if calls.Load() != 0 || manager.Len() != 0 {
			t.Fatalf("denied attach called backend %d times or published state", calls.Load())
		}
	})

	t.Run("factory failure releases reservation", func(t *testing.T) {
		factoryErr := errors.New("backend setup failed")
		config := DefaultConfig()
		config.Limits.Resources = 1
		config.NamespaceFactory = func(*policy.Policy, *quota.Account) (namespace.Namespace, error) { return nil, factoryErr }
		manager, err := NewManagerConfigured(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Attach(new(wago.Instance)); !errors.Is(err, factoryErr) {
			t.Fatalf("factory failure = %v", err)
		}
		if manager.Len() != 0 {
			t.Fatal("failed factory published state")
		}
	})

	t.Run("registration failure closes backend and releases quota", func(t *testing.T) {
		table, err := resource.NewTable()
		if err != nil {
			t.Fatal(err)
		}
		poller, err := readiness.New(table, readiness.Config{MaxRegistrations: 1})
		if err != nil {
			t.Fatal(err)
		}
		blocker, err := table.Add(resource.KindPollable, fakePollable{})
		if err != nil {
			t.Fatal(err)
		}
		if err := poller.Register(blocker, resource.KindPollable); err != nil {
			t.Fatal(err)
		}
		account := quota.NewAccount(quota.Limits{Resources: 1})
		compiled, err := policy.Compile(policy.Config{})
		if err != nil {
			t.Fatal(err)
		}
		state := &State{resources: table, readiness: poller, quotas: account, policy: compiled}
		backend := new(fakeNamespace)
		if _, err := state.createNamespace(func(*policy.Policy, *quota.Account) (namespace.Namespace, error) { return backend, nil }); !errors.Is(err, readiness.ErrLimit) {
			t.Fatalf("registration failure = %v", err)
		}
		usage, closed := account.Snapshot()
		if closed || usage != (quota.Usage{}) || backend.closed.Load() != 1 || table.Len() != 1 || state.NamespaceHandle() != 0 {
			t.Fatalf("rollback usage=%+v closed=%v backend=%d resources=%d handle=%v", usage, closed, backend.closed.Load(), table.Len(), state.NamespaceHandle())
		}
	})
}
