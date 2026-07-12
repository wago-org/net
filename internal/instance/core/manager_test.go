package core

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct {
	closed   atomic.Int32
	socket   namespace.UDPSocket
	listener namespace.TCPListener
	stream   namespace.TCPStream
	query    namespace.DNSQuery
}

func (n *fakeNamespace) Close() error {
	n.closed.Add(1)
	return nil
}

func (n *fakeNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (n *fakeNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	if n.socket != nil {
		return n.socket, namespace.ProgressDone, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	if n.listener != nil {
		return n.listener, namespace.ProgressDone, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	if n.stream != nil {
		return n.stream, namespace.ProgressInProgress, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	if n.query != nil {
		return n.query, namespace.ProgressInProgress, nil
	}
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type fakeUDPSocket struct {
	closed atomic.Int32
	local  namespace.Endpoint
}

func (s *fakeUDPSocket) Close() error {
	s.closed.Add(1)
	return nil
}
func (s *fakeUDPSocket) Readiness() namespace.Readiness    { return namespace.ReadyWritable }
func (s *fakeUDPSocket) LocalEndpoint() namespace.Endpoint { return s.local }
func (s *fakeUDPSocket) TryReceive([]byte) (namespace.DatagramResult, error) {
	return namespace.DatagramResult{}, nil
}
func (s *fakeUDPSocket) TrySend([]byte, namespace.Endpoint) (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}

type fakeTCPListener struct {
	closed   atomic.Int32
	local    namespace.Endpoint
	accepted namespace.TCPStream
}

func (l *fakeTCPListener) Close() error {
	l.closed.Add(1)
	return nil
}
func (l *fakeTCPListener) Readiness() namespace.Readiness    { return namespace.ReadyAccept }
func (l *fakeTCPListener) LocalEndpoint() namespace.Endpoint { return l.local }
func (l *fakeTCPListener) TryAccept() (namespace.TCPStream, namespace.Progress, error) {
	if l.accepted == nil {
		return nil, namespace.ProgressWouldBlock, nil
	}
	stream := l.accepted
	l.accepted = nil
	return stream, namespace.ProgressDone, nil
}

type fakeTCPStream struct {
	closed  atomic.Int32
	local   namespace.Endpoint
	remote  namespace.Endpoint
	input   []byte
	written []byte
}

func (s *fakeTCPStream) Close() error {
	s.closed.Add(1)
	return nil
}
func (s *fakeTCPStream) Readiness() namespace.Readiness {
	return namespace.ReadyConnected | namespace.ReadyReadable | namespace.ReadyWritable
}
func (s *fakeTCPStream) LocalEndpoint() namespace.Endpoint  { return s.local }
func (s *fakeTCPStream) RemoteEndpoint() namespace.Endpoint { return s.remote }
func (s *fakeTCPStream) TryFinishConnect() (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}
func (s *fakeTCPStream) TryRead(dst []byte) (namespace.IOResult, error) {
	if len(s.input) == 0 {
		return namespace.IOResult{State: namespace.IOWouldBlock}, nil
	}
	n := copy(dst, s.input)
	s.input = s.input[n:]
	return namespace.IOResult{Bytes: n, State: namespace.IOReady}, nil
}
func (s *fakeTCPStream) TryWrite(src []byte) (namespace.IOResult, error) {
	if len(src) == 0 {
		return namespace.IOResult{State: namespace.IOReady}, nil
	}
	n := min(3, len(src))
	s.written = append(s.written, src[:n]...)
	return namespace.IOResult{Bytes: n, State: namespace.IOReady}, nil
}
func (s *fakeTCPStream) TryShutdownWrite() (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}

type fakeDNSQuery struct {
	closed   atomic.Int32
	canceled atomic.Int32
	records  []namespace.DNSRecord
	failure  error
}

func (q *fakeDNSQuery) Close() error {
	q.closed.Add(1)
	return nil
}
func (q *fakeDNSQuery) Cancel() error {
	q.canceled.Add(1)
	q.failure = namespace.Fail(namespace.FailureCanceled, nil)
	return nil
}
func (q *fakeDNSQuery) Readiness() namespace.Readiness {
	if q.failure != nil {
		return namespace.ReadyError
	}
	if len(q.records) != 0 {
		return namespace.ReadyDNSResult
	}
	return 0
}
func (q *fakeDNSQuery) TryNext() (namespace.DNSRecord, namespace.DNSNext, error) {
	if q.failure != nil {
		return namespace.DNSRecord{}, 0, q.failure
	}
	if len(q.records) == 0 {
		return namespace.DNSRecord{}, namespace.DNSNextWouldBlock, nil
	}
	record := q.records[0]
	q.records = q.records[1:]
	return record, namespace.DNSNextReady, nil
}

type fakePollable struct{}

func (fakePollable) Close() error                   { return nil }
func (fakePollable) Readiness() namespace.Readiness { return namespace.ReadyReadable }

func TestManagerReadinessIsRightSizedToResourceQuota(t *testing.T) {
	config := DefaultConfig()
	config.Limits.Resources = 2
	config.Readiness.MaxRegistrations = 16
	manager, err := NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	if manager.readiness.MaxRegistrations != 2 {
		t.Fatalf("right-sized registrations = %d, want 2", manager.readiness.MaxRegistrations)
	}
	config.Limits.Resources = 0
	manager, err = NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	if manager.readiness.MaxRegistrations != 1 {
		t.Fatalf("zero-resource registrations = %d, want 1", manager.readiness.MaxRegistrations)
	}
}

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
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
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
		config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
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
		config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return nil, factoryErr }
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
		if _, err := state.createNamespace(func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return backend, nil }); !errors.Is(err, readiness.ErrLimit) {
			t.Fatalf("registration failure = %v", err)
		}
		usage, closed := account.Snapshot()
		if closed || usage != (quota.Usage{}) || backend.closed.Load() != 1 || table.Len() != 1 || state.NamespaceHandle() != 0 {
			t.Fatalf("rollback usage=%+v closed=%v backend=%d resources=%d handle=%v", usage, closed, backend.closed.Load(), table.Len(), state.NamespaceHandle())
		}
	})
}
