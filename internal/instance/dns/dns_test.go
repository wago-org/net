package dns

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	core "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct{ query namespace.DNSQuery }

func (*fakeNamespace) Close() error                   { return nil }
func (*fakeNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (*fakeNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*fakeNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*fakeNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return n.query, namespace.ProgressInProgress, nil
}
func (*fakeNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type fakeQuery struct {
	closed   atomic.Int32
	canceled atomic.Int32
	records  []namespace.DNSRecord
	failure  error
}

func (q *fakeQuery) Close() error { q.closed.Add(1); return nil }
func (q *fakeQuery) Cancel() error {
	q.canceled.Add(1)
	q.failure = namespace.Fail(namespace.FailureCanceled, nil)
	return nil
}
func (q *fakeQuery) Readiness() namespace.Readiness {
	if q.failure != nil {
		return namespace.ReadyError
	}
	if len(q.records) != 0 {
		return namespace.ReadyDNSResult
	}
	return 0
}
func (q *fakeQuery) TryNext() (namespace.DNSRecord, namespace.DNSNext, error) {
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

func TestOperationsPreserveReadinessCancellationAndGenerationSafety(t *testing.T) {
	record := namespace.DNSRecord{Name: "example.com", Type: namespace.DNSRecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.10")}
	query := &fakeQuery{records: []namespace.DNSRecord{record}}
	state, manager, instance := attachState(t, &fakeNamespace{query: query}, 2)
	defer manager.Detach(instance)

	handle, progress, err := Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
	if err != nil || progress != namespace.ProgressInProgress || handle == 0 {
		t.Fatalf("Resolve = %v, %v, %v", handle, progress, err)
	}
	if got, next, err := Next(state, handle); err != nil || next != namespace.DNSNextReady || got != record {
		t.Fatalf("Next = %+v, %v, %v", got, next, err)
	}
	if _, _, err := Next(state, state.NamespaceHandle()); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind next = %v", err)
	}
	if err := Cancel(state, handle); err != nil || query.canceled.Load() != 1 {
		t.Fatalf("Cancel = %d, %v", query.canceled.Load(), err)
	}
	if _, _, err := Next(state, handle); failureOf(t, err) != namespace.FailureCanceled {
		t.Fatalf("canceled result = %v", err)
	}
	if err := state.CloseHandle(handle, resource.KindDNSQuery); err != nil || query.closed.Load() != 1 {
		t.Fatalf("close = %v, count=%d", err, query.closed.Load())
	}
	if _, _, err := Next(state, handle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale next = %v", err)
	}
}

func TestRegistrationRollbackAndCloseRace(t *testing.T) {
	query := new(fakeQuery)
	state, manager, instance := attachState(t, &fakeNamespace{query: query}, 1)
	if handle, progress, err := Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}); handle != 0 || progress != 0 || !errors.Is(err, readiness.ErrLimit) {
		t.Fatalf("Resolve rollback = %v, %v, %v", handle, progress, err)
	}
	if query.closed.Load() != 1 || state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("rollback retained state: closes=%d resources=%d readiness=%+v", query.closed.Load(), state.Resources().Len(), state.Readiness().Snapshot())
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}

	liveQuery := new(fakeQuery)
	liveState, liveManager, liveInstance := attachState(t, &fakeNamespace{query: liveQuery}, 2)
	handle, _, err := Resolve(liveState, liveState.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				_, _, _ = Next(liveState, handle)
				_ = Cancel(liveState, handle)
			}
		}()
	}
	if err := liveManager.Detach(liveInstance); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if liveQuery.closed.Load() != 1 {
		t.Fatalf("close count = %d", liveQuery.closed.Load())
	}
}

func attachState(t testing.TB, backend namespace.Namespace, maxRegistrations int) (*core.State, *core.Manager, *wago.Instance) {
	t.Helper()
	config := core.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: maxRegistrations}
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (namespace.Namespace, error) { return backend, nil }
	manager, err := core.NewManagerConfigured(config)
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

func failureOf(t testing.TB, err error) namespace.Failure {
	t.Helper()
	failure, ok := namespace.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}
