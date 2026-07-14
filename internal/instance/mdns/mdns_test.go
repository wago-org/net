package mdns

import (
	"errors"
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeBase struct{}

func (*fakeBase) Close() error                { return nil }
func (*fakeBase) Readiness() nscore.Readiness { return 0 }
func (*fakeBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeNamespace struct {
	query            nscore.Resource
	queryProgress    nscore.Progress
	queryFailure     error
	announcement     nscore.Resource
	announceProgress nscore.Progress
	announceFailure  error
}

func (n *fakeNamespace) TryQuery(mdnsns.Request) (nscore.Resource, nscore.Progress, error) {
	return n.query, n.queryProgress, n.queryFailure
}
func (n *fakeNamespace) TryAnnounce(uint16) (nscore.Resource, nscore.Progress, error) {
	return n.announcement, n.announceProgress, n.announceFailure
}

type fakeQuery struct {
	record   mdnsns.Record
	next     mdnsns.Next
	failure  error
	canceled bool
	closed   bool
}

func (q *fakeQuery) Close() error { q.closed = true; return nil }
func (q *fakeQuery) Cancel() error {
	q.canceled = true
	return nil
}
func (q *fakeQuery) Readiness() nscore.Readiness { return nscore.ReadyMDNSResult }
func (q *fakeQuery) TryNext() (mdnsns.Record, mdnsns.Next, error) {
	return q.record, q.next, q.failure
}

type fakeAnnouncement struct {
	next     mdnsns.Next
	failure  error
	canceled bool
	closed   bool
}

func (a *fakeAnnouncement) Close() error { a.closed = true; return nil }
func (a *fakeAnnouncement) Cancel() error {
	a.canceled = true
	return nil
}
func (a *fakeAnnouncement) Readiness() nscore.Readiness { return nscore.ReadyMDNSAnnouncement }
func (a *fakeAnnouncement) TryFinish() (mdnsns.Next, error) {
	return a.next, a.failure
}

func TestInstanceMDNSExactKindLifecycle(t *testing.T) {
	record := mdnsns.Record{
		Name: "host.local", Type: mdnsns.RecordA, TTLSeconds: 120,
		Address: netip.MustParseAddr("192.0.2.10"), CacheFlush: true,
	}
	query := &fakeQuery{record: record, next: mdnsns.NextReady}
	announcement := &fakeAnnouncement{next: mdnsns.NextReady}
	backend := &fakeNamespace{
		query: query, queryProgress: nscore.ProgressInProgress,
		announcement: announcement, announceProgress: nscore.ProgressDone,
	}
	state, manager, instance := attachState(t, backend, 8)
	defer manager.Detach(instance)

	queryHandle, progress, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
	if err != nil || progress != nscore.ProgressInProgress || queryHandle == 0 {
		t.Fatalf("Query = %v, %v, %v", queryHandle, progress, err)
	}
	announcementHandle, progress, err := Announce(state, state.NamespaceHandle(), 0)
	if err != nil || progress != nscore.ProgressDone || announcementHandle == 0 {
		t.Fatalf("Announce = %v, %v, %v", announcementHandle, progress, err)
	}
	if _, err := state.Resources().Lookup(queryHandle, resource.KindMDNSAnnouncement); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind query lookup = %v", err)
	}
	if _, err := state.Resources().Lookup(announcementHandle, resource.KindMDNSQuery); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind announcement lookup = %v", err)
	}
	got, next, err := Next(state, queryHandle)
	if err != nil || next != mdnsns.NextReady || got != record {
		t.Fatalf("Next = %+v, %v, %v", got, next, err)
	}
	if next, err := FinishAnnouncement(state, announcementHandle); err != nil || next != mdnsns.NextReady {
		t.Fatalf("FinishAnnouncement = %v, %v", next, err)
	}
	if err := CancelQuery(state, queryHandle); err != nil || !query.canceled {
		t.Fatalf("CancelQuery = %v, canceled=%v", err, query.canceled)
	}
	if err := CancelAnnouncement(state, announcementHandle); err != nil || !announcement.canceled {
		t.Fatalf("CancelAnnouncement = %v, canceled=%v", err, announcement.canceled)
	}
	if err := state.CloseHandle(queryHandle, resource.KindMDNSQuery); err != nil || !query.closed {
		t.Fatalf("close query = %v, closed=%v", err, query.closed)
	}
	if err := state.CloseHandle(announcementHandle, resource.KindMDNSAnnouncement); err != nil || !announcement.closed {
		t.Fatalf("close announcement = %v, closed=%v", err, announcement.closed)
	}
	if _, _, err := Next(state, queryHandle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale query = %v", err)
	}
	if _, err := FinishAnnouncement(state, announcementHandle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale announcement = %v", err)
	}
}

func TestInstanceMDNSRejectsInvalidBackendResults(t *testing.T) {
	query := &fakeQuery{
		record: mdnsns.Record{Name: "host.local", Type: mdnsns.RecordA, TTLSeconds: 0, Address: netip.MustParseAddr("192.0.2.10")},
		next:   mdnsns.NextReady,
	}
	announcement := &fakeAnnouncement{next: 99}
	backend := &fakeNamespace{
		query: query, queryProgress: nscore.ProgressDone,
		announcement: announcement, announceProgress: nscore.ProgressDone,
	}
	state, manager, instance := attachState(t, backend, 8)
	defer manager.Detach(instance)
	queryHandle, _, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	if record, next, err := Next(state, queryHandle); failureOf(err) != nscore.FailureIO || record != (mdnsns.Record{}) || next != 0 {
		t.Fatalf("invalid record = %+v, %v, %v", record, next, err)
	}
	announcementHandle, _, err := Announce(state, state.NamespaceHandle(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if next, err := FinishAnnouncement(state, announcementHandle); failureOf(err) != nscore.FailureIO || next != 0 {
		t.Fatalf("invalid finish = %v, %v", next, err)
	}
}

func TestInstanceMDNSCanonicalizesFailedAndUnusedOutputs(t *testing.T) {
	dirtyRecord := mdnsns.Record{Name: "dirty.local", Type: mdnsns.RecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.99")}
	backendFailure := nscore.Fail(nscore.FailureTimedOut, errors.New("timeout"))
	backend := &fakeNamespace{
		query: new(fakeQuery), queryProgress: nscore.ProgressDone, queryFailure: backendFailure,
		announcement: new(fakeAnnouncement), announceProgress: nscore.ProgressDone, announceFailure: backendFailure,
	}
	state, manager, instance := attachState(t, backend, 4)
	defer manager.Detach(instance)

	if handle, progress, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA}); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed Query = %v, %v, %v", handle, progress, err)
	}
	if handle, progress, err := Announce(state, state.NamespaceHandle(), 0); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed Announce = %v, %v, %v", handle, progress, err)
	}

	query := &fakeQuery{record: dirtyRecord, next: mdnsns.NextWouldBlock}
	announcement := &fakeAnnouncement{next: mdnsns.NextWouldBlock}
	backend.query, backend.queryProgress, backend.queryFailure = query, nscore.ProgressInProgress, nil
	backend.announcement, backend.announceProgress, backend.announceFailure = announcement, nscore.ProgressInProgress, nil
	queryHandle, _, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	announcementHandle, _, err := Announce(state, state.NamespaceHandle(), 0)
	if err != nil {
		t.Fatal(err)
	}

	if record, next, err := Next(state, queryHandle); err != nil || next != mdnsns.NextWouldBlock || record != (mdnsns.Record{}) {
		t.Fatalf("would-block Next = %+v, %v, %v", record, next, err)
	}
	query.record, query.next, query.failure = dirtyRecord, mdnsns.NextReady, backendFailure
	if record, next, err := Next(state, queryHandle); record != (mdnsns.Record{}) || next != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed Next = %+v, %v, %v", record, next, err)
	}
	announcement.failure = backendFailure
	if next, err := FinishAnnouncement(state, announcementHandle); next != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed FinishAnnouncement = %v, %v", next, err)
	}
}

func TestInstanceMDNSCreationRollbackClosesResources(t *testing.T) {
	query := &fakeQuery{}
	backend := &fakeNamespace{query: query, queryProgress: 99}
	state, manager, instance := attachState(t, backend, 4)
	if handle, progress, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA}); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureIO || !query.closed {
		t.Fatalf("invalid query = %v, %v, %v, closed=%v", handle, progress, err, query.closed)
	}
	_ = manager.Detach(instance)

	announcement := &fakeAnnouncement{}
	backend = &fakeNamespace{announcement: announcement, announceProgress: nscore.ProgressInProgress}
	state, manager, instance = attachState(t, backend, 1)
	defer manager.Detach(instance)
	if handle, progress, err := Announce(state, state.NamespaceHandle(), 0); handle != 0 || progress != 0 || !errors.Is(err, readiness.ErrLimit) || !announcement.closed {
		t.Fatalf("announcement rollback = %v, %v, %v, closed=%v", handle, progress, err, announcement.closed)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("rollback retained state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
}

func attachState(t testing.TB, backend mdnsns.Namespace, maxRegistrations int) (*instancecore.State, *instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: maxRegistrations}
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: mdnsns.ServiceKey, Value: backend})
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
	return state, manager, instance
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}
