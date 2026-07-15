package mdns

import (
	"errors"
	"net/netip"
	"runtime"
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

type fakeBase struct{ closeCalls int }

func (b *fakeBase) Close() error              { b.closeCalls++; return nil }
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
	record     mdnsns.Record
	next       mdnsns.Next
	failure    error
	canceled   bool
	closed     bool
	closeCalls int
}

func (q *fakeQuery) Close() error { q.closed = true; q.closeCalls++; return nil }
func (q *fakeQuery) Cancel() error {
	q.canceled = true
	return nil
}
func (q *fakeQuery) Readiness() nscore.Readiness { return nscore.ReadyMDNSResult }
func (q *fakeQuery) TryNext() (mdnsns.Record, mdnsns.Next, error) {
	return q.record, q.next, q.failure
}

type fakeAnnouncement struct {
	next       mdnsns.Next
	failure    error
	canceled   bool
	closed     bool
	closeCalls int
}

func (a *fakeAnnouncement) Close() error { a.closed = true; a.closeCalls++; return nil }
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
	failedQuery := new(fakeQuery)
	failedAnnouncement := new(fakeAnnouncement)
	backend := &fakeNamespace{
		query: failedQuery, queryProgress: nscore.ProgressDone, queryFailure: backendFailure,
		announcement: failedAnnouncement, announceProgress: nscore.ProgressDone, announceFailure: backendFailure,
	}
	state, manager, instance := attachState(t, backend, 4)
	defer manager.Detach(instance)
	resourcesBefore := state.Resources().Len()
	readinessBefore := state.Readiness().Snapshot()

	if handle, progress, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA}); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed Query = %v, %v, %v", handle, progress, err)
	}
	if handle, progress, err := Announce(state, state.NamespaceHandle(), 0); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed Announce = %v, %v, %v", handle, progress, err)
	}
	if failedQuery.closeCalls != 1 || failedAnnouncement.closeCalls != 1 || state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("failed creations retained state: query closes=%d announcement closes=%d resources=%d readiness=%+v", failedQuery.closeCalls, failedAnnouncement.closeCalls, state.Resources().Len(), state.Readiness().Snapshot())
	}
	var typedNilQuery *fakeQuery
	var typedNilAnnouncement *fakeAnnouncement
	backend.query, backend.announcement = typedNilQuery, typedNilAnnouncement
	if handle, progress, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA}); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("typed-nil failed Query = %v, %v, %v", handle, progress, err)
	}
	if handle, progress, err := Announce(state, state.NamespaceHandle(), 0); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("typed-nil failed Announce = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("typed-nil failed creations retained state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
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

func TestInstanceMDNSMalformedSuccessfulCreationRollsBackWithoutPublication(t *testing.T) {
	var typedNilQuery *fakeQuery
	var typedNilAnnouncement *fakeAnnouncement
	for _, test := range []struct {
		name         string
		resource     nscore.Resource
		progress     nscore.Progress
		announcement bool
	}{
		{name: "query wrong resource type", resource: new(fakeAnnouncement), progress: nscore.ProgressDone},
		{name: "query would-block progress", resource: new(fakeQuery), progress: nscore.ProgressWouldBlock},
		{name: "query unknown progress", resource: new(fakeQuery), progress: nscore.Progress(99)},
		{name: "query typed nil resource", resource: typedNilQuery, progress: nscore.ProgressDone},
		{name: "query missing resource", progress: nscore.ProgressDone},
		{name: "announcement wrong resource type", resource: new(fakeQuery), progress: nscore.ProgressDone, announcement: true},
		{name: "announcement would-block progress", resource: new(fakeAnnouncement), progress: nscore.ProgressWouldBlock, announcement: true},
		{name: "announcement unknown progress", resource: new(fakeAnnouncement), progress: nscore.Progress(99), announcement: true},
		{name: "announcement typed nil resource", resource: typedNilAnnouncement, progress: nscore.ProgressDone, announcement: true},
		{name: "announcement missing resource", progress: nscore.ProgressDone, announcement: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := new(fakeNamespace)
			if test.announcement {
				backend.announcement, backend.announceProgress = test.resource, test.progress
			} else {
				backend.query, backend.queryProgress = test.resource, test.progress
			}
			state, manager, instance := attachState(t, backend, 4)
			defer manager.Detach(instance)
			resourcesBefore := state.Resources().Len()
			readinessBefore := state.Readiness().Snapshot()

			var handle resource.Handle
			var progress nscore.Progress
			var err error
			if test.announcement {
				handle, progress, err = Announce(state, state.NamespaceHandle(), 0)
			} else {
				handle, progress, err = Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
			}
			if handle != 0 || progress != 0 || failureOf(err) != nscore.FailureIO {
				t.Fatalf("malformed creation = %v, %v, %v", handle, progress, err)
			}
			if state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
				t.Fatalf("malformed creation published state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
			}
			switch created := test.resource.(type) {
			case *fakeQuery:
				if created != nil && created.closeCalls != 1 {
					t.Fatalf("query close calls = %d", created.closeCalls)
				}
			case *fakeAnnouncement:
				if created != nil && created.closeCalls != 1 {
					t.Fatalf("announcement close calls = %d", created.closeCalls)
				}
			}
		})
	}
}

func TestInstanceMDNSReadinessRegistrationFailureRollsBackResource(t *testing.T) {
	announcement := new(fakeAnnouncement)
	backend := &fakeNamespace{announcement: announcement, announceProgress: nscore.ProgressInProgress}
	state, manager, instance := attachState(t, backend, 1)
	defer manager.Detach(instance)
	resourcesBefore := state.Resources().Len()
	readinessBefore := state.Readiness().Snapshot()

	if handle, progress, err := Announce(state, state.NamespaceHandle(), 0); handle != 0 || progress != 0 || !errors.Is(err, readiness.ErrLimit) {
		t.Fatalf("announcement rollback = %v, %v, %v", handle, progress, err)
	}
	if announcement.closeCalls != 1 || state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("rollback retained state: closes=%d resources=%d readiness=%+v", announcement.closeCalls, state.Resources().Len(), state.Readiness().Snapshot())
	}
}

func TestInstanceMDNSSteadyStateOperationsDoNotAllocate(t *testing.T) {
	if runtime.Compiler == "tinygo" {
		return
	}
	query := &fakeQuery{
		record: mdnsns.Record{
			Name: "host.local", Type: mdnsns.RecordA, TTLSeconds: 120,
			Address: netip.MustParseAddr("192.0.2.10"),
		},
		next: mdnsns.NextReady,
	}
	announcement := &fakeAnnouncement{next: mdnsns.NextReady}
	backend := &fakeNamespace{
		query: query, queryProgress: nscore.ProgressInProgress,
		announcement: announcement, announceProgress: nscore.ProgressInProgress,
	}
	state, manager, instance := attachState(t, backend, 8)
	defer manager.Detach(instance)
	queryHandle, _, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	announcementHandle, _, err := Announce(state, state.NamespaceHandle(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		call func()
	}{
		{name: "next", call: func() { _, _, _ = Next(state, queryHandle) }},
		{name: "cancel query", call: func() { query.canceled = false; _ = CancelQuery(state, queryHandle) }},
		{name: "finish announcement", call: func() { _, _ = FinishAnnouncement(state, announcementHandle) }},
		{name: "cancel announcement", call: func() { announcement.canceled = false; _ = CancelAnnouncement(state, announcementHandle) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if allocs := testing.AllocsPerRun(1000, test.call); allocs != 0 {
				t.Fatalf("allocations = %v, want 0", allocs)
			}
		})
	}
}

func TestInstanceMDNSCancelIsKindAndGenerationSafe(t *testing.T) {
	query := new(fakeQuery)
	announcement := new(fakeAnnouncement)
	backend := &fakeNamespace{
		query: query, queryProgress: nscore.ProgressInProgress,
		announcement: announcement, announceProgress: nscore.ProgressInProgress,
	}
	state, manager, instance := attachState(t, backend, 8)
	defer manager.Detach(instance)
	queryHandle, _, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	announcementHandle, _, err := Announce(state, state.NamespaceHandle(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := CancelQuery(state, announcementHandle); !errors.Is(err, resource.ErrBadHandle) || query.canceled || announcement.canceled {
		t.Fatalf("wrong-kind query cancel = %v query=%v announcement=%v", err, query.canceled, announcement.canceled)
	}
	if err := CancelAnnouncement(state, queryHandle); !errors.Is(err, resource.ErrBadHandle) || query.canceled || announcement.canceled {
		t.Fatalf("wrong-kind announcement cancel = %v query=%v announcement=%v", err, query.canceled, announcement.canceled)
	}
	registrations := state.Readiness().Snapshot().Registrations
	if err := state.CloseHandle(queryHandle, resource.KindMDNSQuery); err != nil || query.closeCalls != 1 {
		t.Fatalf("close query = %v calls=%d", err, query.closeCalls)
	}
	if got := state.Readiness().Snapshot().Registrations; got != registrations-1 {
		t.Fatalf("query close readiness registrations = %d, want %d", got, registrations-1)
	}

	replacement := new(fakeQuery)
	backend.query = replacement
	replacementHandle, _, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	if replacementHandle == queryHandle {
		t.Fatal("replacement query reused stale generation")
	}
	if err := CancelQuery(state, queryHandle); !errors.Is(err, resource.ErrBadHandle) || replacement.canceled {
		t.Fatalf("stale query cancel = %v replacement canceled=%v", err, replacement.canceled)
	}
	if err := CancelQuery(state, replacementHandle); err != nil || !replacement.canceled {
		t.Fatalf("replacement query cancel = %v canceled=%v", err, replacement.canceled)
	}
	if err := CancelAnnouncement(state, announcementHandle); err != nil || !announcement.canceled {
		t.Fatalf("announcement cancel = %v canceled=%v", err, announcement.canceled)
	}
	if query.canceled {
		t.Fatal("closed stale query was canceled")
	}
}

func BenchmarkInstanceMDNSOperations(b *testing.B) {
	query := &fakeQuery{
		record: mdnsns.Record{
			Name: "host.local", Type: mdnsns.RecordA, TTLSeconds: 120,
			Address: netip.MustParseAddr("192.0.2.10"),
		},
		next: mdnsns.NextReady,
	}
	announcement := &fakeAnnouncement{next: mdnsns.NextReady}
	backend := &fakeNamespace{
		query: query, queryProgress: nscore.ProgressInProgress,
		announcement: announcement, announceProgress: nscore.ProgressInProgress,
	}
	state, manager, instance := attachState(b, backend, 8)
	defer manager.Detach(instance)
	queryHandle, _, err := Query(state, state.NamespaceHandle(), mdnsns.Request{Name: "host.local", Types: mdnsns.RecordsA})
	if err != nil {
		b.Fatal(err)
	}
	announcementHandle, _, err := Announce(state, state.NamespaceHandle(), 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Next", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, next, err := Next(state, queryHandle); err != nil || next != mdnsns.NextReady {
				b.Fatalf("Next = %v, %v", next, err)
			}
		}
	})
	b.Run("CancelQuery", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			query.canceled = false
			if err := CancelQuery(state, queryHandle); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("FinishAnnouncement", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if next, err := FinishAnnouncement(state, announcementHandle); err != nil || next != mdnsns.NextReady {
				b.Fatalf("FinishAnnouncement = %v, %v", next, err)
			}
		}
	})
	b.Run("CancelAnnouncement", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			announcement.canceled = false
			if err := CancelAnnouncement(state, announcementHandle); err != nil {
				b.Fatal(err)
			}
		}
	})
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
