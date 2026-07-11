package readiness

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/resource"
)

type testPollable struct {
	mu     sync.Mutex
	ready  namespace.Readiness
	closed bool
}

func (p *testPollable) Readiness() namespace.Readiness {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready
}

func (p *testPollable) Close() error {
	p.mu.Lock()
	p.closed = true
	p.ready = namespace.ReadyClosed
	p.mu.Unlock()
	return nil
}

type testService struct {
	testPollable
	attempts atomic.Int32
	work     bool
}

func (s *testService) TryService(budget namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	s.attempts.Add(1)
	if !budget.Valid() {
		return namespace.ServiceReport{}, 0, namespace.Fail(namespace.FailureInvalidArgument, ErrInvalidBudget)
	}
	if !s.work {
		return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
	}
	s.mu.Lock()
	s.ready = namespace.ReadyReadable
	s.mu.Unlock()
	return namespace.ServiceReport{Packets: 1, Bytes: 1, Operations: 1}, namespace.ProgressDone, nil
}

type badService struct{ testPollable }

func (s *badService) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressDone, nil
}

type closeOnly struct{}

func (closeOnly) Close() error { return nil }

func TestCoordinatorLevelTriggeredSnapshotsAndBoundedOutput(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 3})
	first := &testPollable{ready: namespace.ReadyReadable}
	second := &testPollable{}
	third := &testPollable{ready: namespace.ReadyWritable}
	firstHandle := addAndRegister(t, table, coordinator, resource.KindUDPSocket, first)
	_ = addAndRegister(t, table, coordinator, resource.KindTCPStream, second)
	thirdHandle := addAndRegister(t, table, coordinator, resource.KindDNSQuery, third)

	budget := Budget{Scans: 3, Events: 2}
	events := make([]Event, 2)
	for attempt := 0; attempt < 2; attempt++ {
		report, progress, err := coordinator.TryPoll(events, budget)
		if err != nil || progress != namespace.ProgressDone || !report.ValidFor(budget) {
			t.Fatalf("poll %d = %+v, %v, %v", attempt, report, progress, err)
		}
		if report.Scanned != 3 || report.Events != 2 {
			t.Fatalf("poll %d report = %+v", attempt, report)
		}
		seen := map[resource.Handle]namespace.Readiness{}
		for _, event := range events {
			if !event.Valid() {
				t.Fatalf("invalid event: %+v", event)
			}
			seen[event.Handle] = event.Readiness
		}
		if seen[firstHandle] != namespace.ReadyReadable || seen[thirdHandle] != namespace.ReadyWritable {
			t.Fatalf("level snapshot %d = %+v", attempt, seen)
		}
	}

	oneEvent := make([]Event, 1)
	oneBudget := Budget{Scans: 3, Events: 1}
	report, _, err := coordinator.TryPoll(oneEvent, oneBudget)
	if err != nil || report.Events != 1 || report.Scanned > 3 {
		t.Fatalf("bounded output = %+v, %v", report, err)
	}
	if snapshot := coordinator.Snapshot(); snapshot.Registrations != 3 || snapshot.Capacity != 3 || snapshot.Closed {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestCoordinatorRemovesStaleHandlesWithinScanBudget(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 2})
	stale := &testPollable{ready: namespace.ReadyReadable}
	live := &testPollable{ready: namespace.ReadyWritable}
	staleHandle := addAndRegister(t, table, coordinator, resource.KindUDPSocket, stale)
	liveHandle := addAndRegister(t, table, coordinator, resource.KindTCPStream, live)
	if err := table.CloseHandle(staleHandle, resource.KindUDPSocket); err != nil {
		t.Fatal(err)
	}

	budget := Budget{Scans: 2, Events: 1}
	events := make([]Event, 1)
	report, progress, err := coordinator.TryPoll(events, budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidFor(budget) {
		t.Fatalf("stale poll = %+v, %v, %v", report, progress, err)
	}
	if report.StaleRegistrations != 1 || report.Events != 1 || events[0].Handle != liveHandle {
		t.Fatalf("stale poll result = %+v, %+v", report, events)
	}
	if snapshot := coordinator.Snapshot(); snapshot.Registrations != 1 {
		t.Fatalf("stale registration retained: %+v", snapshot)
	}
	if coordinator.Unregister(staleHandle) {
		t.Fatal("removed stale handle unregistered twice")
	}
}

func TestCoordinatorBoundsServiceAttemptsAndRotatesCursor(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 2})
	first := &testService{work: true}
	second := &testService{work: true}
	firstHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, first)
	secondHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, second)

	budget := Budget{
		Scans:           2,
		Events:          2,
		ServiceAttempts: 1,
		Service:         namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1},
	}
	events := make([]Event, 2)
	report, progress, err := coordinator.TryPoll(events, budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidFor(budget) {
		t.Fatalf("first service poll = %+v, %v, %v", report, progress, err)
	}
	if report.Scanned != 1 || report.ServiceAttempts != 1 || report.ServiceCompleted != 1 || report.Events != 1 || events[0].Handle != firstHandle {
		t.Fatalf("first service bound = %+v, %+v", report, events)
	}
	if first.attempts.Load() != 1 || second.attempts.Load() != 0 {
		t.Fatalf("first attempts = %d/%d", first.attempts.Load(), second.attempts.Load())
	}

	clear(events)
	report, progress, err = coordinator.TryPoll(events, budget)
	if err != nil || progress != namespace.ProgressDone || events[0].Handle != secondHandle {
		t.Fatalf("second service poll = %+v, %v, %v, %+v", report, progress, err, events)
	}
	if first.attempts.Load() != 1 || second.attempts.Load() != 1 {
		t.Fatalf("rotated attempts = %d/%d", first.attempts.Load(), second.attempts.Load())
	}
}

func TestCoordinatorRejectsInvalidBackendServiceResults(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 1})
	addAndRegister(t, table, coordinator, resource.KindNamespace, &badService{})
	budget := Budget{
		Scans:           1,
		Events:          1,
		ServiceAttempts: 1,
		Service:         namespace.ServiceBudget{Packets: 1, Bytes: 1, Operations: 1},
	}
	_, _, err := coordinator.TryPoll(make([]Event, 1), budget)
	failure, ok := namespace.FailureOf(err)
	if !ok || failure != namespace.FailureIO || !errors.Is(err, ErrInvalidServiceResult) {
		t.Fatalf("invalid service result error = %v", err)
	}
}

func TestCoordinatorRegistrationValidationAndFiniteLimit(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 1})
	pollable := &testPollable{}
	handle, err := table.Add(resource.KindPollable, pollable)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Register(0, resource.KindPollable); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatalf("zero registration = %v", err)
	}
	if err := coordinator.Register(handle, resource.KindInvalid); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatalf("invalid kind = %v", err)
	}
	if err := coordinator.Register(handle, resource.KindPollable); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Register(handle, resource.KindPollable); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate registration = %v", err)
	}
	otherHandle, err := table.Add(resource.KindPollable, &testPollable{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Register(otherHandle, resource.KindPollable); !errors.Is(err, ErrLimit) {
		t.Fatalf("registration limit = %v", err)
	}

	nonPollable, err := table.Add(resource.KindPollable, closeOnly{})
	if err != nil {
		t.Fatal(err)
	}
	other := newCoordinator(t, table, Config{MaxRegistrations: 1})
	if err := other.Register(nonPollable, resource.KindPollable); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatalf("non-pollable registration = %v", err)
	}
	if _, _, err := coordinator.TryPoll(nil, Budget{Scans: 1, Events: 1}); !errors.Is(err, ErrInvalidBudget) {
		t.Fatalf("short event buffer = %v", err)
	}
}

func TestCoordinatorCloseAndConcurrentPoll(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, DefaultConfig())
	for i := 0; i < 16; i++ {
		addAndRegister(t, table, coordinator, resource.KindPollable, &testPollable{ready: namespace.ReadyReadable})
	}
	budget := Budget{Scans: 4, Events: 4}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			events := make([]Event, 4)
			for j := 0; j < 100; j++ {
				_, _, err := coordinator.TryPoll(events, budget)
				if err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("poll error: %v", err)
					return
				}
			}
		}()
	}
	if err := coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := coordinator.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if snapshot := coordinator.Snapshot(); !snapshot.Closed || snapshot.Registrations != 0 {
		t.Fatalf("closed snapshot = %+v", snapshot)
	}
	if coordinator.Unregister(1) {
		t.Fatal("unregister succeeded after close")
	}
}

func newTable(t testing.TB) *resource.Table {
	t.Helper()
	table, err := resource.NewTable()
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func newCoordinator(t testing.TB, table *resource.Table, config Config) *Coordinator {
	t.Helper()
	coordinator, err := New(table, config)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func addAndRegister(t testing.TB, table *resource.Table, coordinator *Coordinator, kind resource.Kind, value resource.Resource) resource.Handle {
	t.Helper()
	handle, err := table.Add(kind, value)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Register(handle, kind); err != nil {
		t.Fatal(err)
	}
	return handle
}
