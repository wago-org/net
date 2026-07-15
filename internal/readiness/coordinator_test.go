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
	failure  error
	invalid  bool
}

func (s *testService) TryService(budget namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	s.attempts.Add(1)
	if !budget.Valid() {
		return namespace.ServiceReport{}, 0, namespace.Fail(namespace.FailureInvalidArgument, ErrInvalidBudget)
	}
	if s.failure != nil {
		return namespace.ServiceReport{}, 0, s.failure
	}
	if s.invalid {
		return namespace.ServiceReport{}, namespace.ProgressDone, nil
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

func TestCoordinatorSeparatesStaleAndFreshGenerationsInReusedSlot(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 2})
	stale := &testPollable{ready: namespace.ReadyReadable}
	staleHandle := addAndRegister(t, table, coordinator, resource.KindUDPSocket, stale)
	if err := table.CloseHandle(staleHandle, resource.KindUDPSocket); err != nil {
		t.Fatal(err)
	}
	fresh := &testPollable{ready: namespace.ReadyWritable}
	freshHandle := addAndRegister(t, table, coordinator, resource.KindUDPSocket, fresh)
	if freshHandle == staleHandle || uint16(freshHandle) != uint16(staleHandle) {
		t.Fatalf("generation-safe slot reuse = stale %v, fresh %v", staleHandle, freshHandle)
	}

	events := make([]Event, 1)
	budget := Budget{Scans: 2, Events: 1}
	report, progress, err := coordinator.TryPoll(events, budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidFor(budget) {
		t.Fatalf("generation poll = %+v, %v, %v", report, progress, err)
	}
	if report != (Report{Scanned: 2, Events: 1, StaleRegistrations: 1}) || events[0] != (Event{Handle: freshHandle, Readiness: namespace.ReadyWritable}) {
		t.Fatalf("generation poll result = %+v, %+v", report, events)
	}
	if coordinator.Unregister(staleHandle) {
		t.Fatal("stale generation unregistered fresh registration")
	}
	if snapshot := coordinator.Snapshot(); snapshot.Registrations != 1 {
		t.Fatalf("fresh registration removed with stale generation: %+v", snapshot)
	}
}

func TestServiceAttemptLimitDoesNotSuppressIndependentReadyScan(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 2})
	service := &testService{}
	ready := &testPollable{ready: namespace.ReadyWritable}
	addAndRegister(t, table, coordinator, resource.KindNamespace, service)
	readyHandle := addAndRegister(t, table, coordinator, resource.KindTCPStream, ready)
	budget := Budget{
		Scans:           2,
		Events:          1,
		ServiceAttempts: 1,
		Service:         namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1},
	}
	events := make([]Event, 1)
	report, progress, err := coordinator.TryPoll(events, budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidFor(budget) {
		t.Fatalf("poll = %+v, %v, %v", report, progress, err)
	}
	if report != (Report{Scanned: 2, Events: 1, ServiceAttempts: 1}) || events[0] != (Event{Handle: readyHandle, Readiness: namespace.ReadyWritable}) || service.attempts.Load() != 1 {
		t.Fatalf("independent bounds = report %+v events %+v attempts %d", report, events, service.attempts.Load())
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
	if report.Scanned != 2 || report.ServiceAttempts != 1 || report.ServiceCompleted != 1 || report.Events != 1 || events[0].Handle != firstHandle {
		t.Fatalf("first service bound = %+v, %+v", report, events)
	}
	if first.attempts.Load() != 1 || second.attempts.Load() != 0 {
		t.Fatalf("first attempts = %d/%d", first.attempts.Load(), second.attempts.Load())
	}

	clear(events)
	report, progress, err = coordinator.TryPoll(events, budget)
	if err != nil || progress != namespace.ProgressDone || report.Scanned != 2 || report.ServiceAttempts != 1 || report.ServiceCompleted != 1 || report.Events != 2 || events[0].Handle != firstHandle || events[1].Handle != secondHandle {
		t.Fatalf("second service poll = %+v, %v, %v, %+v", report, progress, err, events)
	}
	if first.attempts.Load() != 1 || second.attempts.Load() != 1 {
		t.Fatalf("rotated attempts = %d/%d", first.attempts.Load(), second.attempts.Load())
	}
}

func TestUnregisterPreservesScanCursorAcrossTailReplacement(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 3})
	first := &testPollable{}
	second := &testPollable{ready: namespace.ReadyReadable}
	third := &testPollable{}
	addAndRegister(t, table, coordinator, resource.KindPollable, first)
	secondHandle := addAndRegister(t, table, coordinator, resource.KindPollable, second)
	thirdHandle := addAndRegister(t, table, coordinator, resource.KindPollable, third)
	budget := Budget{Scans: 1, Events: 1}
	events := make([]Event, 1)
	if report, progress, err := coordinator.TryPoll(events, budget); err != nil || progress != namespace.ProgressWouldBlock || report != (Report{Scanned: 1}) {
		t.Fatalf("initial scan = %+v, %v, %v", report, progress, err)
	}
	if !coordinator.Unregister(thirdHandle) {
		t.Fatal("tail unregister failed")
	}
	replacement := &testPollable{}
	addAndRegister(t, table, coordinator, resource.KindPollable, replacement)
	if report, progress, err := coordinator.TryPoll(events, budget); err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 1, Events: 1}) || events[0] != (Event{Handle: secondHandle, Readiness: namespace.ReadyReadable}) {
		t.Fatalf("scan after tail replacement = %+v, %v, %v, events=%+v", report, progress, err, events)
	}
}

func TestUnregisterPreservesServiceCursorAcrossSwapDelete(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 3})
	first := &testService{work: true}
	second := &testService{work: true}
	third := &testService{work: true}
	firstHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, first)
	secondHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, second)
	thirdHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, third)

	coordinator.mu.Lock()
	coordinator.cursor = 0
	coordinator.serviceCursor = 2
	coordinator.mu.Unlock()
	if !coordinator.Unregister(firstHandle) {
		t.Fatal("head unregister failed")
	}

	budget := Budget{
		Scans: 1, Events: 1, ServiceAttempts: 1,
		Service: namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1},
	}
	events := make([]Event, 1)
	report, progress, err := coordinator.TryPoll(events, budget)
	if err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 1, Events: 1, ServiceAttempts: 1, ServiceCompleted: 1}) {
		t.Fatalf("poll after swap-delete = %+v, %v, %v, events=%+v", report, progress, err, events)
	}
	if events[0] != (Event{Handle: thirdHandle, Readiness: namespace.ReadyReadable}) || first.attempts.Load() != 0 || second.attempts.Load() != 0 || third.attempts.Load() != 1 {
		t.Fatalf("service cursor moved to wrong registration: events=%+v attempts=%d/%d/%d", events, first.attempts.Load(), second.attempts.Load(), third.attempts.Load())
	}
	if snapshot := coordinator.Snapshot(); snapshot.Registrations != 2 || snapshot.Cursor != 1 {
		t.Fatalf("post-unregister snapshot = %+v", snapshot)
	}
	if !coordinator.Unregister(secondHandle) {
		t.Fatal("remaining registration unregister failed")
	}
}

func TestStaleSwapDeletePreservesScanAndServiceFairness(t *testing.T) {
	for staleIndex := 0; staleIndex < 3; staleIndex++ {
		t.Run([]string{"head", "middle", "tail"}[staleIndex], func(t *testing.T) {
			table := newTable(t)
			coordinator := newCoordinator(t, table, Config{MaxRegistrations: 3})
			services := []*testService{{work: true}, {work: true}, {work: true}}
			handles := make([]resource.Handle, len(services))
			for i, service := range services {
				handles[i] = addAndRegister(t, table, coordinator, resource.KindNamespace, service)
			}

			coordinator.mu.Lock()
			coordinator.cursor = staleIndex
			coordinator.serviceCursor = staleIndex
			coordinator.mu.Unlock()
			if err := table.CloseHandle(handles[staleIndex], resource.KindNamespace); err != nil {
				t.Fatal(err)
			}

			budget := Budget{
				Scans: 3, Events: 2, ServiceAttempts: 1,
				Service: namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1},
			}
			events := make([]Event, 2)
			report, progress, err := coordinator.TryPoll(events, budget)
			if err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 3, Events: 1, ServiceAttempts: 1, ServiceCompleted: 1, StaleRegistrations: 1}) {
				t.Fatalf("stale poll = %+v, %v, %v, events=%+v", report, progress, err, events)
			}
			firstServiced := 2
			if staleIndex == 2 {
				firstServiced = 0
			}
			if events[0] != (Event{Handle: handles[firstServiced], Readiness: namespace.ReadyReadable}) {
				t.Fatalf("first serviced event = %+v, want handle %v", events[0], handles[firstServiced])
			}
			for i, service := range services {
				want := int32(0)
				if i == firstServiced {
					want = 1
				}
				if got := service.attempts.Load(); got != want {
					t.Fatalf("service %d attempts = %d, want %d", i, got, want)
				}
			}

			clear(events)
			report, progress, err = coordinator.TryPoll(events, budget)
			if err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 2, Events: 2, ServiceAttempts: 1, ServiceCompleted: 1}) {
				t.Fatalf("rotated poll = %+v, %v, %v, events=%+v", report, progress, err, events)
			}
			secondServiced := 1
			if staleIndex == 1 {
				secondServiced = 0
			}
			if services[secondServiced].attempts.Load() != 1 {
				t.Fatalf("second serviced attempts = %d", services[secondServiced].attempts.Load())
			}
			if snapshot := coordinator.Snapshot(); snapshot.Registrations != 2 {
				t.Fatalf("stale registration retained: %+v", snapshot)
			}
		})
	}
}

func TestEventBudgetEarlyStopRotatesScanCursor(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 3})
	want := make([]resource.Handle, 3)
	for i := range want {
		want[i] = addAndRegister(t, table, coordinator, resource.KindPollable, &testPollable{ready: namespace.ReadyReadable})
	}
	budget := Budget{Scans: 3, Events: 1}
	events := make([]Event, 1)
	for i, handle := range append(want, want[0]) {
		report, progress, err := coordinator.TryPoll(events, budget)
		if err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 1, Events: 1}) || events[0] != (Event{Handle: handle, Readiness: namespace.ReadyReadable}) {
			t.Fatalf("poll %d = %+v, %v, %v, events=%+v", i, report, progress, err, events)
		}
	}
}

func TestServiceErrorCursorRecoversAfterOffenderRemoval(t *testing.T) {
	table := newTable(t)
	coordinator := newCoordinator(t, table, Config{MaxRegistrations: 2})
	failure := errors.New("service failed")
	bad := &testService{failure: failure}
	good := &testService{work: true}
	badHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, bad)
	goodHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, good)
	budget := Budget{
		Scans: 2, Events: 1, ServiceAttempts: 1,
		Service: namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1},
	}
	events := make([]Event, 1)
	if report, progress, err := coordinator.TryPoll(events, budget); !errors.Is(err, failure) || progress != namespace.ProgressWouldBlock || report != (Report{Scanned: 1, ServiceAttempts: 1}) || bad.attempts.Load() != 1 || good.attempts.Load() != 0 {
		t.Fatalf("failed service = %+v, %v, %v, attempts=%d/%d", report, progress, err, bad.attempts.Load(), good.attempts.Load())
	}
	if !coordinator.Unregister(badHandle) {
		t.Fatal("failed service unregister")
	}
	if report, progress, err := coordinator.TryPoll(events, budget); err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 1, Events: 1, ServiceAttempts: 1, ServiceCompleted: 1}) || events[0] != (Event{Handle: goodHandle, Readiness: namespace.ReadyReadable}) || good.attempts.Load() != 1 {
		t.Fatalf("service after removal = %+v, %v, %v, events=%+v attempts=%d", report, progress, err, events, good.attempts.Load())
	}
}

func TestServiceFailuresPreserveCursorsForDeterministicRetry(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*testService)
		checkErr  func(error) bool
	}{
		{
			name: "backend error",
			configure: func(service *testService) {
				service.failure = namespace.Fail(namespace.FailureTemporary, errors.New("temporary"))
			},
			checkErr: func(err error) bool {
				failure, ok := namespace.FailureOf(err)
				return ok && failure == namespace.FailureTemporary
			},
		},
		{
			name: "invalid backend result",
			configure: func(service *testService) {
				service.invalid = true
			},
			checkErr: func(err error) bool {
				failure, ok := namespace.FailureOf(err)
				return ok && failure == namespace.FailureIO && errors.Is(err, ErrInvalidServiceResult)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			table := newTable(t)
			coordinator := newCoordinator(t, table, Config{MaxRegistrations: 2})
			first := new(testService)
			test.configure(first)
			second := &testService{work: true}
			firstHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, first)
			secondHandle := addAndRegister(t, table, coordinator, resource.KindNamespace, second)
			budget := Budget{
				Scans: 2, Events: 2, ServiceAttempts: 1,
				Service: namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1},
			}
			events := make([]Event, 2)

			for attempt := int32(1); attempt <= 2; attempt++ {
				report, progress, err := coordinator.TryPoll(events, budget)
				if !test.checkErr(err) || progress != namespace.ProgressWouldBlock || report != (Report{Scanned: 1, ServiceAttempts: 1}) {
					t.Fatalf("failed poll %d = %+v, %v, %v", attempt, report, progress, err)
				}
				if first.attempts.Load() != attempt || second.attempts.Load() != 0 {
					t.Fatalf("failed attempts %d = %d/%d", attempt, first.attempts.Load(), second.attempts.Load())
				}
				coordinator.mu.Lock()
				cursor, serviceCursor := coordinator.cursor, coordinator.serviceCursor
				coordinator.mu.Unlock()
				if cursor != 0 || serviceCursor != 0 {
					t.Fatalf("failed cursors %d = %d/%d", attempt, cursor, serviceCursor)
				}
			}

			first.failure = nil
			first.invalid = false
			first.work = true
			report, progress, err := coordinator.TryPoll(events, budget)
			if err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 2, Events: 1, ServiceAttempts: 1, ServiceCompleted: 1}) || events[0] != (Event{Handle: firstHandle, Readiness: namespace.ReadyReadable}) {
				t.Fatalf("recovered first poll = %+v, %v, %v, events=%+v", report, progress, err, events)
			}
			clear(events)
			report, progress, err = coordinator.TryPoll(events, budget)
			if err != nil || progress != namespace.ProgressDone || report != (Report{Scanned: 2, Events: 2, ServiceAttempts: 1, ServiceCompleted: 1}) || events[0] != (Event{Handle: firstHandle, Readiness: namespace.ReadyReadable}) || events[1] != (Event{Handle: secondHandle, Readiness: namespace.ReadyReadable}) {
				t.Fatalf("recovered rotation poll = %+v, %v, %v, events=%+v", report, progress, err, events)
			}
			if first.attempts.Load() != 3 || second.attempts.Load() != 1 {
				t.Fatalf("recovered attempts = %d/%d", first.attempts.Load(), second.attempts.Load())
			}
		})
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
