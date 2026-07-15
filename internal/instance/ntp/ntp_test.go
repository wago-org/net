package ntp

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeBase struct{ closed bool }

func (b *fakeBase) Close() error { b.closed = true; return nil }
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
	next     nscore.Resource
	progress nscore.Progress
	failure  error
}

func (n *fakeNamespace) TrySync() (nscore.Resource, nscore.Progress, error) {
	progress := n.progress
	if progress == 0 {
		progress = nscore.ProgressInProgress
	}
	return n.next, progress, n.failure
}

type fakeSync struct {
	sample     ntpns.Sample
	next       ntpns.Next
	failure    error
	canceled   bool
	closed     bool
	closeCalls int
}

func (s *fakeSync) Close() error { s.closed = true; s.closeCalls++; return nil }
func (s *fakeSync) Cancel() error {
	s.canceled = true
	return nil
}
func (s *fakeSync) Readiness() nscore.Readiness {
	if s.closed {
		return nscore.ReadyClosed
	}
	return nscore.ReadyNTPResult
}
func (s *fakeSync) TryResult() (ntpns.Sample, ntpns.Next, error) {
	next := s.next
	if next == 0 {
		next = ntpns.NextReady
	}
	return s.sample, next, s.failure
}

func TestInstanceNTPCanonicalizesFailedAndUnusedOutputs(t *testing.T) {
	dirtySample := ntpns.Sample{
		Server: netip.MustParseAddr("192.0.2.123"), CorrectedTime: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		RoundTripDelay: time.Millisecond, Stratum: 2, Version: 4,
	}
	backendFailure := nscore.Fail(nscore.FailureTimedOut, errors.New("timeout"))
	failedSync := new(fakeSync)
	adapter := &fakeNamespace{next: failedSync, progress: nscore.ProgressDone, failure: backendFailure}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: ntpns.ServiceKey, Value: adapter})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	resourcesBefore := state.Resources().Len()
	readinessBefore := state.Readiness().Snapshot()

	if handle, progress, err := Sync(state, state.NamespaceHandle()); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed Sync = %v, %v, %v", handle, progress, err)
	}
	if failedSync.closeCalls != 1 || state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("failed Sync retained state: closes=%d resources=%d readiness=%+v", failedSync.closeCalls, state.Resources().Len(), state.Readiness().Snapshot())
	}
	var typedNil *fakeSync
	adapter.next = typedNil
	if handle, progress, err := Sync(state, state.NamespaceHandle()); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("typed-nil failed Sync = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("typed-nil failed Sync retained state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}

	synchronization := &fakeSync{sample: dirtySample, next: ntpns.NextWouldBlock}
	adapter.next, adapter.progress, adapter.failure = synchronization, nscore.ProgressInProgress, nil
	handle, _, err := Sync(state, state.NamespaceHandle())
	if err != nil {
		t.Fatal(err)
	}
	if sample, next, err := Result(state, handle); err != nil || next != ntpns.NextWouldBlock || sample != (ntpns.Sample{}) {
		t.Fatalf("would-block Result = %+v, %v, %v", sample, next, err)
	}
	synchronization.next, synchronization.failure = ntpns.NextReady, backendFailure
	if sample, next, err := Result(state, handle); sample != (ntpns.Sample{}) || next != 0 || failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("failed Result = %+v, %v, %v", sample, next, err)
	}
	synchronization.failure = nil
	synchronization.sample = dirtySample
	synchronization.sample.Server = netip.MustParseAddr("127.0.0.1")
	if sample, next, err := Result(state, handle); sample != (ntpns.Sample{}) || next != 0 || failureOf(err) != nscore.FailureIO {
		t.Fatalf("invalid server Result = %+v, %v, %v", sample, next, err)
	}
}

func TestInstanceNTPExactKindLifecycle(t *testing.T) {
	sample := ntpns.Sample{
		Server: netip.MustParseAddr("192.0.2.123"), CorrectedTime: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC),
		RoundTripDelay: time.Millisecond, Stratum: 2, Version: 4,
	}
	synchronization := &fakeSync{sample: sample}
	adapter := &fakeNamespace{next: synchronization}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: ntpns.ServiceKey, Value: adapter})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, progress, err := Sync(state, state.NamespaceHandle())
	if err != nil || progress != nscore.ProgressInProgress || handle == 0 {
		t.Fatalf("Sync = %v, %v, %v", handle, progress, err)
	}
	if _, err := state.Resources().Lookup(handle, resource.KindICMPv4Echo); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind lookup = %v", err)
	}
	got, next, err := Result(state, handle)
	if err != nil || next != ntpns.NextReady || got != sample {
		t.Fatalf("Result = %+v, %v, %v", got, next, err)
	}
	if err := Cancel(state, handle); err != nil || !synchronization.canceled {
		t.Fatalf("Cancel = %v, canceled=%v", err, synchronization.canceled)
	}
	if err := state.CloseHandle(handle, resource.KindNTPSync); err != nil || !synchronization.closed {
		t.Fatalf("CloseHandle = %v, closed=%v", err, synchronization.closed)
	}
	if _, _, err := Result(state, handle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale result = %v", err)
	}
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}
