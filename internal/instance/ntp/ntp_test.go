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

type fakeNamespace struct{ next nscore.Resource }

func (n *fakeNamespace) TrySync() (nscore.Resource, nscore.Progress, error) {
	return n.next, nscore.ProgressInProgress, nil
}

type fakeSync struct {
	sample   ntpns.Sample
	canceled bool
	closed   bool
}

func (s *fakeSync) Close() error { s.closed = true; return nil }
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
	return s.sample, ntpns.NextReady, nil
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
