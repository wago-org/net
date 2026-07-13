package icmpv4

import (
	"errors"
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
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

func (n *fakeNamespace) TryEcho(icmpns.Request) (nscore.Resource, nscore.Progress, error) {
	return n.next, nscore.ProgressInProgress, nil
}

type fakeEcho struct {
	payload  []byte
	canceled bool
	closed   bool
}

func (e *fakeEcho) Close() error { e.closed = true; return nil }
func (e *fakeEcho) Cancel() error {
	e.canceled = true
	return nil
}
func (e *fakeEcho) Readiness() nscore.Readiness {
	if e.closed {
		return nscore.ReadyClosed
	}
	return nscore.ReadyICMPv4Reply
}
func (e *fakeEcho) TryResult(dst []byte) (icmpns.Result, icmpns.Next, error) {
	copied := copy(dst, e.payload)
	return icmpns.Result{Source: netip.MustParseAddr("192.0.2.1"), Identifier: 1, Sequence: 2, Copied: copied, PayloadBytes: len(e.payload)}, icmpns.NextReady, nil
}

func TestInstanceICMPv4ExactKindLifecycle(t *testing.T) {
	exchange := &fakeEcho{payload: []byte("reply")}
	adapter := &fakeNamespace{next: exchange}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: icmpns.ServiceKey, Value: adapter})
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
	handle, progress, err := Echo(state, state.NamespaceHandle(), icmpns.Request{Destination: netip.MustParseAddr("192.0.2.1")})
	if err != nil || progress != nscore.ProgressInProgress || handle == 0 {
		t.Fatalf("Echo = %v, %v, %v", handle, progress, err)
	}
	if _, err := state.Resources().Lookup(handle, resource.KindDNSQuery); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind lookup = %v", err)
	}
	var dst [3]byte
	result, next, err := Result(state, handle, dst[:])
	if err != nil || next != icmpns.NextReady || !result.Valid(len(dst)) || string(dst[:]) != "rep" {
		t.Fatalf("Result = %+v, %v, %v, payload=%q", result, next, err, dst[:])
	}
	if err := Cancel(state, handle); err != nil || !exchange.canceled {
		t.Fatalf("Cancel = %v, canceled=%v", err, exchange.canceled)
	}
	if err := state.CloseHandle(handle, resource.KindICMPv4Echo); err != nil || !exchange.closed {
		t.Fatalf("CloseHandle = %v, closed=%v", err, exchange.closed)
	}
	if _, _, err := Result(state, handle, dst[:]); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale result = %v", err)
	}
}
