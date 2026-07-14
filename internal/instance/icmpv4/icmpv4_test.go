package icmpv4

import (
	"bytes"
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

type fakeNamespace struct {
	next     nscore.Resource
	progress nscore.Progress
	failure  error
}

func (n *fakeNamespace) TryEcho(icmpns.Request) (nscore.Resource, nscore.Progress, error) {
	if n.progress != 0 || n.failure != nil {
		return n.next, n.progress, n.failure
	}
	return n.next, nscore.ProgressInProgress, nil
}

type fakeEcho struct {
	payload    []byte
	canceled   bool
	closed     bool
	closeCalls int
}

type mutatingEcho struct {
	payload []byte
	result  icmpns.Result
	next    icmpns.Next
	failure error
}

func (*mutatingEcho) Close() error                { return nil }
func (*mutatingEcho) Cancel() error               { return nil }
func (*mutatingEcho) Readiness() nscore.Readiness { return nscore.ReadyICMPv4Reply }
func (e *mutatingEcho) TryResult(dst []byte) (icmpns.Result, icmpns.Next, error) {
	result := e.result
	result.Copied = copy(dst, e.payload)
	return result, e.next, e.failure
}

func (e *fakeEcho) Close() error {
	e.closed = true
	e.closeCalls++
	return nil
}
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

func TestResultLeavesDestinationUnchangedOnBackendFailure(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	exchange := &mutatingEcho{
		payload: []byte("mutated"), next: icmpns.NextReady, failure: errors.New("backend failed"),
		result: icmpns.Result{Source: netip.MustParseAddr("192.0.2.1"), PayloadBytes: len("mutated")},
	}
	handle, err := state.Resources().Add(resource.KindICMPv4Echo, exchange)
	if err != nil {
		t.Fatal(err)
	}
	dst := bytes.Repeat([]byte{0xa5}, 16)
	before := append([]byte(nil), dst...)
	if result, next, err := Result(state, handle, dst); err == nil || result != (icmpns.Result{}) || next != 0 || !bytes.Equal(dst, before) {
		t.Fatalf("backend failure = %+v, %v, %v, payload=%x", result, next, err, dst)
	}
	exchange.failure = nil
	exchange.result.PayloadBytes = icmpns.MaxEchoPayloadBytes + 1
	if result, next, err := Result(state, handle, dst); failureOf(err) != nscore.FailureIO || result != (icmpns.Result{}) || next != 0 || !bytes.Equal(dst, before) {
		t.Fatalf("unrepresentable result = %+v, %v, %v, payload=%x", result, next, err, dst)
	}
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func TestEchoErrorsCloseResourcesAndCanonicalizeOutputs(t *testing.T) {
	adapter := &fakeNamespace{}
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
	resourcesBefore := state.Resources().Len()
	readinessBefore := state.Readiness().Snapshot()
	failure := nscore.Fail(nscore.FailureTemporary, errors.New("backend failed"))
	request := icmpns.Request{Destination: netip.MustParseAddr("192.0.2.1")}

	exchange := new(fakeEcho)
	adapter.next, adapter.progress, adapter.failure = exchange, nscore.ProgressDone, failure
	if handle, progress, err := Echo(state, state.NamespaceHandle(), request); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTemporary {
		t.Fatalf("failed echo = %v, %v, %v", handle, progress, err)
	}
	if exchange.closeCalls != 1 || state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("failed echo published state: closes=%d resources=%d readiness=%+v", exchange.closeCalls, state.Resources().Len(), state.Readiness().Snapshot())
	}

	var typedNil *fakeEcho
	adapter.next = typedNil
	if handle, progress, err := Echo(state, state.NamespaceHandle(), request); handle != 0 || progress != 0 || failureOf(err) != nscore.FailureTemporary {
		t.Fatalf("typed-nil failed echo = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("typed-nil failed echo published state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
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
	if err := state.CloseHandle(handle, resource.KindICMPv4Echo); err != nil || !exchange.closed || exchange.closeCalls != 1 {
		t.Fatalf("CloseHandle = %v, closed=%v calls=%d", err, exchange.closed, exchange.closeCalls)
	}
	if _, _, err := Result(state, handle, dst[:]); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale result = %v", err)
	}
}
