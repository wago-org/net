package icmpv6

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
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
	operations      icmpns.Operations
	echo            nscore.Resource
	echoProgress    nscore.Progress
	resolution      nscore.Resource
	resolveProgress nscore.Progress
	lookup          icmpns.Neighbor
	found           bool
	lookupFailure   error
	seeded          icmpns.Neighbor
	removed         icmpns.NeighborRequest
}

func (n *fakeNamespace) Operations() icmpns.Operations { return n.operations }
func (n *fakeNamespace) TryEcho(icmpns.EchoRequest) (nscore.Resource, nscore.Progress, error) {
	return n.echo, n.echoProgress, nil
}
func (n *fakeNamespace) TryResolve(icmpns.NeighborRequest) (nscore.Resource, nscore.Progress, error) {
	return n.resolution, n.resolveProgress, nil
}
func (n *fakeNamespace) LookupNeighbor(icmpns.NeighborRequest) (icmpns.Neighbor, bool, error) {
	return n.lookup, n.found, n.lookupFailure
}
func (n *fakeNamespace) SeedNeighbor(neighbor icmpns.Neighbor) error {
	n.seeded = neighbor
	return nil
}
func (n *fakeNamespace) RemoveNeighbor(request icmpns.NeighborRequest) error {
	n.removed = request
	return nil
}

type fakeEcho struct {
	payload  []byte
	result   icmpns.EchoResult
	next     icmpns.Next
	failure  error
	canceled bool
	closed   bool
}

func (e *fakeEcho) Close() error { e.closed = true; return nil }
func (e *fakeEcho) Cancel() error {
	e.canceled = true
	return nil
}
func (e *fakeEcho) Readiness() nscore.Readiness { return nscore.ReadyICMPv6Reply }
func (e *fakeEcho) TryResult(dst []byte) (icmpns.EchoResult, icmpns.Next, error) {
	result := e.result
	result.Copied = copy(dst, e.payload)
	if result.PayloadBytes == 0 {
		result.PayloadBytes = len(e.payload)
	}
	return result, e.next, e.failure
}

type fakeResolution struct {
	neighbor icmpns.Neighbor
	next     icmpns.Next
	failure  error
	canceled bool
	closed   bool
}

func (r *fakeResolution) Close() error { r.closed = true; return nil }
func (r *fakeResolution) Cancel() error {
	r.canceled = true
	return nil
}
func (r *fakeResolution) Readiness() nscore.Readiness { return nscore.ReadyICMPv6Neighbor }
func (r *fakeResolution) TryResult() (icmpns.Neighbor, icmpns.Next, error) {
	return r.neighbor, r.next, r.failure
}

func TestInstanceICMPv6ExactKindLifecycle(t *testing.T) {
	destination := netip.MustParseAddr("2001:db8::2")
	neighbor := icmpns.Neighbor{Address: destination, MAC: [6]byte{0x02, 0, 0, 0, 0, 2}}
	echo := &fakeEcho{
		payload: []byte("reply"), next: icmpns.NextReady,
		result: icmpns.EchoResult{Source: destination, Identifier: 3, Sequence: 4},
	}
	resolution := &fakeResolution{neighbor: neighbor, next: icmpns.NextReady}
	backend := &fakeNamespace{
		operations: icmpns.SupportedOperations,
		echo:       echo, echoProgress: nscore.ProgressInProgress,
		resolution: resolution, resolveProgress: nscore.ProgressDone,
		lookup: neighbor, found: true,
	}
	state, manager, instance := attachState(t, backend, 8)
	defer manager.Detach(instance)

	operations, err := Operations(state, state.NamespaceHandle())
	if err != nil || operations != icmpns.SupportedOperations {
		t.Fatalf("Operations = %v, %v", operations, err)
	}
	echoHandle, progress, err := Echo(state, state.NamespaceHandle(), icmpns.EchoRequest{Destination: destination, Payload: []byte("reply")})
	if err != nil || progress != nscore.ProgressInProgress || echoHandle == 0 {
		t.Fatalf("Echo = %v, %v, %v", echoHandle, progress, err)
	}
	neighborHandle, progress, err := Resolve(state, state.NamespaceHandle(), icmpns.NeighborRequest{Address: destination})
	if err != nil || progress != nscore.ProgressDone || neighborHandle == 0 {
		t.Fatalf("Resolve = %v, %v, %v", neighborHandle, progress, err)
	}
	if _, err := state.Resources().Lookup(echoHandle, resource.KindICMPv6Neighbor); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind echo lookup = %v", err)
	}
	if _, err := state.Resources().Lookup(neighborHandle, resource.KindICMPv6Echo); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind neighbor lookup = %v", err)
	}

	dst := bytes.Repeat([]byte{0xa5}, 3)
	result, next, err := EchoResult(state, echoHandle, dst)
	if err != nil || next != icmpns.NextReady || !result.Valid(len(dst)) || string(dst) != "rep" {
		t.Fatalf("EchoResult = %+v, %v, %v, payload=%q", result, next, err, dst)
	}
	gotNeighbor, next, err := NeighborResult(state, neighborHandle)
	if err != nil || next != icmpns.NextReady || gotNeighbor != neighbor {
		t.Fatalf("NeighborResult = %+v, %v, %v", gotNeighbor, next, err)
	}
	lookedUp, found, err := Lookup(state, state.NamespaceHandle(), icmpns.NeighborRequest{Address: destination})
	if err != nil || !found || lookedUp != neighbor {
		t.Fatalf("Lookup = %+v, %v, %v", lookedUp, found, err)
	}
	if err := Seed(state, state.NamespaceHandle(), neighbor); err != nil || backend.seeded != neighbor {
		t.Fatalf("Seed = %v, neighbor=%+v", err, backend.seeded)
	}
	request := icmpns.NeighborRequest{Address: destination}
	if err := Remove(state, state.NamespaceHandle(), request); err != nil || backend.removed != request {
		t.Fatalf("Remove = %v, request=%+v", err, backend.removed)
	}
	if err := CancelEcho(state, echoHandle); err != nil || !echo.canceled {
		t.Fatalf("CancelEcho = %v, canceled=%v", err, echo.canceled)
	}
	if err := CancelNeighbor(state, neighborHandle); err != nil || !resolution.canceled {
		t.Fatalf("CancelNeighbor = %v, canceled=%v", err, resolution.canceled)
	}
	if err := state.CloseHandle(echoHandle, resource.KindICMPv6Echo); err != nil || !echo.closed {
		t.Fatalf("close echo = %v, closed=%v", err, echo.closed)
	}
	if err := state.CloseHandle(neighborHandle, resource.KindICMPv6Neighbor); err != nil || !resolution.closed {
		t.Fatalf("close neighbor = %v, closed=%v", err, resolution.closed)
	}
	if _, _, err := EchoResult(state, echoHandle, dst); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale echo = %v", err)
	}
	if _, _, err := NeighborResult(state, neighborHandle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale neighbor = %v", err)
	}
}

func TestEchoResultRejectsInvalidBackendOutputWithoutMutation(t *testing.T) {
	destination := netip.MustParseAddr("2001:db8::3")
	echo := &fakeEcho{
		payload: []byte("mutated"), next: icmpns.NextReady, failure: errors.New("backend failed"),
		result: icmpns.EchoResult{Source: destination},
	}
	backend := &fakeNamespace{operations: icmpns.SupportedOperations, echo: echo, echoProgress: nscore.ProgressDone}
	state, manager, instance := attachState(t, backend, 4)
	defer manager.Detach(instance)
	handle, _, err := Echo(state, state.NamespaceHandle(), icmpns.EchoRequest{Destination: destination, Payload: []byte("request")})
	if err != nil {
		t.Fatal(err)
	}
	dst := bytes.Repeat([]byte{0xa5}, 16)
	before := append([]byte(nil), dst...)
	if result, next, err := EchoResult(state, handle, dst); err == nil || result != (icmpns.EchoResult{}) || next != 0 || !bytes.Equal(dst, before) {
		t.Fatalf("backend error = %+v, %v, %v, payload=%x", result, next, err, dst)
	}

	echo.failure = nil
	echo.next = 99
	if result, next, err := EchoResult(state, handle, dst); failureOf(err) != nscore.FailureIO || result != (icmpns.EchoResult{}) || next != 0 || !bytes.Equal(dst, before) {
		t.Fatalf("invalid next = %+v, %v, %v, payload=%x", result, next, err, dst)
	}
	echo.next = icmpns.NextWouldBlock
	if result, next, err := EchoResult(state, handle, dst); err != nil || result != (icmpns.EchoResult{}) || next != icmpns.NextWouldBlock || !bytes.Equal(dst, before) {
		t.Fatalf("would-block = %+v, %v, %v, payload=%x", result, next, err, dst)
	}
}

func TestNeighborResultsClearInvalidBackendOutputs(t *testing.T) {
	destination := netip.MustParseAddr("2001:db8::5")
	neighbor := icmpns.Neighbor{Address: destination, MAC: [6]byte{0x02, 0, 0, 0, 0, 5}}
	resolution := &fakeResolution{neighbor: neighbor, next: icmpns.NextReady, failure: errors.New("resolution failed")}
	backend := &fakeNamespace{
		operations: icmpns.SupportedOperations,
		resolution: resolution, resolveProgress: nscore.ProgressDone,
		lookup: neighbor, found: true, lookupFailure: errors.New("lookup failed"),
	}
	state, manager, instance := attachState(t, backend, 4)
	defer manager.Detach(instance)
	handle, _, err := Resolve(state, state.NamespaceHandle(), icmpns.NeighborRequest{Address: destination})
	if err != nil {
		t.Fatal(err)
	}
	if got, next, err := NeighborResult(state, handle); err == nil || got != (icmpns.Neighbor{}) || next != 0 {
		t.Fatalf("failed resolution output = %+v, %v, %v", got, next, err)
	}
	if got, found, err := Lookup(state, state.NamespaceHandle(), icmpns.NeighborRequest{Address: destination}); err == nil || got != (icmpns.Neighbor{}) || found {
		t.Fatalf("failed lookup output = %+v, %v, %v", got, found, err)
	}

	resolution.failure = nil
	resolution.neighbor = icmpns.Neighbor{}
	if got, next, err := NeighborResult(state, handle); failureOf(err) != nscore.FailureIO || got != (icmpns.Neighbor{}) || next != 0 {
		t.Fatalf("invalid resolution output = %+v, %v, %v", got, next, err)
	}
	backend.lookupFailure = nil
	backend.lookup = icmpns.Neighbor{}
	if got, found, err := Lookup(state, state.NamespaceHandle(), icmpns.NeighborRequest{Address: destination}); failureOf(err) != nscore.FailureIO || got != (icmpns.Neighbor{}) || found {
		t.Fatalf("invalid lookup output = %+v, %v, %v", got, found, err)
	}
	backend.lookup = neighbor
	backend.found = false
	if got, found, err := Lookup(state, state.NamespaceHandle(), icmpns.NeighborRequest{Address: destination}); err != nil || got != (icmpns.Neighbor{}) || found {
		t.Fatalf("not-found lookup output = %+v, %v, %v", got, found, err)
	}
}

func TestCreationValidationAndRegistrationRollbackCloseResources(t *testing.T) {
	destination := netip.MustParseAddr("2001:db8::4")
	echo := &fakeEcho{next: icmpns.NextReady, result: icmpns.EchoResult{Source: destination}}
	backend := &fakeNamespace{operations: icmpns.SupportedOperations, echo: echo, echoProgress: 99}
	state, manager, instance := attachState(t, backend, 4)
	if handle, progress, err := Echo(state, state.NamespaceHandle(), icmpns.EchoRequest{Destination: destination, Payload: []byte("x")}); handle != 0 || progress != 99 || failureOf(err) != nscore.FailureIO || !echo.closed {
		t.Fatalf("invalid creation = %v, %v, %v, closed=%v", handle, progress, err, echo.closed)
	}
	_ = manager.Detach(instance)

	echo = &fakeEcho{next: icmpns.NextReady, result: icmpns.EchoResult{Source: destination}}
	backend = &fakeNamespace{operations: icmpns.SupportedOperations, echo: echo, echoProgress: nscore.ProgressDone}
	state, manager, instance = attachState(t, backend, 1)
	defer manager.Detach(instance)
	if handle, progress, err := Echo(state, state.NamespaceHandle(), icmpns.EchoRequest{Destination: destination, Payload: []byte("x")}); handle != 0 || progress != nscore.ProgressDone || !errors.Is(err, readiness.ErrLimit) || !echo.closed {
		t.Fatalf("registration rollback = %v, %v, %v, closed=%v", handle, progress, err, echo.closed)
	}
	if state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("rollback retained state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}
}

func attachState(t testing.TB, backend icmpns.Namespace, maxRegistrations int) (*instancecore.State, *instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: maxRegistrations}
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: icmpns.ServiceKey, Value: backend})
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

func BenchmarkEchoResultReady(b *testing.B) {
	destination := netip.MustParseAddr("2001:db8::9")
	echo := &fakeEcho{
		payload: bytes.Repeat([]byte{0x5a}, 256), next: icmpns.NextReady,
		result: icmpns.EchoResult{Source: destination, Identifier: 1, Sequence: 2},
	}
	backend := &fakeNamespace{operations: icmpns.SupportedOperations, echo: echo, echoProgress: nscore.ProgressDone}
	state, manager, instance := attachState(b, backend, 4)
	defer manager.Detach(instance)
	handle, _, err := Echo(state, state.NamespaceHandle(), icmpns.EchoRequest{Destination: destination, Payload: []byte("request")})
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 256)
	if _, _, err := EchoResult(state, handle, dst); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(256)
	b.ResetTimer()
	for b.Loop() {
		_, _, _ = EchoResult(state, handle, dst)
	}
}
