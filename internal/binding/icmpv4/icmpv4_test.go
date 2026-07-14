package icmpv4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	icmpabi "github.com/wago-org/net/internal/abi/icmpv4"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type testHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h testHost) Memory() []byte           { return h.memory }
func (h testHost) Instance() *wago.Instance { return h.instance }

type fakeBase struct{}

func (*fakeBase) Close() error                { return nil }
func (*fakeBase) Readiness() nscore.Readiness { return 0 }
func (*fakeBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeNamespace struct {
	next        nscore.Resource
	progress    nscore.Progress
	failure     error
	destination netip.Addr
	payload     []byte
	calls       int
}

func (n *fakeNamespace) TryEcho(request icmpns.Request) (nscore.Resource, nscore.Progress, error) {
	n.calls++
	n.destination = request.Destination
	n.payload = append(n.payload[:0], request.Payload...)
	return n.next, n.progress, n.failure
}

type fakeEcho struct {
	payload     []byte
	result      icmpns.Result
	next        icmpns.Next
	failure     error
	resultCalls int
	cancelCalls int
	closeCalls  int
}

func (e *fakeEcho) Close() error {
	e.closeCalls++
	return nil
}
func (e *fakeEcho) Cancel() error {
	e.cancelCalls++
	return nil
}
func (*fakeEcho) Readiness() nscore.Readiness { return nscore.ReadyICMPv4Reply }
func (e *fakeEcho) TryResult(dst []byte) (icmpns.Result, icmpns.Next, error) {
	e.resultCalls++
	result := e.result
	result.Copied = copy(dst, e.payload)
	return result, e.next, e.failure
}

func TestBindingsPrevalidateEchoAndPreserveResultOutputs(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 1024)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 900); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[900:908])
	copy(host.memory[128:132], "ping")
	if !icmpabi.EncodeEchoRequestV1(host.memory, 0, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.9")}, 128, 4) {
		t.Fatal("encode request")
	}

	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "echo"), host, namespaceHandle, 0, 16); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap echo = %v, calls=%d", status, backend.calls)
	}
	host.memory[40] = 1
	handleBefore := append([]byte(nil), host.memory[80:88]...)
	if status := callBinding(t, bindingByName(t, bindings, "echo"), host, namespaceHandle, 0, 80); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory[80:88], handleBefore) {
		t.Fatalf("reserved echo = %v, calls=%d", status, backend.calls)
	}
	host.memory[40] = 0

	backend.failure = nscore.Fail(nscore.FailureAccessDenied, errors.New("denied"))
	if status := callBinding(t, bindingByName(t, bindings, "echo"), host, namespaceHandle, 0, 80); status != guest.StatusAccessDenied || backend.calls != 1 || !bytes.Equal(host.memory[80:88], handleBefore) {
		t.Fatalf("failed echo = %v, calls=%d", status, backend.calls)
	}

	var typedNil *fakeEcho
	backend.next, backend.progress, backend.failure = typedNil, nscore.ProgressDone, nil
	if status := callBinding(t, bindingByName(t, bindings, "echo"), host, namespaceHandle, 0, 80); status != guest.StatusIO || backend.calls != 2 || !bytes.Equal(host.memory[80:88], handleBefore) {
		t.Fatalf("typed-nil echo = %v, calls=%d", status, backend.calls)
	}

	echo := &fakeEcho{
		payload: []byte("reply"), next: icmpns.NextWouldBlock,
		result: icmpns.Result{Source: netip.MustParseAddr("192.0.2.1"), Identifier: 7, Sequence: 11, PayloadBytes: 5},
	}
	backend.next, backend.progress = echo, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "echo"), host, namespaceHandle, 0, 80); status != guest.StatusOK || backend.calls != 3 || backend.destination != netip.MustParseAddr("192.0.2.9") || string(backend.payload) != "ping" {
		t.Fatalf("echo = %v, calls=%d destination=%v payload=%q", status, backend.calls, backend.destination, backend.payload)
	}
	echoHandle := binary.LittleEndian.Uint64(host.memory[80:88])

	pending := &fakeEcho{}
	backend.next, backend.progress = pending, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "echo"), host, namespaceHandle, 0, 88); status != guest.StatusInProgress {
		t.Fatalf("in-progress echo = %v", status)
	}
	pendingHandle := binary.LittleEndian.Uint64(host.memory[88:96])

	payloadBefore := append([]byte(nil), host.memory[256:272]...)
	resultBefore := append([]byte(nil), host.memory[320:320+icmpabi.EchoResultV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, echoHandle, 320, 16, 320); status != guest.StatusInvalidArgument || echo.resultCalls != 0 {
		t.Fatalf("overlap result = %v, calls=%d", status, echo.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, echoHandle, 256, 16, 320); status != guest.StatusAgain || !bytes.Equal(host.memory[256:272], payloadBefore) || !bytes.Equal(host.memory[320:320+icmpabi.EchoResultV1Size], resultBefore) {
		t.Fatalf("would-block result = %v", status)
	}
	echo.failure = nscore.Fail(nscore.FailureCanceled, errors.New("canceled"))
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, echoHandle, 256, 16, 320); status != guest.StatusCanceled || !bytes.Equal(host.memory[256:272], payloadBefore) || !bytes.Equal(host.memory[320:320+icmpabi.EchoResultV1Size], resultBefore) {
		t.Fatalf("failed result = %v", status)
	}
	echo.failure = nil
	echo.next = 99
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, echoHandle, 256, 16, 320); status != guest.StatusIO || !bytes.Equal(host.memory[256:272], payloadBefore) || !bytes.Equal(host.memory[320:320+icmpabi.EchoResultV1Size], resultBefore) {
		t.Fatalf("malformed result = %v", status)
	}
	echo.next = icmpns.NextReady
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, echoHandle, 256, 16, 320); status != guest.StatusOK || string(host.memory[256:261]) != "reply" {
		t.Fatalf("ready result = %v, payload=%q", status, host.memory[256:261])
	}
	if identifier := binary.LittleEndian.Uint16(host.memory[352:354]); identifier != 7 {
		t.Fatalf("identifier = %d", identifier)
	}
	if sequence := binary.LittleEndian.Uint16(host.memory[354:356]); sequence != 11 {
		t.Fatalf("sequence = %d", sequence)
	}
	if copied := binary.LittleEndian.Uint32(host.memory[356:360]); copied != 5 {
		t.Fatalf("copied = %d", copied)
	}
	if payloadBytes := binary.LittleEndian.Uint32(host.memory[360:364]); payloadBytes != 5 {
		t.Fatalf("payload bytes = %d", payloadBytes)
	}

	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, echoHandle); status != guest.StatusOK || echo.cancelCalls != 1 {
		t.Fatalf("cancel = %v, calls=%d", status, echo.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, echoHandle); status != guest.StatusOK || echo.closeCalls != 1 {
		t.Fatalf("close = %v, calls=%d", status, echo.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, echoHandle, 256, 16, 320); status != guest.StatusBadHandle {
		t.Fatalf("stale result = %v", status)
	}

	fresh := &fakeEcho{next: icmpns.NextWouldBlock}
	backend.next, backend.progress = fresh, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "echo"), host, namespaceHandle, 0, 96); status != guest.StatusOK {
		t.Fatalf("fresh echo = %v", status)
	}
	freshHandle := binary.LittleEndian.Uint64(host.memory[96:104])
	if freshHandle == echoHandle || uint16(freshHandle) != uint16(echoHandle) {
		t.Fatalf("generation-safe slot reuse = old %v, fresh %v", echoHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, echoHandle); status != guest.StatusBadHandle || fresh.cancelCalls != 0 {
		t.Fatalf("stale cancel = %v, fresh calls=%d", status, fresh.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, freshHandle, 256, 16, 320); status != guest.StatusAgain || fresh.resultCalls != 1 {
		t.Fatalf("fresh result = %v, calls=%d", status, fresh.resultCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, freshHandle); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("close fresh = %v, calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, pendingHandle); status != guest.StatusOK || pending.closeCalls != 1 {
		t.Fatalf("close pending = %v, calls=%d", status, pending.closeCalls)
	}
}

func TestResultRejectsRangesBeforeHandleLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 64)}
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, Bindings(plugin.NewHost(manager)), "result"), host, 1, 0, 16, 32); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("out-of-bounds result = %v", status)
	}
}

func attachManager(t testing.TB, backend icmpns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
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
	return manager, instance
}

func bindingByName(t testing.TB, bindings []plugin.Binding, name string) wago.HostFunc {
	t.Helper()
	for _, binding := range bindings {
		if binding.Name == name {
			return binding.Func
		}
	}
	t.Fatalf("binding %q missing", name)
	return nil
}

func callBinding(t testing.TB, function wago.HostFunc, host testHost, params ...uint64) guest.Status {
	t.Helper()
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}

func BenchmarkResultBindingReady(b *testing.B) {
	echo := &fakeEcho{
		payload: bytes.Repeat([]byte{0x5a}, 256), next: icmpns.NextReady,
		result: icmpns.Result{Source: netip.MustParseAddr("192.0.2.1"), Identifier: 1, Sequence: 2, PayloadBytes: 256},
	}
	manager, instance := attachManager(b, &fakeNamespace{next: echo, progress: nscore.ProgressDone})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindICMPv4Echo, echo)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, 1024)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "result")
	params := []uint64{uint64(handle), 0, 256, 512}
	var results [1]uint64
	function(host, params, results[:])
	if status := guest.Status(int32(results[0])); status != guest.StatusOK {
		b.Fatalf("warmup status = %v", status)
	}
	b.ReportAllocs()
	b.SetBytes(256)
	b.ResetTimer()
	for b.Loop() {
		function(host, params, results[:])
	}
}
