package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	dnsabi "github.com/wago-org/net/internal/abi/dns"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
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
	next     nscore.Resource
	progress nscore.Progress
	failure  error
	request  dnsns.Request
	calls    int
}

func (n *fakeNamespace) TryResolve(request dnsns.Request) (nscore.Resource, nscore.Progress, error) {
	n.calls++
	n.request = request
	return n.next, n.progress, n.failure
}

type fakeQuery struct {
	record      dnsns.Record
	next        dnsns.Next
	failure     error
	nextCalls   int
	cancelCalls int
	closeCalls  int
}

func (q *fakeQuery) Close() error {
	q.closeCalls++
	return nil
}
func (q *fakeQuery) Cancel() error {
	q.cancelCalls++
	return nil
}
func (*fakeQuery) Readiness() nscore.Readiness { return nscore.ReadyDNSResult }
func (q *fakeQuery) TryNext() (dnsns.Record, dnsns.Next, error) {
	q.nextCalls++
	return q.record, q.next, q.failure
}

func TestBindingsResolveNextAtomicStatusesAndLifecycle(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 1024)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 900); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[900:908]))
	request := dnsns.Request{Name: "api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	if !dnsabi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode query")
	}

	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 264); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap resolve = %v, calls=%d", status, backend.calls)
	}
	host.memory[264] = 1
	handleBefore := append([]byte(nil), host.memory[320:328]...)
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory[320:328], handleBefore) {
		t.Fatalf("reserved resolve = %v, calls=%d", status, backend.calls)
	}
	host.memory[264] = 0

	backend.failure = nscore.Fail(nscore.FailureNameNotFound, errors.New("missing"))
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusNameNotFound || backend.calls != 1 || !bytes.Equal(host.memory[320:328], handleBefore) {
		t.Fatalf("failed resolve = %v, calls=%d", status, backend.calls)
	}

	query := &fakeQuery{next: dnsns.NextWouldBlock}
	var typedNil *fakeQuery
	backend.next, backend.progress, backend.failure = typedNil, nscore.ProgressDone, nil
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusIO || backend.calls != 2 || !bytes.Equal(host.memory[320:328], handleBefore) {
		t.Fatalf("typed-nil resolve = %v, calls=%d", status, backend.calls)
	}
	backend.next = query
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusOK || backend.calls != 3 || backend.request != request {
		t.Fatalf("resolve = %v, calls=%d request=%+v", status, backend.calls, backend.request)
	}
	queryHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[320:328]))

	pending := new(fakeQuery)
	backend.next, backend.progress = pending, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 328); status != guest.StatusInProgress {
		t.Fatalf("in-progress resolve = %v", status)
	}
	pendingHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[328:336]))

	recordBefore := append([]byte(nil), host.memory[400:400+dnsabi.DNSRecordV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusAgain || !bytes.Equal(host.memory[400:400+dnsabi.DNSRecordV1Size], recordBefore) {
		t.Fatalf("would-block next = %v", status)
	}
	query.next = dnsns.NextEOF
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusEOF || !bytes.Equal(host.memory[400:400+dnsabi.DNSRecordV1Size], recordBefore) {
		t.Fatalf("EOF next = %v", status)
	}
	query.failure = nscore.Fail(nscore.FailureTemporary, errors.New("temporary"))
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusTemporaryFailure || !bytes.Equal(host.memory[400:400+dnsabi.DNSRecordV1Size], recordBefore) {
		t.Fatalf("failed next = %v", status)
	}
	query.failure = nil
	query.next = dnsns.NextReady
	query.record = dnsns.Record{Name: "api.example.com", Type: dnsns.RecordCNAME, TTLSeconds: 90, CanonicalName: "edge.example.com"}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusOK {
		t.Fatalf("CNAME next = %v", status)
	}
	encoded := host.memory[400 : 400+dnsabi.DNSRecordV1Size]
	if got := binary.LittleEndian.Uint32(encoded[260:264]); got != dnsabi.DNSRecordTypeCNAME {
		t.Fatalf("record type = %d", got)
	}
	if !bytes.Equal(encoded[268:300], make([]byte, 32)) {
		t.Fatal("CNAME published address bytes")
	}
	if canonical, ok := dnsabi.DecodeDNSNameV1(encoded, 300); !ok || canonical != query.record.CanonicalName {
		t.Fatalf("canonical name = %q, %v", canonical, ok)
	}

	query.record = dnsns.Record{Name: "api.example.com", Type: dnsns.RecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.9")}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusOK {
		t.Fatalf("A next = %v", status)
	}
	encoded = host.memory[400 : 400+dnsabi.DNSRecordV1Size]
	endpoint, ok := abicore.DecodeEndpointV1(encoded, 268)
	if !ok || endpoint.Address != query.record.Address || endpoint.Port != 0 || endpoint.ScopeID != 0 || endpoint.FlowInfo != 0 {
		t.Fatalf("address = %+v, %v", endpoint, ok)
	}
	if !bytes.Equal(encoded[300:], make([]byte, dnsabi.DNSNameV1Size)) {
		t.Fatal("address record published canonical-name bytes")
	}

	query.record = dnsns.Record{Name: "api.example.com", Type: dnsns.RecordA}
	invalidBefore := append([]byte(nil), host.memory[400:400+dnsabi.DNSRecordV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusIO || !bytes.Equal(host.memory[400:400+dnsabi.DNSRecordV1Size], invalidBefore) {
		t.Fatalf("malformed next = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(namespaceHandle), 400); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind next = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(queryHandle)); status != guest.StatusOK || query.cancelCalls != 1 {
		t.Fatalf("cancel = %v, calls=%d", status, query.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(queryHandle)); status != guest.StatusOK || query.closeCalls != 1 {
		t.Fatalf("close = %v, calls=%d", status, query.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusBadHandle {
		t.Fatalf("stale next = %v", status)
	}

	fresh := &fakeQuery{next: dnsns.NextWouldBlock}
	backend.next, backend.progress = fresh, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 336); status != guest.StatusInProgress {
		t.Fatalf("fresh resolve = %v", status)
	}
	freshHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[336:344]))
	if freshHandle == queryHandle || uint16(freshHandle) != uint16(queryHandle) {
		t.Fatalf("generation-safe slot reuse = old %v, fresh %v", queryHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(queryHandle)); status != guest.StatusBadHandle || fresh.cancelCalls != 0 {
		t.Fatalf("stale cancel = %v, fresh calls=%d", status, fresh.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(queryHandle)); status != guest.StatusBadHandle || fresh.closeCalls != 0 {
		t.Fatalf("stale close = %v, fresh calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusBadHandle || fresh.nextCalls != 0 {
		t.Fatalf("stale next after reuse = %v, fresh calls=%d", status, fresh.nextCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(freshHandle), 400); status != guest.StatusAgain || fresh.nextCalls != 1 {
		t.Fatalf("fresh next = %v, calls=%d", status, fresh.nextCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("fresh close = %v, calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(pendingHandle)); status != guest.StatusOK || pending.closeCalls != 1 {
		t.Fatalf("close pending = %v, calls=%d", status, pending.closeCalls)
	}
}

func TestBindingsRejectHighBitI32AliasesBeforeBackendCalls(t *testing.T) {
	backend := &fakeNamespace{failure: nscore.Fail(nscore.FailureTemporary, errors.New("backend called"))}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 1024)}
	bindings := Bindings(plugin.NewHost(manager))
	state, _ := manager.ForInstance(instance)
	request := dnsns.Request{Name: "api.example.com", Types: dnsns.RecordsA}
	if !dnsabi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode query")
	}
	query := &fakeQuery{next: dnsns.NextWouldBlock}
	handle, err := state.Resources().Add(resource.KindDNSQuery, query)
	if err != nil {
		t.Fatal(err)
	}

	const high = uint64(1) << 32
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, high+900); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("high namespace output = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(state.NamespaceHandle()), high, 320); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high resolve request = %v, calls=%d", status, backend.calls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(state.NamespaceHandle()), 0, high+320); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high resolve output = %v, calls=%d", status, backend.calls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(handle), high+400); status != guest.StatusInvalidArgument || query.nextCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high next output = %v, calls=%d", status, query.nextCalls)
	}
}

func TestBindingsPreserveFullWidthNamespaceAndQueryHandles(t *testing.T) {
	query := &fakeQuery{next: dnsns.NextWouldBlock}
	created := &fakeQuery{next: dnsns.NextWouldBlock}
	backend := &fakeNamespace{next: created, progress: nscore.ProgressInProgress}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x73}, 1024)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	namespaceHandle := state.NamespaceHandle()
	queryHandle, err := state.Resources().Add(resource.KindDNSQuery, query)
	if err != nil {
		t.Fatal(err)
	}
	request := dnsns.Request{Name: "api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	if !dnsabi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode query")
	}

	const high = uint64(1) << 63
	handleBefore := append([]byte(nil), host.memory[320:328]...)
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle)|high, 0, 320); status != guest.StatusBadHandle || backend.calls != 0 || !bytes.Equal(host.memory[320:328], handleBefore) {
		t.Fatalf("high namespace resolve = %v calls=%d", status, backend.calls)
	}
	recordBefore := append([]byte(nil), host.memory[400:400+dnsabi.DNSRecordV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle)|high, 400); status != guest.StatusBadHandle || query.nextCalls != 0 || !bytes.Equal(host.memory[400:400+dnsabi.DNSRecordV1Size], recordBefore) {
		t.Fatalf("high query next = %v calls=%d", status, query.nextCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(queryHandle)|high); status != guest.StatusBadHandle || query.cancelCalls != 0 {
		t.Fatalf("high query cancel = %v calls=%d", status, query.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(queryHandle)|high); status != guest.StatusBadHandle || query.closeCalls != 0 {
		t.Fatalf("high query close = %v calls=%d", status, query.closeCalls)
	}

	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusInProgress || backend.calls != 1 || backend.request != request {
		t.Fatalf("exact namespace resolve = %v calls=%d request=%+v", status, backend.calls, backend.request)
	}
	createdHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[320:328]))
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 400); status != guest.StatusAgain || query.nextCalls != 1 || !bytes.Equal(host.memory[400:400+dnsabi.DNSRecordV1Size], recordBefore) {
		t.Fatalf("exact query next = %v calls=%d", status, query.nextCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, uint64(queryHandle)); status != guest.StatusOK || query.cancelCalls != 1 {
		t.Fatalf("exact query cancel = %v calls=%d", status, query.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(queryHandle)); status != guest.StatusOK || query.closeCalls != 1 {
		t.Fatalf("exact query close = %v calls=%d", status, query.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(createdHandle)); status != guest.StatusOK || created.closeCalls != 1 {
		t.Fatalf("created query close = %v calls=%d", status, created.closeCalls)
	}
}

func TestBindingsPrevalidateBeforeInstanceAndHandleLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 64)}
	bindings := Bindings(plugin.NewHost(manager))
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 57); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("namespace range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "resolve"), host, 1, 0, 32); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("resolve range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, 1, 1); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("next range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func attachManager(t testing.TB, backend dnsns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		if backend == nil {
			return nscore.ComposeNamespace(&fakeBase{})
		}
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dnsns.ServiceKey, Value: backend})
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

func BenchmarkNextBindingReady(b *testing.B) {
	query := &fakeQuery{
		record: dnsns.Record{Name: "api.example.com", Type: dnsns.RecordAAAA, TTLSeconds: 60, Address: netip.MustParseAddr("2001:db8::9")},
		next:   dnsns.NextReady,
	}
	manager, instance := attachManager(b, &fakeNamespace{next: query, progress: nscore.ProgressDone})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindDNSQuery, query)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, dnsabi.DNSRecordV1Size)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "next")
	params := []uint64{uint64(handle), 0}
	var results [1]uint64
	function(host, params, results[:])
	if status := guest.Status(int32(results[0])); status != guest.StatusOK {
		b.Fatalf("warmup status = %v", status)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		function(host, params, results[:])
	}
}
