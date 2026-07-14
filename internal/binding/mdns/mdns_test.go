package mdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	mdnsabi "github.com/wago-org/net/internal/abi/mdns"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
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
	query                nscore.Resource
	queryProgress        nscore.Progress
	queryFailure         error
	request              mdnsns.Request
	queryCalls           int
	announcement         nscore.Resource
	announcementProgress nscore.Progress
	announcementFailure  error
	service              uint16
	announcementCalls    int
}

func (n *fakeNamespace) TryQuery(request mdnsns.Request) (nscore.Resource, nscore.Progress, error) {
	n.queryCalls++
	n.request = request
	return n.query, n.queryProgress, n.queryFailure
}
func (n *fakeNamespace) TryAnnounce(service uint16) (nscore.Resource, nscore.Progress, error) {
	n.announcementCalls++
	n.service = service
	return n.announcement, n.announcementProgress, n.announcementFailure
}

type fakeQuery struct {
	record      mdnsns.Record
	next        mdnsns.Next
	failure     error
	nextCalls   int
	cancelCalls int
	closeCalls  int
}

type fakeAnnouncement struct {
	next        mdnsns.Next
	failure     error
	finishCalls int
	cancelCalls int
	closeCalls  int
}

func (a *fakeAnnouncement) Close() error {
	a.closeCalls++
	return nil
}
func (a *fakeAnnouncement) Cancel() error {
	a.cancelCalls++
	return nil
}
func (*fakeAnnouncement) Readiness() nscore.Readiness { return nscore.ReadyMDNSAnnouncement }
func (a *fakeAnnouncement) TryFinish() (mdnsns.Next, error) {
	a.finishCalls++
	return a.next, a.failure
}

func (q *fakeQuery) Close() error {
	q.closeCalls++
	return nil
}
func (q *fakeQuery) Cancel() error {
	q.cancelCalls++
	return nil
}
func (*fakeQuery) Readiness() nscore.Readiness { return nscore.ReadyMDNSResult }
func (q *fakeQuery) TryNext() (mdnsns.Record, mdnsns.Next, error) {
	q.nextCalls++
	return q.record, q.next, q.failure
}

func TestBindingsQueryNextAtomicStatusesAndLifecycle(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 1600)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 1500); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[1500:1508]))
	request := mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR | mdnsns.RecordsSRV}
	if !mdnsabi.EncodeQueryV1(host.memory, 0, request) {
		t.Fatal("encode query")
	}

	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 264); status != guest.StatusInvalidArgument || backend.queryCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap query = %v, calls=%d", status, backend.queryCalls)
	}
	host.memory[264] = 1
	handleBefore := append([]byte(nil), host.memory[320:328]...)
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusInvalidArgument || backend.queryCalls != 0 || !bytes.Equal(host.memory[320:328], handleBefore) {
		t.Fatalf("reserved query = %v, calls=%d", status, backend.queryCalls)
	}
	host.memory[264] = 0

	backend.queryFailure = nscore.Fail(nscore.FailureAccessDenied, errors.New("denied"))
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusAccessDenied || backend.queryCalls != 1 || !bytes.Equal(host.memory[320:328], handleBefore) {
		t.Fatalf("failed query = %v, calls=%d", status, backend.queryCalls)
	}

	query := &fakeQuery{next: mdnsns.NextWouldBlock}
	backend.query, backend.queryProgress, backend.queryFailure = query, nscore.ProgressDone, nil
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusOK || backend.queryCalls != 2 || backend.request != request {
		t.Fatalf("query = %v, calls=%d request=%+v", status, backend.queryCalls, backend.request)
	}
	queryHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[320:328]))

	pending := new(fakeQuery)
	backend.query, backend.queryProgress = pending, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 328); status != guest.StatusInProgress {
		t.Fatalf("in-progress query = %v", status)
	}
	pendingHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[328:336]))

	recordBefore := append([]byte(nil), host.memory[500:500+mdnsabi.RecordV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 500); status != guest.StatusAgain || query.nextCalls != 1 || !bytes.Equal(host.memory[500:500+mdnsabi.RecordV1Size], recordBefore) {
		t.Fatalf("would-block next = %v, calls=%d", status, query.nextCalls)
	}
	query.next = mdnsns.NextEOF
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 500); status != guest.StatusEOF || !bytes.Equal(host.memory[500:500+mdnsabi.RecordV1Size], recordBefore) {
		t.Fatalf("EOF next = %v", status)
	}
	query.failure = nscore.Fail(nscore.FailureCanceled, errors.New("canceled"))
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 500); status != guest.StatusCanceled || !bytes.Equal(host.memory[500:500+mdnsabi.RecordV1Size], recordBefore) {
		t.Fatalf("failed next = %v", status)
	}
	query.failure = nil
	query.next = mdnsns.NextReady
	query.record = mdnsns.Record{Name: "host.local", Type: mdnsns.RecordA, Address: netip.MustParseAddr("192.0.2.10")}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 500); status != guest.StatusIO || !bytes.Equal(host.memory[500:500+mdnsabi.RecordV1Size], recordBefore) {
		t.Fatalf("malformed record = %v", status)
	}

	query.record.TTLSeconds = 120
	query.record.CacheFlush = true
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 500); status != guest.StatusOK {
		t.Fatalf("ready next = %v", status)
	}
	encoded := host.memory[500 : 500+mdnsabi.RecordV1Size]
	if got := binary.LittleEndian.Uint32(encoded[260:264]); got != mdnsabi.RecordTypeA {
		t.Fatalf("record type = %d", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[264:268]); got != query.record.TTLSeconds {
		t.Fatalf("TTL = %d", got)
	}
	endpoint, ok := abicore.DecodeEndpointV1(encoded, 268)
	if !ok || endpoint.Address != query.record.Address || endpoint.Port != 0 || endpoint.ScopeID != 0 || endpoint.FlowInfo != 0 {
		t.Fatalf("address = %+v, %v", endpoint, ok)
	}
	if !bytes.Equal(encoded[300:824], make([]byte, 524)) {
		t.Fatal("A record published type-specific unused bytes")
	}
	if flags := binary.LittleEndian.Uint32(encoded[824:828]); flags != mdnsabi.RecordFlagCacheFlush {
		t.Fatalf("flags = %#x", flags)
	}
	if reserved := binary.LittleEndian.Uint32(encoded[828:832]); reserved != 0 {
		t.Fatalf("reserved = %#x", reserved)
	}

	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(namespaceHandle), 500); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind next = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel_query"), host, uint64(queryHandle)); status != guest.StatusOK || query.cancelCalls != 1 {
		t.Fatalf("cancel query = %v, calls=%d", status, query.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_query"), host, uint64(queryHandle)); status != guest.StatusOK || query.closeCalls != 1 {
		t.Fatalf("close query = %v, calls=%d", status, query.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(queryHandle), 500); status != guest.StatusBadHandle {
		t.Fatalf("stale next = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_query"), host, uint64(pendingHandle)); status != guest.StatusOK || pending.closeCalls != 1 {
		t.Fatalf("close pending = %v, calls=%d", status, pending.closeCalls)
	}
}

func TestBindingsAnnouncementAtomicStatusesAndLifecycle(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x6b}, 256)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 224); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[224:232]))
	if !mdnsabi.EncodeAnnouncementV1(host.memory, 0, 7) {
		t.Fatal("encode announcement")
	}

	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, uint64(namespaceHandle), 0, 4); status != guest.StatusInvalidArgument || backend.announcementCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap announcement = %v, calls=%d", status, backend.announcementCalls)
	}
	binary.LittleEndian.PutUint32(host.memory[4:8], 1)
	before = append(before[:0], host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, uint64(namespaceHandle), 0, 32); status != guest.StatusInvalidArgument || backend.announcementCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("reserved announcement = %v, calls=%d", status, backend.announcementCalls)
	}
	binary.LittleEndian.PutUint32(host.memory[4:8], 0)
	binary.LittleEndian.PutUint32(host.memory[0:4], 1<<16)
	before = append(before[:0], host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, uint64(namespaceHandle), 0, 32); status != guest.StatusInvalidArgument || backend.announcementCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("wide service announcement = %v, calls=%d", status, backend.announcementCalls)
	}
	binary.LittleEndian.PutUint32(host.memory[0:4], 7)
	handleBefore := append([]byte(nil), host.memory[32:40]...)

	backend.announcementFailure = nscore.Fail(nscore.FailureAccessDenied, errors.New("denied"))
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, uint64(namespaceHandle), 0, 32); status != guest.StatusAccessDenied || backend.announcementCalls != 1 || !bytes.Equal(host.memory[32:40], handleBefore) {
		t.Fatalf("failed announcement = %v, calls=%d", status, backend.announcementCalls)
	}

	invalid := &fakeAnnouncement{}
	backend.announcement, backend.announcementProgress, backend.announcementFailure = invalid, nscore.ProgressWouldBlock, nil
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, uint64(namespaceHandle), 0, 32); status != guest.StatusIO || invalid.closeCalls != 1 || !bytes.Equal(host.memory[32:40], handleBefore) {
		t.Fatalf("malformed announcement = %v, closes=%d", status, invalid.closeCalls)
	}

	ready := &fakeAnnouncement{next: mdnsns.NextWouldBlock}
	backend.announcement, backend.announcementProgress = ready, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, uint64(namespaceHandle), 0, 32); status != guest.StatusOK || backend.service != 7 {
		t.Fatalf("ready announcement = %v, service=%d", status, backend.service)
	}
	readyHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[32:40]))

	pending := &fakeAnnouncement{next: mdnsns.NextWouldBlock}
	backend.announcement, backend.announcementProgress = pending, nscore.ProgressInProgress
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, uint64(namespaceHandle), 0, 40); status != guest.StatusInProgress {
		t.Fatalf("pending announcement = %v", status)
	}
	pendingHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[40:48]))

	if status := callBinding(t, bindingByName(t, bindings, "finish_announcement"), host, uint64(readyHandle)); status != guest.StatusAgain || ready.finishCalls != 1 {
		t.Fatalf("would-block finish = %v, calls=%d", status, ready.finishCalls)
	}
	ready.failure = nscore.Fail(nscore.FailureCanceled, errors.New("canceled"))
	if status := callBinding(t, bindingByName(t, bindings, "finish_announcement"), host, uint64(readyHandle)); status != guest.StatusCanceled {
		t.Fatalf("failed finish = %v", status)
	}
	ready.failure = nil
	ready.next = mdnsns.NextEOF
	if status := callBinding(t, bindingByName(t, bindings, "finish_announcement"), host, uint64(readyHandle)); status != guest.StatusIO {
		t.Fatalf("malformed finish = %v", status)
	}
	ready.next = mdnsns.NextReady
	if status := callBinding(t, bindingByName(t, bindings, "finish_announcement"), host, uint64(readyHandle)); status != guest.StatusOK {
		t.Fatalf("ready finish = %v", status)
	}

	if status := callBinding(t, bindingByName(t, bindings, "finish_announcement"), host, uint64(namespaceHandle)); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind finish = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel_announcement"), host, uint64(readyHandle)); status != guest.StatusOK || ready.cancelCalls != 1 {
		t.Fatalf("cancel announcement = %v, calls=%d", status, ready.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_announcement"), host, uint64(readyHandle)); status != guest.StatusOK || ready.closeCalls != 1 {
		t.Fatalf("close announcement = %v, calls=%d", status, ready.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "finish_announcement"), host, uint64(readyHandle)); status != guest.StatusBadHandle {
		t.Fatalf("stale finish = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_announcement"), host, uint64(pendingHandle)); status != guest.StatusOK || pending.closeCalls != 1 {
		t.Fatalf("close pending = %v, calls=%d", status, pending.closeCalls)
	}
}

func TestBindingsPrevalidateQueryOutputsBeforeInstanceAndHandleLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 64)}
	bindings := Bindings(plugin.NewHost(manager))
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 57); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("namespace range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, 1, 0, 32); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("query range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "announce"), host, 1, 0, 60); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("announcement range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, 1, 1); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("next range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func attachManager(t testing.TB, backend mdnsns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		if backend == nil {
			return nscore.ComposeNamespace(&fakeBase{})
		}
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

func BenchmarkFinishAnnouncementBindingReady(b *testing.B) {
	announcement := &fakeAnnouncement{next: mdnsns.NextReady}
	manager, instance := attachManager(b, &fakeNamespace{})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindMDNSAnnouncement, announcement)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, 1)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "finish_announcement")
	params := []uint64{uint64(handle)}
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

func BenchmarkNextBindingReady(b *testing.B) {
	query := &fakeQuery{
		record: mdnsns.Record{Name: "host.local", Type: mdnsns.RecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.10"), CacheFlush: true},
		next:   mdnsns.NextReady,
	}
	manager, instance := attachManager(b, &fakeNamespace{query: query, queryProgress: nscore.ProgressDone})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindMDNSQuery, query)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, mdnsabi.RecordV1Size)}
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
