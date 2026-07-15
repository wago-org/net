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

	var typedNil *fakeQuery
	backend.query, backend.queryProgress, backend.queryFailure = typedNil, nscore.ProgressDone, nil
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusIO || backend.queryCalls != 2 || !bytes.Equal(host.memory[320:328], handleBefore) {
		t.Fatalf("typed-nil query = %v, calls=%d", status, backend.queryCalls)
	}

	query := &fakeQuery{next: mdnsns.NextWouldBlock}
	backend.query, backend.queryProgress = query, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusOK || backend.queryCalls != 3 || backend.request != request {
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

	fresh := &fakeQuery{next: mdnsns.NextWouldBlock}
	backend.query, backend.queryProgress = fresh, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "query"), host, uint64(namespaceHandle), 0, 336); status != guest.StatusOK {
		t.Fatalf("fresh query = %v", status)
	}
	freshHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[336:344]))
	if freshHandle == queryHandle || uint16(freshHandle) != uint16(queryHandle) {
		t.Fatalf("generation-safe slot reuse = old %v, fresh %v", queryHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel_query"), host, uint64(queryHandle)); status != guest.StatusBadHandle || fresh.cancelCalls != 0 {
		t.Fatalf("stale cancel = %v, fresh calls=%d", status, fresh.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(freshHandle), 500); status != guest.StatusAgain || fresh.nextCalls != 1 {
		t.Fatalf("fresh next = %v, calls=%d", status, fresh.nextCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_query"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("close fresh = %v, calls=%d", status, fresh.closeCalls)
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

func TestBindingsAnnouncementHandlesPreserveKindGenerationAndFullI64Identity(t *testing.T) {
	manager, instance := attachManager(t, &fakeNamespace{})
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: make([]byte, 1)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}

	old := &fakeAnnouncement{next: mdnsns.NextWouldBlock}
	oldHandle, err := state.Resources().Add(resource.KindMDNSAnnouncement, old)
	if err != nil {
		t.Fatal(err)
	}
	query := &fakeQuery{next: mdnsns.NextWouldBlock}
	queryHandle, err := state.Resources().Add(resource.KindMDNSQuery, query)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		binding string
		handle  resource.Handle
	}{
		{binding: "finish_announcement", handle: queryHandle},
		{binding: "cancel_announcement", handle: queryHandle},
		{binding: "close_announcement", handle: queryHandle},
		{binding: "cancel_query", handle: oldHandle},
		{binding: "close_query", handle: oldHandle},
	} {
		if status := callBinding(t, bindingByName(t, bindings, test.binding), host, uint64(test.handle)); status != guest.StatusBadHandle {
			t.Fatalf("%s wrong-kind status = %v", test.binding, status)
		}
	}
	if old.finishCalls != 0 || old.cancelCalls != 0 || old.closeCalls != 0 || query.cancelCalls != 0 || query.closeCalls != 0 {
		t.Fatalf("wrong-kind operation reached resource: old=%d/%d/%d query=%d/%d", old.finishCalls, old.cancelCalls, old.closeCalls, query.cancelCalls, query.closeCalls)
	}

	if status := callBinding(t, bindingByName(t, bindings, "close_announcement"), host, uint64(oldHandle)); status != guest.StatusOK || old.closeCalls != 1 {
		t.Fatalf("close old announcement = %v, calls=%d", status, old.closeCalls)
	}
	fresh := &fakeAnnouncement{next: mdnsns.NextReady}
	freshHandle, err := state.Resources().Add(resource.KindMDNSAnnouncement, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if freshHandle == oldHandle || uint16(freshHandle) != uint16(oldHandle) {
		t.Fatalf("generation-safe announcement slot reuse = old %v, fresh %v", oldHandle, freshHandle)
	}
	for _, binding := range []string{"finish_announcement", "cancel_announcement", "close_announcement"} {
		if status := callBinding(t, bindingByName(t, bindings, binding), host, uint64(oldHandle)); status != guest.StatusBadHandle {
			t.Fatalf("%s stale status = %v", binding, status)
		}
	}
	wideAlias := uint64(freshHandle) | uint64(1)<<48
	for _, binding := range []string{"finish_announcement", "cancel_announcement", "close_announcement"} {
		if status := callBinding(t, bindingByName(t, bindings, binding), host, wideAlias); status != guest.StatusBadHandle {
			t.Fatalf("%s wide i64 alias status = %v", binding, status)
		}
	}
	if fresh.finishCalls != 0 || fresh.cancelCalls != 0 || fresh.closeCalls != 0 {
		t.Fatalf("stale or wide handle reached fresh resource: %d/%d/%d", fresh.finishCalls, fresh.cancelCalls, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "finish_announcement"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.finishCalls != 1 {
		t.Fatalf("finish fresh announcement = %v, calls=%d", status, fresh.finishCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel_announcement"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.cancelCalls != 1 {
		t.Fatalf("cancel fresh announcement = %v, calls=%d", status, fresh.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_announcement"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("close fresh announcement = %v, calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_query"), host, uint64(queryHandle)); status != guest.StatusOK || query.closeCalls != 1 {
		t.Fatalf("close query = %v, calls=%d", status, query.closeCalls)
	}
}

func TestBindingsNamespaceAndQueryHandlesPreserveFullI64Identity(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x3c}, 1200)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	namespaceHandle := state.NamespaceHandle()
	if !mdnsabi.EncodeQueryV1(host.memory, 0, mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}) {
		t.Fatal("encode query")
	}
	if !mdnsabi.EncodeAnnouncementV1(host.memory, 300, 0) {
		t.Fatal("encode announcement")
	}
	wideNamespace := uint64(namespaceHandle) | uint64(1)<<48
	for _, test := range []struct {
		binding string
		params  []uint64
	}{
		{binding: "query", params: []uint64{wideNamespace, 0, 1100}},
		{binding: "announce", params: []uint64{wideNamespace, 300, 1100}},
	} {
		before := append([]byte(nil), host.memory[1100:1108]...)
		queryCalls, announcementCalls := backend.queryCalls, backend.announcementCalls
		if status := callBinding(t, bindingByName(t, bindings, test.binding), host, test.params...); status != guest.StatusBadHandle {
			t.Fatalf("%s wide namespace status = %v", test.binding, status)
		}
		if backend.queryCalls != queryCalls || backend.announcementCalls != announcementCalls {
			t.Fatalf("%s wide namespace reached backend: query=%d announcement=%d", test.binding, backend.queryCalls, backend.announcementCalls)
		}
		if !bytes.Equal(host.memory[1100:1108], before) {
			t.Fatalf("%s wide namespace mutated output", test.binding)
		}
	}

	old := &fakeQuery{next: mdnsns.NextWouldBlock}
	oldHandle, err := state.Resources().Add(resource.KindMDNSQuery, old)
	if err != nil {
		t.Fatal(err)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_query"), host, uint64(oldHandle)); status != guest.StatusOK || old.closeCalls != 1 {
		t.Fatalf("close old query = %v, calls=%d", status, old.closeCalls)
	}
	fresh := &fakeQuery{next: mdnsns.NextWouldBlock}
	freshHandle, err := state.Resources().Add(resource.KindMDNSQuery, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if freshHandle == oldHandle || uint16(freshHandle) != uint16(oldHandle) {
		t.Fatalf("generation-safe query slot reuse = old %v, fresh %v", oldHandle, freshHandle)
	}
	wideQuery := uint64(freshHandle) | uint64(1)<<48
	for _, handle := range []uint64{uint64(oldHandle), wideQuery} {
		if status := callBinding(t, bindingByName(t, bindings, "next"), host, handle, 0); status != guest.StatusBadHandle {
			t.Fatalf("next alias %#x status = %v", handle, status)
		}
		if status := callBinding(t, bindingByName(t, bindings, "cancel_query"), host, handle); status != guest.StatusBadHandle {
			t.Fatalf("cancel alias %#x status = %v", handle, status)
		}
		if status := callBinding(t, bindingByName(t, bindings, "close_query"), host, handle); status != guest.StatusBadHandle {
			t.Fatalf("close alias %#x status = %v", handle, status)
		}
	}
	if fresh.nextCalls != 0 || fresh.cancelCalls != 0 || fresh.closeCalls != 0 {
		t.Fatalf("stale or wide query handle reached fresh resource: %d/%d/%d", fresh.nextCalls, fresh.cancelCalls, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "next"), host, uint64(freshHandle), 0); status != guest.StatusAgain || fresh.nextCalls != 1 {
		t.Fatalf("next fresh query = %v, calls=%d", status, fresh.nextCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel_query"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.cancelCalls != 1 {
		t.Fatalf("cancel fresh query = %v, calls=%d", status, fresh.cancelCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_query"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("close fresh query = %v, calls=%d", status, fresh.closeCalls)
	}
}

func TestBindingsRejectHighBitI32AliasesBeforeStateAndBackendWork(t *testing.T) {
	backend := &fakeNamespace{}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x4d}, 1000)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	namespaceHandle := state.NamespaceHandle()
	query := &fakeQuery{next: mdnsns.NextReady, record: mdnsns.Record{Name: "host.local", Type: mdnsns.RecordA, TTLSeconds: 1, Address: netip.MustParseAddr("192.0.2.1")}}
	queryHandle, err := state.Resources().Add(resource.KindMDNSQuery, query)
	if err != nil {
		t.Fatal(err)
	}
	if !mdnsabi.EncodeQueryV1(host.memory, 0, mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}) {
		t.Fatal("encode query")
	}
	if !mdnsabi.EncodeAnnouncementV1(host.memory, 400, 7) {
		t.Fatal("encode announcement")
	}

	high := uint64(1) << 32
	tests := []struct {
		name    string
		binding string
		params  []uint64
	}{
		{name: "namespace output", binding: "namespace_default", params: []uint64{high | 900}},
		{name: "query request", binding: "query", params: []uint64{uint64(namespaceHandle), high, 900}},
		{name: "query output", binding: "query", params: []uint64{uint64(namespaceHandle), 0, high | 900}},
		{name: "next output", binding: "next", params: []uint64{uint64(queryHandle), high | 64}},
		{name: "announcement request", binding: "announce", params: []uint64{uint64(namespaceHandle), high | 400, 900}},
		{name: "announcement output", binding: "announce", params: []uint64{uint64(namespaceHandle), 400, high | 900}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := append([]byte(nil), host.memory...)
			queryCalls, announcementCalls, nextCalls := backend.queryCalls, backend.announcementCalls, query.nextCalls
			if status := callBinding(t, bindingByName(t, bindings, test.binding), host, test.params...); status != guest.StatusInvalidArgument {
				t.Fatalf("status = %v", status)
			}
			if backend.queryCalls != queryCalls || backend.announcementCalls != announcementCalls || query.nextCalls != nextCalls {
				t.Fatalf("backend work changed: query=%d announcement=%d next=%d", backend.queryCalls, backend.announcementCalls, query.nextCalls)
			}
			if !bytes.Equal(host.memory, before) {
				t.Fatal("invalid alias mutated guest memory")
			}
		})
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
