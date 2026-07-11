package net

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/abi"
	"github.com/wago-org/net/internal/instance"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type guestDNSNamespace struct {
	queries      []*guestDNSQuery
	resolveCalls int
	closed       bool
}

func (n *guestDNSNamespace) Close() error { n.closed = true; return nil }
func (n *guestDNSNamespace) Readiness() namespace.Readiness {
	if n.closed {
		return namespace.ReadyClosed
	}
	return namespace.ReadyWritable
}
func (n *guestDNSNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *guestDNSNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *guestDNSNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *guestDNSNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	n.resolveCalls++
	if len(n.queries) == 0 {
		return nil, 0, namespace.Fail(namespace.FailureResourceLimit, nil)
	}
	query := n.queries[0]
	n.queries = n.queries[1:]
	return query, namespace.ProgressInProgress, nil
}
func (n *guestDNSNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type guestDNSQuery struct {
	records  []namespace.DNSRecord
	ready    bool
	canceled bool
	closed   bool
}

func (q *guestDNSQuery) Close() error { q.closed = true; return nil }
func (q *guestDNSQuery) Cancel() error {
	if q.closed {
		return namespace.Fail(namespace.FailureClosed, nil)
	}
	q.canceled = true
	q.ready = true
	return nil
}
func (q *guestDNSQuery) Readiness() namespace.Readiness {
	if q.closed {
		return namespace.ReadyClosed
	}
	if q.canceled {
		return namespace.ReadyError
	}
	if q.ready {
		return namespace.ReadyDNSResult
	}
	return 0
}
func (q *guestDNSQuery) TryNext() (namespace.DNSRecord, namespace.DNSNext, error) {
	if q.closed {
		return namespace.DNSRecord{}, 0, namespace.Fail(namespace.FailureClosed, nil)
	}
	if q.canceled {
		return namespace.DNSRecord{}, 0, namespace.Fail(namespace.FailureCanceled, nil)
	}
	if !q.ready {
		return namespace.DNSRecord{}, namespace.DNSNextWouldBlock, nil
	}
	if len(q.records) == 0 {
		return namespace.DNSRecord{}, namespace.DNSNextEOF, nil
	}
	record := q.records[0]
	q.records = q.records[1:]
	return record, namespace.DNSNextReady, nil
}

func TestDNSBindingsRemainCompleteButUnregistered(t *testing.T) {
	extension := Init(Config{})
	runtime := runtimeForExtension(t, extension)
	if got := len(extension.dnsBindings()); got != 6 {
		t.Fatalf("checked DNS bindings = %d, want 6", got)
	}
	for _, binding := range extension.dnsBindings() {
		if _, exists := runtime.HostImports()[DNSModule+"."+binding.name]; exists {
			t.Fatalf("incomplete DNS binding %q was registered", binding.name)
		}
	}
	for _, capability := range runtime.Capabilities() {
		if capability == CapDNS {
			t.Fatal("incomplete DNS capability was advertised")
		}
	}
	for name := range Imports(Config{}) {
		if len(name) >= len(DNSModule)+1 && name[:len(DNSModule)+1] == DNSModule+"." {
			t.Fatalf("low-level imports exposed DNS function %q", name)
		}
	}
}

func TestCheckedGuestDNSResolveNextCancelAndClose(t *testing.T) {
	record := namespace.DNSRecord{Name: "example.com", Type: namespace.DNSRecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.44")}
	first := &guestDNSQuery{records: []namespace.DNSRecord{record}, ready: true}
	second := new(guestDNSQuery)
	extension, state, backend, host := newGuestDNSHarness(t, first, second)
	namespaceHandle := state.NamespaceHandle()
	if namespaceHandle == 0 {
		t.Fatal("missing DNS namespace handle")
	}

	if got := callDNS(extension.dnsNamespaceDefault, host, 1024); got != StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	if encoded := resource.Handle(binary.LittleEndian.Uint64(host.memory[1024:1032])); encoded != namespaceHandle {
		t.Fatalf("namespace handle = %v, want %v", encoded, namespaceHandle)
	}
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	if !abi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode query")
	}
	if got := callDNS(extension.dnsResolve, host, uint64(namespaceHandle), 0, 300); got != StatusInProgress {
		t.Fatalf("resolve = %v", got)
	}
	handle := resource.Handle(binary.LittleEndian.Uint64(host.memory[300:308]))
	if handle == 0 || backend.resolveCalls != 1 {
		t.Fatalf("resolved handle/calls = %v/%d", handle, backend.resolveCalls)
	}
	if got := callDNS(extension.dnsNext, host, uint64(handle), 400); got != StatusOK {
		t.Fatalf("next = %v", got)
	}
	if name, ok := abi.DecodeDNSNameV1(host.memory, 400); !ok || name != record.Name {
		t.Fatalf("encoded record name = %q, %v", name, ok)
	}
	if typ := binary.LittleEndian.Uint32(host.memory[660:664]); typ != abi.DNSRecordTypeA {
		t.Fatalf("encoded record type = %d", typ)
	}
	if ttl := binary.LittleEndian.Uint32(host.memory[664:668]); ttl != record.TTLSeconds {
		t.Fatalf("encoded record TTL = %d", ttl)
	}
	if endpoint, ok := abi.DecodeEndpointV1(host.memory, 668); !ok || endpoint.Address != record.Address {
		t.Fatalf("encoded record address = %+v, %v", endpoint, ok)
	}
	beforeEOF := append([]byte(nil), host.memory[400:960]...)
	if got := callDNS(extension.dnsNext, host, uint64(handle), 400); got != StatusEOF {
		t.Fatalf("next EOF = %v", got)
	}
	if !bytes.Equal(beforeEOF, host.memory[400:960]) {
		t.Fatal("EOF mutated DNS record output")
	}
	if got := callDNS(extension.dnsClose, host, uint64(handle)); got != StatusOK || !first.closed {
		t.Fatalf("close = %v, closed=%v", got, first.closed)
	}

	if got := callDNS(extension.dnsResolve, host, uint64(namespaceHandle), 0, 300); got != StatusInProgress {
		t.Fatalf("second resolve = %v", got)
	}
	cancelHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[300:308]))
	if got := callDNS(extension.dnsCancel, host, uint64(cancelHandle)); got != StatusOK || !second.canceled {
		t.Fatalf("cancel = %v, canceled=%v", got, second.canceled)
	}
	if got := callDNS(extension.dnsNext, host, uint64(cancelHandle), 400); got != StatusCanceled {
		t.Fatalf("canceled next = %v", got)
	}
	if got := callDNS(extension.dnsClose, host, uint64(cancelHandle)); got != StatusOK || !second.closed {
		t.Fatalf("canceled close = %v, closed=%v", got, second.closed)
	}
}

func TestGuestDNSRejectsMalformedMemoryBeforeWork(t *testing.T) {
	query := &guestDNSQuery{records: []namespace.DNSRecord{{Name: "example.com", Type: namespace.DNSRecordA, Address: netip.MustParseAddr("192.0.2.1")}}, ready: true}
	extension, state, backend, host := newGuestDNSHarness(t, query)
	namespaceHandle := state.NamespaceHandle()
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	if !abi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode query")
	}
	before := append([]byte(nil), host.memory...)
	if got := callDNS(extension.dnsResolve, host, uint64(namespaceHandle), uint64(len(host.memory)-10), 300); got != StatusInvalidArgument {
		t.Fatalf("short query = %v", got)
	}
	if got := callDNS(extension.dnsResolve, host, uint64(namespaceHandle), 0, 260); got != StatusInvalidArgument {
		t.Fatalf("overlapping query/output = %v", got)
	}
	host.memory[264] = 1
	if got := callDNS(extension.dnsResolve, host, uint64(namespaceHandle), 0, 300); got != StatusInvalidArgument {
		t.Fatalf("reserved query = %v", got)
	}
	if backend.resolveCalls != 0 || !bytes.Equal(before[:264], host.memory[:264]) {
		t.Fatalf("malformed query performed work or mutated input: calls=%d", backend.resolveCalls)
	}
	host.memory[264] = 0
	if got := callDNS(extension.dnsResolve, host, uint64(namespaceHandle), 0, 300); got != StatusInProgress {
		t.Fatalf("valid resolve = %v", got)
	}
	handle := resource.Handle(binary.LittleEndian.Uint64(host.memory[300:308]))
	if got := callDNS(extension.dnsNext, host, uint64(handle), uint64(len(host.memory)-10)); got != StatusInvalidArgument {
		t.Fatalf("short record output = %v", got)
	}
	if len(query.records) != 1 {
		t.Fatal("invalid next consumed a DNS record")
	}
	if got := callDNS(extension.dnsNext, host, uint64(namespaceHandle), 400); got != StatusBadHandle {
		t.Fatalf("wrong-kind next = %v", got)
	}
}

func FuzzGuestDNSMemory(f *testing.F) {
	seed := make([]byte, 1024)
	_ = abi.EncodeDNSQueryV1(seed, 0, namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
	f.Add(seed, uint64(0), uint64(300))
	f.Add([]byte{1, 2, 3}, ^uint64(0), ^uint64(0))
	f.Fuzz(func(t *testing.T, memory []byte, queryPtr, outputPtr uint64) {
		if len(memory) > 4096 {
			memory = memory[:4096]
		}
		query := &guestDNSQuery{records: []namespace.DNSRecord{{Name: "example.com", Type: namespace.DNSRecordA, Address: netip.MustParseAddr("192.0.2.1")}}, ready: true}
		extension, state, _, host := newGuestDNSHarness(t, query)
		host.memory = append([]byte(nil), memory...)
		var results [1]uint64
		extension.dnsResolve(host, []uint64{uint64(state.NamespaceHandle()), queryPtr, outputPtr}, results[:])
		if Status(int32(results[0])) == StatusInProgress {
			handleBytes, ok := abi.Slice(host.memory, uint32(outputPtr), abi.HandleV1Size)
			if ok {
				handle := binary.LittleEndian.Uint64(handleBytes)
				extension.dnsNext(host, []uint64{handle, outputPtr}, results[:])
			}
		}
	})
}

func newGuestDNSHarness(t testing.TB, queries ...*guestDNSQuery) (*Extension, *instance.State, *guestDNSNamespace, udpHostModule) {
	t.Helper()
	backend := &guestDNSNamespace{queries: append([]*guestDNSQuery(nil), queries...)}
	manager, err := instance.NewManagerConfigured(instance.Config{
		Limits:    quota.DefaultLimits(),
		Readiness: instance.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (namespace.Namespace, error) {
			return backend, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wagoInstance := new(wago.Instance)
	if err := manager.Attach(wagoInstance); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Detach(wagoInstance) })
	state, ok := manager.ForInstance(wagoInstance)
	if !ok {
		t.Fatal("missing attached DNS state")
	}
	return &Extension{instances: manager}, state, backend, udpHostModule{instance: wagoInstance, memory: make([]byte, 2048)}
}

func callDNS(function wago.HostFunc, host udpHostModule, params ...uint64) Status {
	var results [1]uint64
	function(host, params, results[:])
	return Status(int32(results[0]))
}
