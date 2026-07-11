package net

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/abi"
	"github.com/wago-org/net/internal/instance"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
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

func TestDNSBindingsAreRegisteredOnlyAsCompleteTable(t *testing.T) {
	extension := Init(Config{})
	runtime := runtimeForExtension(t, extension)
	if got := len(extension.dnsBindings()); got != 6 {
		t.Fatalf("checked DNS bindings = %d, want 6", got)
	}
	for _, binding := range extension.dnsBindings() {
		if _, ok := runtime.HostImports()[DNSModule+"."+binding.name].(wago.HostFunc); !ok {
			t.Fatalf("registered DNS binding %q missing", binding.name)
		}
	}
	foundCapability := false
	for _, capability := range runtime.Capabilities() {
		foundCapability = foundCapability || capability == CapDNS
	}
	if !foundCapability {
		t.Fatal("complete DNS capability was not advertised")
	}
	for name := range Imports(Config{}) {
		if len(name) >= len(DNSModule)+1 && name[:len(DNSModule)+1] == DNSModule+"." {
			t.Fatalf("low-level stateless imports exposed DNS resource function %q", name)
		}
	}
}

func TestGuestDNSUnavailableNamespaceAndCapabilityGate(t *testing.T) {
	extension := Init(Config{})
	runtime := runtimeForExtension(t, extension)
	instance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime))
	if err != nil {
		t.Fatalf("instantiate empty DNS guest: %v", err)
	}
	host := udpHostModule{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 16)}
	before := append([]byte(nil), host.memory...)
	if got := callRegisteredDNS(t, runtime, "namespace_default", host, 0); got != StatusNotSupported {
		t.Fatalf("DNS namespace without configuration = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("unavailable DNS namespace mutated output")
	}
	_ = instance.Close()

	importEntry := append(append(wasmtest.Name(DNSModule), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	wasmBytes := wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(importEntry)),
	)
	module, err := runtime.Compile(wasmBytes)
	if err != nil {
		t.Fatalf("compile DNS capability module: %v", err)
	}
	if _, err := runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{DeniedCapabilities: []wago.Capability{CapDNS}})); !errors.Is(err, wago.ErrPermissionDenied) {
		t.Fatalf("denied DNS capability instantiate = %v", err)
	}
	allowed, err := runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{CapDNS}}))
	if err != nil {
		t.Fatalf("allowed DNS capability instantiate: %v", err)
	}
	_ = allowed.Close()
}

func TestRegisteredGuestDNSActualBackendSmoke(t *testing.T) {
	extension := Init(actualGuestDNSConfig(103))
	runtime := runtimeForExtension(t, extension)
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	host := udpHostModule{instance: instance, memory: make([]byte, 1024)}
	if got := callRegisteredDNS(t, runtime, "namespace_default", host, 300); got != StatusOK {
		t.Fatalf("registered DNS namespace = %v", got)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[300:308]))
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	if !abi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode registered DNS request")
	}
	if got := callRegisteredDNS(t, runtime, "resolve", host, uint64(namespaceHandle), 0, 320); got != StatusInProgress {
		t.Fatalf("registered DNS resolve = %v", got)
	}
	query := resource.Handle(binary.LittleEndian.Uint64(host.memory[320:328]))
	if got := callRegisteredDNS(t, runtime, "cancel", host, uint64(query)); got != StatusOK {
		t.Fatalf("registered DNS cancel = %v", got)
	}
	if got := callRegisteredDNS(t, runtime, "next", host, uint64(query), 400); got != StatusCanceled {
		t.Fatalf("registered canceled DNS next = %v", got)
	}
	if got := callRegisteredDNS(t, runtime, "close", host, uint64(query)); got != StatusOK {
		t.Fatalf("registered DNS close = %v", got)
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

func TestActualBackendGuestDNSSuccessPollQuotaAndCleanup(t *testing.T) {
	extension, instance, host := newActualGuestDNSInstance(t, 81)
	state, ok := extension.instanceManager().ForInstance(instance)
	if !ok {
		t.Fatal("missing actual DNS state")
	}
	namespaceHandle := actualGuestDNSNamespaceHandle(t, extension, host)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	if !abi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode actual DNS request")
	}
	if got := callDNSNamed(t, extension, "resolve", host, uint64(namespaceHandle), 0, 260); got != StatusInvalidArgument {
		t.Fatalf("overlapping actual resolve = %v", got)
	}
	if usage, _ := state.Quotas().Snapshot(); usage.DNSResources != 0 || usage.DNSWork != 0 {
		t.Fatalf("invalid resolve performed work = %+v", usage)
	}
	if got := callDNSNamed(t, extension, "resolve", host, uint64(namespaceHandle), 0, 300); got != StatusInProgress {
		t.Fatalf("actual resolve = %v", got)
	}
	query := resource.Handle(binary.LittleEndian.Uint64(host.memory[300:308]))
	if query == 0 {
		t.Fatal("actual resolve returned zero handle")
	}
	copy(host.memory[308:316], bytes.Repeat([]byte{0x5a}, 8))
	beforeLimit := append([]byte(nil), host.memory[308:316]...)
	if got := callDNSNamed(t, extension, "resolve", host, uint64(namespaceHandle), 0, 308); got != StatusResourceLimit {
		t.Fatalf("second actual resolve = %v", got)
	}
	if !bytes.Equal(host.memory[308:316], beforeLimit) {
		t.Fatal("quota-denied resolve mutated handle output")
	}
	copy(host.memory[400:960], bytes.Repeat([]byte{0xa5}, int(abi.DNSRecordV1Size)))
	beforeNext := append([]byte(nil), host.memory[400:960]...)
	if got := callDNSNamed(t, extension, "next", host, uint64(query), 400); got != StatusAgain {
		t.Fatalf("next before response = %v", got)
	}
	if !bytes.Equal(host.memory[400:960], beforeNext) {
		t.Fatal("AGAIN mutated actual DNS record output")
	}

	writePollBudget(host.memory, 1000, 2, 2, 1, 1, 1514, 1)
	beforeLink := concreteNamespace(t, state).Link().Snapshot()
	if got := callDNSNamed(t, extension, "poll", host, 1100, 2, 1000, 1110); got != StatusInvalidArgument {
		t.Fatalf("overlapping actual DNS poll = %v", got)
	}
	if after := concreteNamespace(t, state).Link().Snapshot(); after != beforeLink {
		t.Fatalf("invalid DNS poll performed service: before %+v after %+v", beforeLink, after)
	}

	txid, localPort := serviceActualGuestDNSQuery(t, extension, state, host)
	answers := []guestDNSWireAnswer{
		{name: "example.com", typ: 5, ttl: 60, cname: "canonical.example.com"},
		{name: "canonical.example.com", typ: 1, ttl: 120, data: []byte{192, 0, 2, 99}},
		{name: "canonical.example.com", typ: 28, ttl: 180, data: netip.MustParseAddr("2001:db8::99").AsSlice()},
	}
	response := buildGuestDNSResponse(t, actualGuestDNSConfig(81), request, txid, localPort, 0, false, answers)
	if err := concreteNamespace(t, state).Link().TryEnqueue(packetlink.Ingress, response); err != nil {
		t.Fatalf("enqueue actual DNS response: %v", err)
	}
	pollActualGuestDNSUntil(t, extension, host, query, namespace.ReadyDNSResult)

	want := []namespace.DNSRecord{
		{Name: "example.com", Type: namespace.DNSRecordCNAME, TTLSeconds: 60, CanonicalName: "canonical.example.com"},
		{Name: "canonical.example.com", Type: namespace.DNSRecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.99")},
		{Name: "canonical.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 180, Address: netip.MustParseAddr("2001:db8::99")},
	}
	for i, expected := range want {
		if got := callDNSNamed(t, extension, "next", host, uint64(query), 400); got != StatusOK {
			t.Fatalf("actual next %d = %v", i, got)
		}
		if record := decodeGuestDNSRecord(t, host.memory, 400); record != expected {
			t.Fatalf("actual record %d = %+v, want %+v", i, record, expected)
		}
	}
	beforeEOF := append([]byte(nil), host.memory[400:960]...)
	if got := callDNSNamed(t, extension, "next", host, uint64(query), 400); got != StatusEOF {
		t.Fatalf("actual DNS EOF = %v", got)
	}
	if !bytes.Equal(host.memory[400:960], beforeEOF) {
		t.Fatal("actual DNS EOF mutated record output")
	}
	if got := callDNSNamed(t, extension, "close", host, uint64(query)); got != StatusOK {
		t.Fatalf("actual DNS close = %v", got)
	}
	if usage, closed := state.Quotas().Snapshot(); closed || usage.Resources != 1 || usage.DNSResources != 0 || usage.DNSWork != 0 || usage.QueuedBytes != 0 {
		t.Fatalf("closed actual DNS quota = %+v, closed=%v", usage, closed)
	}

	if got := callDNSNamed(t, extension, "resolve", host, uint64(namespaceHandle), 0, 300); got != StatusInProgress {
		t.Fatalf("cleanup resolve = %v", got)
	}
	link := concreteNamespace(t, state).Link()
	account := state.Quotas()
	if err := instance.Close(); err != nil {
		t.Fatalf("close actual DNS instance: %v", err)
	}
	if _, exists := extension.instanceManager().ForInstance(instance); exists {
		t.Fatal("actual DNS state survived instance close")
	}
	if usage, closed := account.Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("instance close retained DNS quota = %+v, closed=%v", usage, closed)
	}
	if snapshot := link.Snapshot(); !snapshot.Closed || snapshot.IngressFrames != 0 || snapshot.EgressFrames != 0 {
		t.Fatalf("instance close retained DNS link = %+v", snapshot)
	}
}

func TestActualBackendGuestDNSFailureStatuses(t *testing.T) {
	for _, test := range []struct {
		name      string
		rcode     uint16
		truncated bool
		want      Status
	}{
		{name: "name not found", rcode: 3, want: StatusNameNotFound},
		{name: "server failure", rcode: 2, want: StatusTemporaryFailure},
		{name: "truncated without TCP fallback", truncated: true, want: StatusTemporaryFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			extension, instance, host := newActualGuestDNSInstance(t, byte(90+test.rcode))
			defer instance.Close()
			state, _ := extension.instanceManager().ForInstance(instance)
			namespaceHandle := actualGuestDNSNamespaceHandle(t, extension, host)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
			query := resolveActualGuestDNS(t, extension, host, namespaceHandle, request)
			txid, localPort := serviceActualGuestDNSQuery(t, extension, state, host)
			response := buildGuestDNSResponse(t, actualGuestDNSConfig(byte(90+test.rcode)), request, txid, localPort, test.rcode, test.truncated, nil)
			if err := concreteNamespace(t, state).Link().TryEnqueue(packetlink.Ingress, response); err != nil {
				t.Fatal(err)
			}
			pollActualGuestDNSUntil(t, extension, host, query, namespace.ReadyError)
			if got := callDNSNamed(t, extension, "next", host, uint64(query), 400); got != test.want {
				t.Fatalf("failure next = %v, want %v", got, test.want)
			}
			if got := callDNSNamed(t, extension, "close", host, uint64(query)); got != StatusOK {
				t.Fatalf("failure close = %v", got)
			}
		})
	}
}

func TestActualBackendGuestDNSTimeoutCancelPolicyKindsAndIsolation(t *testing.T) {
	extension, instance, host := newActualGuestDNSInstance(t, 101)
	defer instance.Close()
	state, _ := extension.instanceManager().ForInstance(instance)
	namespaceHandle := actualGuestDNSNamespaceHandle(t, extension, host)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	query := resolveActualGuestDNS(t, extension, host, namespaceHandle, request)
	_ = serviceActualGuestDNSQueryFrame(t, extension, state, host)
	pollActualGuestDNSUntil(t, extension, host, query, namespace.ReadyError)
	if got := callDNSNamed(t, extension, "next", host, uint64(query), 400); got != StatusTimedOut {
		t.Fatalf("actual DNS timeout = %v", got)
	}
	if got := callDNSNamed(t, extension, "close", host, uint64(query)); got != StatusOK {
		t.Fatalf("timeout close = %v", got)
	}

	query = resolveActualGuestDNS(t, extension, host, namespaceHandle, request)
	if got := callDNSNamed(t, extension, "next", host, uint64(namespaceHandle), 400); got != StatusBadHandle {
		t.Fatalf("wrong-kind DNS next = %v", got)
	}
	otherExtension, otherInstance, otherHost := newActualGuestDNSInstance(t, 102)
	defer otherInstance.Close()
	_ = actualGuestDNSNamespaceHandle(t, otherExtension, otherHost)
	if got := callDNSNamed(t, otherExtension, "next", otherHost, uint64(query), 400); got != StatusBadHandle {
		t.Fatalf("cross-instance DNS next = %v", got)
	}
	if got := callDNSNamed(t, otherExtension, "cancel", otherHost, uint64(query)); got != StatusBadHandle {
		t.Fatalf("cross-instance DNS cancel = %v", got)
	}
	if got := callDNSNamed(t, extension, "cancel", host, uint64(query)); got != StatusOK {
		t.Fatalf("actual DNS cancel = %v", got)
	}
	pollActualGuestDNSUntil(t, extension, host, query, namespace.ReadyError)
	if got := callDNSNamed(t, extension, "next", host, uint64(query), 400); got != StatusCanceled {
		t.Fatalf("canceled actual DNS next = %v", got)
	}
	if got := callDNSNamed(t, extension, "close", host, uint64(query)); got != StatusOK {
		t.Fatalf("canceled actual DNS close = %v", got)
	}
	if got := callDNSNamed(t, extension, "next", host, uint64(query), 400); got != StatusBadHandle {
		t.Fatalf("stale actual DNS next = %v", got)
	}

	denied := namespace.DNSRequest{Name: "denied.invalid", Types: namespace.DNSRecordsA}
	if !abi.EncodeDNSQueryV1(host.memory, 0, denied) {
		t.Fatal("encode denied DNS query")
	}
	before, _ := state.Quotas().Snapshot()
	if got := callDNSNamed(t, extension, "resolve", host, uint64(namespaceHandle), 0, 300); got != StatusAccessDenied {
		t.Fatalf("actual DNS policy denial = %v", got)
	}
	if after, _ := state.Quotas().Snapshot(); after != before {
		t.Fatalf("policy-denied DNS changed quota: before %+v after %+v", before, after)
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

func callRegisteredDNS(t testing.TB, runtime *wago.Runtime, name string, host udpHostModule, params ...uint64) Status {
	t.Helper()
	fn, ok := runtime.HostImports()[DNSModule+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("registered DNS binding %q missing", name)
	}
	return callDNS(fn, host, params...)
}

func callDNSNamed(t testing.TB, extension *Extension, name string, host udpHostModule, params ...uint64) Status {
	t.Helper()
	for _, binding := range extension.dnsBindings() {
		if binding.name == name {
			return callDNS(binding.fn, host, params...)
		}
	}
	t.Fatalf("DNS binding %q missing", name)
	return StatusOther
}

func actualGuestDNSConfig(id byte) Config {
	limits := QuotaLimits{Resources: 2, DNSResources: 1, QueuedBytes: 8192, DNSWork: 2, ServiceUnits: 64}
	ready := ReadinessConfig{MaxRegistrations: 2}
	return Config{
		Policy: PolicyConfig{Rules: []PolicyRule{{
			Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportDNS},
			Directions: []PolicyDirection{PolicyOutbound}, DNSSuffixes: []string{"example.com"},
		}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &StaticIPv4Config{
			Hostname: "guest-dns", RandSeed: int64(id),
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, id}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 53},
			IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4},
			DNS: DNSConfig{
				Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 1, MaxRecords: 4,
				MaxResponseBytes: 512, MaxAttempts: 1, RetryServiceAttempts: 1,
			},
		},
	}
}

func newActualGuestDNSInstance(t testing.TB, id byte) (*Extension, *wago.Instance, udpHostModule) {
	t.Helper()
	extension := Init(actualGuestDNSConfig(id))
	runtime := runtimeForExtension(t, extension)
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("compile empty DNS guest: %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("instantiate DNS guest: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return extension, instance, udpHostModule{instance: instance, memory: make([]byte, 4096)}
}

func actualGuestDNSNamespaceHandle(t testing.TB, extension *Extension, host udpHostModule) resource.Handle {
	t.Helper()
	if got := callDNSNamed(t, extension, "namespace_default", host, 3000); got != StatusOK {
		t.Fatalf("DNS namespace_default = %v", got)
	}
	return resource.Handle(binary.LittleEndian.Uint64(host.memory[3000:3008]))
}

func resolveActualGuestDNS(t testing.TB, extension *Extension, host udpHostModule, namespaceHandle resource.Handle, request namespace.DNSRequest) resource.Handle {
	t.Helper()
	if !abi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatalf("encode DNS request %+v", request)
	}
	if got := callDNSNamed(t, extension, "resolve", host, uint64(namespaceHandle), 0, 300); got != StatusInProgress {
		t.Fatalf("DNS resolve %+v = %v", request, got)
	}
	return resource.Handle(binary.LittleEndian.Uint64(host.memory[300:308]))
}

func serviceActualGuestDNSQuery(t testing.TB, extension *Extension, state *instance.State, host udpHostModule) (uint16, uint16) {
	t.Helper()
	frame := serviceActualGuestDNSQueryFrame(t, extension, state, host)
	if len(frame) < 14+20+8+12 {
		t.Fatalf("short DNS query frame: %d", len(frame))
	}
	ipHeaderBytes := int(frame[14]&0x0f) * 4
	udpOffset := 14 + ipHeaderBytes
	if ipHeaderBytes < 20 || udpOffset+10 > len(frame) {
		t.Fatalf("invalid DNS query IPv4 header: %d", ipHeaderBytes)
	}
	return binary.BigEndian.Uint16(frame[udpOffset+8 : udpOffset+10]), binary.BigEndian.Uint16(frame[udpOffset : udpOffset+2])
}

func serviceActualGuestDNSQueryFrame(t testing.TB, extension *Extension, state *instance.State, host udpHostModule) []byte {
	t.Helper()
	writePollBudget(host.memory, 1000, 2, 2, 1, 1, 1514, 2)
	if got := callDNSNamed(t, extension, "poll", host, 1100, 2, 1000, 1200); got != StatusOK {
		t.Fatalf("DNS egress poll = %v", got)
	}
	result := decodePollResult(host.memory, 1200)
	if result[2] != 1 || result[3] != 1 {
		t.Fatalf("DNS egress poll report = %v", result)
	}
	frame := make([]byte, 1514)
	dequeued, err := concreteNamespace(t, state).Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !dequeued.Ready || dequeued.Truncated {
		t.Fatalf("dequeue DNS query = %+v, %v", dequeued, err)
	}
	return append([]byte(nil), frame[:dequeued.FrameBytes]...)
}

func pollActualGuestDNSUntil(t testing.TB, extension *Extension, host udpHostModule, handle resource.Handle, readiness namespace.Readiness) {
	t.Helper()
	for range 6 {
		writePollBudget(host.memory, 1000, 2, 2, 1, 1, 1514, 2)
		status := callDNSNamed(t, extension, "poll", host, 1100, 2, 1000, 1200)
		if status != StatusOK && status != StatusAgain {
			t.Fatalf("DNS readiness poll = %v", status)
		}
		report := decodePollResult(host.memory, 1200)
		if report[0] > 2 || report[1] > 2 || report[2] > 1 || report[3] > 1 {
			t.Fatalf("unbounded DNS poll report = %v", report)
		}
		if hasPollEvent(decodePollEvents(host.memory, 1100, report[0]), handle, readiness) {
			return
		}
	}
	t.Fatalf("DNS handle %v did not reach readiness %v", handle, readiness)
}

type guestDNSWireAnswer struct {
	name  string
	typ   uint16
	ttl   uint32
	data  []byte
	cname string
}

func buildGuestDNSResponse(t testing.TB, config Config, request namespace.DNSRequest, txid, destinationPort, rcode uint16, truncated bool, answers []guestDNSWireAnswer) []byte {
	t.Helper()
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[0:2], txid)
	flags := uint16(1 << 15)
	if truncated {
		flags |= 1 << 9
	}
	flags |= rcode & 0x0f
	binary.BigEndian.PutUint16(payload[2:4], flags)
	questionCount := uint16(0)
	if request.Types&namespace.DNSRecordsA != 0 {
		questionCount++
		payload = appendDNSWireQuestion(payload, request.Name, 1)
	}
	if request.Types&namespace.DNSRecordsAAAA != 0 {
		questionCount++
		payload = appendDNSWireQuestion(payload, request.Name, 28)
	}
	binary.BigEndian.PutUint16(payload[4:6], questionCount)
	binary.BigEndian.PutUint16(payload[6:8], uint16(len(answers)))
	for _, answer := range answers {
		payload = appendDNSWireName(payload, answer.name)
		payload = binary.BigEndian.AppendUint16(payload, answer.typ)
		payload = binary.BigEndian.AppendUint16(payload, 1)
		payload = binary.BigEndian.AppendUint32(payload, answer.ttl)
		data := answer.data
		if answer.typ == 5 {
			data = appendDNSWireName(nil, answer.cname)
		}
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(data)))
		payload = append(payload, data...)
	}
	if len(payload) > 512 {
		t.Fatalf("test DNS response is too large: %d", len(payload))
	}

	static := config.StaticIPv4
	frame := make([]byte, 14+20+8+len(payload))
	copy(frame[0:6], static.HardwareAddress[:])
	copy(frame[6:12], static.GatewayHardwareAddress[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], static.DNS.Server.AsSlice())
	copy(ip[16:20], static.IPv4Address.AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip))
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	return frame
}

func appendDNSWireQuestion(dst []byte, name string, typ uint16) []byte {
	dst = appendDNSWireName(dst, name)
	dst = binary.BigEndian.AppendUint16(dst, typ)
	return binary.BigEndian.AppendUint16(dst, 1)
}

func appendDNSWireName(dst []byte, name string) []byte {
	for len(name) != 0 {
		label, rest, found := bytes.Cut([]byte(name), []byte{'.'})
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
		if !found {
			break
		}
		name = string(rest)
	}
	return append(dst, 0)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func decodeGuestDNSRecord(t testing.TB, memory []byte, ptr uint32) namespace.DNSRecord {
	t.Helper()
	name, ok := abi.DecodeDNSNameV1(memory, ptr)
	if !ok {
		t.Fatal("decode guest DNS record name")
	}
	typ := binary.LittleEndian.Uint32(memory[ptr+260 : ptr+264])
	record := namespace.DNSRecord{Name: name, TTLSeconds: binary.LittleEndian.Uint32(memory[ptr+264 : ptr+268])}
	switch typ {
	case abi.DNSRecordTypeA:
		record.Type = namespace.DNSRecordA
		endpoint, ok := abi.DecodeEndpointV1(memory, ptr+268)
		if !ok {
			t.Fatal("decode guest DNS A address")
		}
		record.Address = endpoint.Address
	case abi.DNSRecordTypeAAAA:
		record.Type = namespace.DNSRecordAAAA
		endpoint, ok := abi.DecodeEndpointV1(memory, ptr+268)
		if !ok {
			t.Fatal("decode guest DNS AAAA address")
		}
		record.Address = endpoint.Address
	case abi.DNSRecordTypeCNAME:
		record.Type = namespace.DNSRecordCNAME
		canonical, ok := abi.DecodeDNSNameV1(memory, ptr+300)
		if !ok {
			t.Fatal("decode guest DNS CNAME")
		}
		record.CanonicalName = canonical
	default:
		t.Fatalf("unknown guest DNS record type %d", typ)
	}
	return record
}
