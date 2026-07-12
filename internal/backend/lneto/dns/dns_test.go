package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	lnetodns "github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestBuildDNSQueryPacketDirectEncoding(t *testing.T) {
	request := namespace.DNSRequest{Name: "service.api.example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	packet, err := buildDNSQueryPacket(request, 0x1234, 1232)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := lnetodns.NewFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if frame.TxID() != 0x1234 || frame.Flags().IsResponse() || frame.QDCount() != 2 || frame.ANCount() != 0 || frame.NSCount() != 0 || frame.ARCount() != 1 {
		t.Fatalf("query header = txid=%x flags=%x counts=%d/%d/%d/%d", frame.TxID(), frame.Flags(), frame.QDCount(), frame.ANCount(), frame.NSCount(), frame.ARCount())
	}
	offset, err := validateDNSQuestions(packet, lnetodns.SizeHeader, frame.QDCount(), request)
	if err != nil {
		t.Fatal(err)
	}
	if offset+11 != len(packet) || packet[offset] != 0 || binary.BigEndian.Uint16(packet[offset+1:offset+3]) != 41 || binary.BigEndian.Uint16(packet[offset+3:offset+5]) != 1232 {
		t.Fatalf("EDNS resource = %x", packet[offset:])
	}
	for _, value := range packet[offset+5:] {
		if value != 0 {
			t.Fatalf("nonzero EDNS tail: %x", packet[offset:])
		}
	}
}

func TestBuildDNSQueryPacketIntoUsesCallerStorage(t *testing.T) {
	request := namespace.DNSRequest{Name: "service.api.example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	var storage [dnsQueryPacketCapacity]byte
	for i := range storage {
		storage[i] = 0xff
	}
	packet, err := buildDNSQueryPacketInto(storage[:], request, 0x5678, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) == 0 || &packet[0] != &storage[0] {
		t.Fatal("query packet did not retain caller-owned storage")
	}
	frame, err := lnetodns.NewFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if frame.TxID() != 0x5678 || frame.QDCount() != 2 || frame.ARCount() != 1 {
		t.Fatalf("query header = txid=%x counts=%d/%d", frame.TxID(), frame.QDCount(), frame.ARCount())
	}
	if _, err := buildDNSQueryPacketInto(storage[:len(packet)-1], request, 1, 512); !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short storage error = %v", err)
	}
}

func TestBuildDNSQueryPacketIntoFitsMaximumCanonicalName(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	request := namespace.DNSRequest{Name: name, Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	if !request.Valid() || len(name) != 253 {
		t.Fatalf("maximum request validity = %v, length=%d", request.Valid(), len(name))
	}
	var storage [dnsQueryPacketCapacity]byte
	packet, err := buildDNSQueryPacketInto(storage[:], request, 0xabcd, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != len(storage) || &packet[0] != &storage[0] {
		t.Fatalf("maximum packet length = %d, capacity=%d", len(packet), len(storage))
	}
	frame, err := lnetodns.NewFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateDNSQuestions(packet, lnetodns.SizeHeader, frame.QDCount(), request); err != nil {
		t.Fatal(err)
	}
}

func TestDNSNameInterningReusesRequestAndBoundedScratch(t *testing.T) {
	storage := make([]string, 1)
	count := 0
	request := "example.com"
	name, err := internDNSName([]byte(request), request, storage, &count)
	if err != nil || name != request || count != 0 {
		t.Fatalf("request intern = %q, count=%d, err=%v", name, count, err)
	}
	first, err := internDNSName([]byte("alias.example.com"), request, storage, &count)
	if err != nil || count != 1 {
		t.Fatalf("first alias intern = %q, count=%d, err=%v", first, count, err)
	}
	second, err := internDNSName([]byte("alias.example.com"), request, storage, &count)
	if err != nil || second != first || count != 1 {
		t.Fatalf("reused alias intern = %q, count=%d, err=%v", second, count, err)
	}
	if _, err := internDNSName([]byte("other.example.com"), request, storage, &count); err == nil {
		t.Fatal("bounded name scratch accepted a second unique name")
	}
}

func TestDNSBoundedQueryRecordsAndQuotaLifecycle(t *testing.T) {
	config := dnsTestConfig(t, 41)
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	resource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress || resource == nil {
		t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
	}
	query := resource.(*dnsQuery)
	if len(query.packet) == 0 || &query.packet[0] != &query.packetStorage[0] {
		t.Fatal("live query packet does not use embedded storage")
	}
	if cap(query.records) != int(config.DNS.MaxRecords) || cap(query.records) > len(query.recordStorage) {
		t.Fatalf("live query records capacity = %d", cap(query.records))
	}
	if got := query.Readiness(); got != 0 {
		t.Fatalf("initial readiness = %v", got)
	}
	if _, next, err := query.TryNext(); err != nil || next != namespace.DNSNextWouldBlock {
		t.Fatalf("initial next = %v, %v", next, err)
	}
	usage, closed := config.Quotas.Snapshot()
	if closed || usage.Resources != 1 || usage.DNSResources != 1 || usage.DNSWork != 2 || usage.QueuedBytes != dnsRetainedBytes(config.DNS) {
		t.Fatalf("in-flight quota = %+v, closed=%v", usage, closed)
	}

	outgoing := serviceDNSPacket(t, ns)
	txid, localPort := dnsPacketIdentity(t, outgoing)
	response := buildDNSResponseFrame(t, config, txid, localPort, request.Name)
	if err := ns.Link().TryEnqueue(packetlink.Ingress, response); err != nil {
		t.Fatal(err)
	}
	setNextIngress(ns, true)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report != (namespace.ServiceReport{Packets: 1, Bytes: uint32(len(response)), Operations: 1}) {
		t.Fatalf("response service = %+v, %v, %v", report, progress, err)
	}
	if got := query.Readiness(); got != namespace.ReadyDNSResult {
		t.Fatalf("completed readiness = %v", got)
	}

	want := []namespace.DNSRecord{
		{Name: "example.com", Type: namespace.DNSRecordCNAME, TTLSeconds: 60, CanonicalName: "canonical.example.com"},
		{Name: "canonical.example.com", Type: namespace.DNSRecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.99")},
		{Name: "canonical.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 180, Address: netip.MustParseAddr("2001:db8::99")},
	}
	for i, expected := range want {
		record, next, err := query.TryNext()
		if err != nil || next != namespace.DNSNextReady || record != expected {
			t.Fatalf("record %d = %+v, %v, %v; want %+v", i, record, next, err, expected)
		}
	}
	if _, next, err := query.TryNext(); err != nil || next != namespace.DNSNextEOF {
		t.Fatalf("EOF = %v, %v", next, err)
	}
	usage, _ = config.Quotas.Snapshot()
	if usage.DNSWork != 0 || usage.Resources != 1 || usage.DNSResources != 1 || usage.QueuedBytes == 0 {
		t.Fatalf("completed quota = %+v", usage)
	}
	workReset := query.work.ResetReleased()
	if workReset {
		t.Fatalf("completed query retained work graph state: reset=%v", workReset)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed query retained quota = %+v", usage)
	}
	retainedReset := query.retained.ResetReleased()
	workReset = query.work.ResetReleased()
	if retainedReset || workReset || query.request != (namespace.DNSRequest{}) || query.packet != nil || query.records != nil || query.failure != nil || query.cursor != 0 {
		t.Fatalf("closed query retained graph state: retained_reset=%v work_reset=%v request=%+v packet=%v records=%v failure=%v cursor=%d", retainedReset, workReset, query.request, query.packet != nil, query.records != nil, query.failure, query.cursor)
	}
	if got := query.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed readiness = %v", got)
	}
}

func TestResolveCloseReusesOverflowRecordBacking(t *testing.T) {
	config := dnsTestConfig(t, 41)
	config.DNS.MaxQueries = 1
	config.DNS.MaxRecords = inlineDNSRecordCapacity + 1
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	allocs := testing.AllocsPerRun(1000, func() {
		value, progress, err := ns.TryResolve(request)
		if err != nil || progress != namespace.ProgressInProgress {
			panic(err)
		}
		if err := value.Close(); err != nil {
			panic(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("resolve/close allocations = %v, want <= 1", allocs)
	}
}

func TestDNSRetryTimeoutPolicyLimitsAndReuse(t *testing.T) {
	config := dnsTestConfig(t, 42)
	config.DNS.MaxQueries = 1
	config.DNS.MaxAttempts = 2
	config.DNS.RetryServiceAttempts = 1
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	resource, _, err := ns.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	query := resource.(*dnsQuery)
	if _, _, err := ns.TryResolve(request); requireFailure(t, err) != namespace.FailureResourceLimit {
		t.Fatalf("second query error = %v", err)
	}
	if _, _, err := ns.TryResolve(namespace.DNSRequest{Name: "denied.example", Types: namespace.DNSRecordsA}); requireFailure(t, err) != namespace.FailureAccessDenied {
		t.Fatalf("denied query error = %v", err)
	}

	_ = serviceDNSPacket(t, ns)
	maintenance := serviceDNSMaintenance(t, ns)
	if maintenance != (namespace.ServiceReport{Operations: 1}) {
		t.Fatalf("retry maintenance = %+v", maintenance)
	}
	_ = serviceDNSPacket(t, ns)
	maintenance = serviceDNSMaintenance(t, ns)
	if maintenance != (namespace.ServiceReport{Operations: 1}) {
		t.Fatalf("timeout maintenance = %+v", maintenance)
	}
	if got := query.Readiness(); got != namespace.ReadyError {
		t.Fatalf("timeout readiness = %v", got)
	}
	if _, _, err := query.TryNext(); requireFailure(t, err) != namespace.FailureTimedOut {
		t.Fatalf("timeout result error = %v", err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage.DNSWork != 0 || usage.DNSResources != 1 {
		t.Fatalf("timeout quota = %+v", usage)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	reusedResource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress || reusedResource == query {
		t.Fatalf("query reuse = %T, %v, %v", reusedResource, progress, err)
	}
	reused := reusedResource.(*dnsQuery)
	if err := reused.Cancel(); err != nil {
		t.Fatal(err)
	}
	if got := reused.Readiness(); got != namespace.ReadyError {
		t.Fatalf("canceled readiness = %v", got)
	}
	if _, _, err := reused.TryNext(); requireFailure(t, err) != namespace.FailureCanceled {
		t.Fatalf("canceled result error = %v", err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage.DNSWork != 0 || usage.DNSResources != 1 {
		t.Fatalf("canceled quota = %+v", usage)
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSTerminalCompletionRetiresTransportAndIgnoresLateResponses(t *testing.T) {
	config := dnsTestConfig(t, 44)
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	resource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
	}
	query := resource.(*dnsQuery)
	outgoing := serviceDNSPacket(t, ns)
	txid, localPort := dnsPacketIdentity(t, outgoing)
	serviceDNSIngressFrame(t, ns, buildDNSResponseFrame(t, config, txid, localPort, request.Name))
	if query.state != dnsQueryDone || query.Readiness() != namespace.ReadyDNSResult {
		t.Fatalf("completion state = %v, readiness=%v", query.state, query.Readiness())
	}
	ns.core.Lock()
	leaseCount := ns.core.UDPPortLeaseCountLocked()
	stillMapped := ns.adapter.byPort[localPort] != nil
	ns.core.Unlock()
	if leaseCount != 0 || stillMapped || query.localPort != 0 || query.portLease.UDPPort() != 0 {
		t.Fatalf("completion transport retained lease=%d mapped=%v local_port=%d lease_port=%d", leaseCount, stillMapped, query.localPort, query.portLease.UDPPort())
	}
	before := append([]namespace.DNSRecord(nil), query.records...)
	serviceDNSIngressFrame(t, ns, buildDNSResponseFrameWithRecords(t, config, txid, localPort, request.Name, []namespace.DNSRecord{{
		Name: "example.com", Type: namespace.DNSRecordA, TTLSeconds: 1, Address: netip.MustParseAddr("192.0.2.1"),
	}}))
	if !reflect.DeepEqual(query.records, before) {
		t.Fatalf("late response mutated committed records: got %+v want %+v", query.records, before)
	}
	first, next, err := query.TryNext()
	if err != nil || next != namespace.DNSNextReady || first != before[0] {
		t.Fatalf("first record = %+v, %v, %v; want %+v", first, next, err, before[0])
	}
	serviceDNSIngressFrame(t, ns, buildDNSResponseFrameWithRecords(t, config, txid, localPort, request.Name, []namespace.DNSRecord{{
		Name: "example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 1, Address: netip.MustParseAddr("2001:db8::1"),
	}}))
	for i, want := range before[1:] {
		record, next, err := query.TryNext()
		if err != nil || next != namespace.DNSNextReady || record != want {
			t.Fatalf("remaining record %d = %+v, %v, %v; want %+v", i, record, next, err, want)
		}
	}
	if _, next, err := query.TryNext(); err != nil || next != namespace.DNSNextEOF {
		t.Fatalf("EOF = %v, %v", next, err)
	}
	ns.adapter.nextPort = localPort
	reusedResource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("reused resolve = %T, %v, %v", reusedResource, progress, err)
	}
	reused := reusedResource.(*dnsQuery)
	if reused.localPort != localPort {
		t.Fatalf("reused local port = %d, want %d", reused.localPort, localPort)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if err := query.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSTerminalFailuresRetireTransportImmediately(t *testing.T) {
	for _, test := range []struct {
		name        string
		expected    namespace.Failure
		prepare     func(*testing.T, *testNamespace, *dnsQuery, namespaceTestConfig)
		terminalize func(*testing.T, *testNamespace, *dnsQuery, namespaceTestConfig)
	}{
		{
			name:     "canceled",
			expected: namespace.FailureCanceled,
			terminalize: func(t *testing.T, _ *testNamespace, query *dnsQuery, _ namespaceTestConfig) {
				if err := query.Cancel(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:     "timed out",
			expected: namespace.FailureTimedOut,
			prepare: func(t *testing.T, ns *testNamespace, _ *dnsQuery, _ namespaceTestConfig) {
				_ = serviceDNSPacket(t, ns)
				if report := serviceDNSMaintenance(t, ns); report != (namespace.ServiceReport{Operations: 1}) {
					t.Fatalf("retry maintenance = %+v", report)
				}
				_ = serviceDNSPacket(t, ns)
			},
			terminalize: func(t *testing.T, ns *testNamespace, _ *dnsQuery, _ namespaceTestConfig) {
				if report := serviceDNSMaintenance(t, ns); report != (namespace.ServiceReport{Operations: 1}) {
					t.Fatalf("timeout maintenance = %+v", report)
				}
			},
		},
		{
			name:     "parser failure",
			expected: namespace.FailureIO,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := dnsTestConfig(t, 45)
			config.DNS.MaxQueries = 1
			config.DNS.MaxAttempts = 2
			config.DNS.RetryServiceAttempts = 1
			ns := newTestNamespace(t, config)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
			resource, progress, err := ns.TryResolve(request)
			if err != nil || progress != namespace.ProgressInProgress {
				t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
			}
			query := resource.(*dnsQuery)
			localPort := query.localPort
			if test.prepare != nil {
				test.prepare(t, ns, query, config)
			}
			if test.name == "parser failure" {
				outgoing := serviceDNSPacket(t, ns)
				txid, destinationPort := dnsPacketIdentity(t, outgoing)
				message := lnetodns.Message{Questions: []lnetodns.Question{{Name: lnetodns.MustNewName(request.Name), Type: lnetodns.TypeA, Class: lnetodns.ClassINET}}}
				serviceDNSIngressFrame(t, ns, buildDNSFrame(t, config, txid, destinationPort, message, lnetodns.HeaderFlags(1<<15)))
			} else {
				test.terminalize(t, ns, query, config)
			}
			if got := query.Readiness(); got != namespace.ReadyError {
				t.Fatalf("terminal readiness = %v", got)
			}
			ns.core.Lock()
			leaseCount := ns.core.UDPPortLeaseCountLocked()
			stillMapped := ns.adapter.byPort[localPort] != nil
			ns.core.Unlock()
			if leaseCount != 0 || stillMapped || query.localPort != 0 || query.portLease.UDPPort() != 0 {
				t.Fatalf("terminal transport retained lease=%d mapped=%v local_port=%d lease_port=%d", leaseCount, stillMapped, query.localPort, query.portLease.UDPPort())
			}
			if _, _, err := query.TryNext(); requireFailure(t, err) != test.expected {
				t.Fatalf("terminal failure = %v, want %v", err, test.expected)
			}
			if err := query.Close(); err != nil {
				t.Fatal(err)
			}
			if err := query.Close(); err != nil {
				t.Fatalf("second close = %v", err)
			}
		})
	}
}

func TestDNSResponseFailureMappingAndRecordBound(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	name := lnetodns.MustNewName(request.Name)
	for _, test := range []struct {
		name    string
		flags   lnetodns.HeaderFlags
		answers []lnetodns.Resource
		limit   int
		want    namespace.Failure
	}{
		{name: "not found", flags: lnetodns.HeaderFlags(1<<15) | lnetodns.HeaderFlags(lnetodns.RCodeNameError), limit: 1, want: namespace.FailureNameNotFound},
		{name: "truncated", flags: lnetodns.HeaderFlags(1<<15 | 1<<9), limit: 1, want: namespace.FailureTemporary},
		{name: "record limit", flags: lnetodns.HeaderFlags(1 << 15), answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
			lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 2}),
		}, limit: 1, want: namespace.FailureResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := lnetodns.Message{Questions: []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}}, Answers: test.answers}
			payload, err := message.AppendTo(nil, 7, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			_, response, failure, err := parseDNSResponse(payload, 7, request, test.limit)
			if !response || err == nil || failure != test.want {
				t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
			}
		})
	}
}

func TestDNSResponseRequiresExactEchoedQuestions(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	name := lnetodns.MustNewName(request.Name)
	valid := []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}
	other := lnetodns.MustNewName("other.example.com")
	for _, test := range []struct {
		name      string
		questions []lnetodns.Question
		flags     lnetodns.HeaderFlags
	}{
		{name: "missing type", questions: valid[:1], flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "extra type", questions: append(append([]lnetodns.Question(nil), valid...), valid[0]), flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong name", questions: []lnetodns.Question{{Name: other, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}, valid[1]}, flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong order", questions: []lnetodns.Question{valid[1], valid[0]}, flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong class", questions: []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassCHAOS}, valid[1]}, flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong opcode", questions: valid, flags: lnetodns.HeaderFlags(1<<15) | lnetodns.HeaderFlags(lnetodns.OpCodeStatus<<11)},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := (&lnetodns.Message{Questions: test.questions}).AppendTo(nil, 11, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			_, response, failure, err := parseDNSResponse(payload, 11, request, 8)
			if !response || failure != namespace.FailureIO || err == nil {
				t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
			}
		})
	}
}

func TestDNSResponseSelectsUniqueReachableChainAndRequestedTypes(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	name := lnetodns.MustNewName(request.Name)
	alias := lnetodns.MustNewName("alias.example.com")
	terminal := lnetodns.MustNewName("terminal.example.com")
	unrelated := lnetodns.MustNewName("unrelated.example.com")
	aliasData, _ := alias.AppendTo(nil)
	terminalData, _ := terminal.AppendTo(nil)
	message := lnetodns.Message{
		Questions: []lnetodns.Question{
			{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
			{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
		},
		Answers: []lnetodns.Resource{
			lnetodns.NewResource(unrelated, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 10, aliasData),
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 99, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeCNAME, lnetodns.ClassINET, 20, terminalData),
			lnetodns.NewResource(alias, lnetodns.TypeA, lnetodns.ClassINET, 30, []byte{192, 0, 2, 30}),
			lnetodns.NewResource(terminal, lnetodns.TypeA, lnetodns.ClassINET, 40, []byte{192, 0, 2, 40}),
			lnetodns.NewResource(terminal, lnetodns.TypeA, lnetodns.ClassINET, 41, []byte{192, 0, 2, 40}),
			lnetodns.NewResource(terminal, lnetodns.TypeAAAA, lnetodns.ClassINET, 50, netip.MustParseAddr("2001:db8::40").AsSlice()),
		},
	}
	payload, err := message.AppendTo(nil, 12, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		t.Fatal(err)
	}
	records, response, failure, err := parseDNSResponse(payload, 12, request, 4)
	if err != nil || !response || failure != 0 {
		t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
	}
	want := []namespace.DNSRecord{
		{Name: request.Name, Type: namespace.DNSRecordCNAME, TTLSeconds: 10, CanonicalName: "alias.example.com"},
		{Name: "alias.example.com", Type: namespace.DNSRecordCNAME, TTLSeconds: 20, CanonicalName: "terminal.example.com"},
		{Name: "terminal.example.com", Type: namespace.DNSRecordA, TTLSeconds: 40, Address: netip.MustParseAddr("192.0.2.40")},
		{Name: "terminal.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 50, Address: netip.MustParseAddr("2001:db8::40")},
	}
	if len(records) != len(want) {
		t.Fatalf("records = %+v", records)
	}
	for i := range want {
		if records[i] != want[i] {
			t.Fatalf("record %d = %+v, want %+v", i, records[i], want[i])
		}
	}

	aOnly := namespace.DNSRequest{Name: request.Name, Types: namespace.DNSRecordsA}
	unrequested, err := (&lnetodns.Message{
		Questions: []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}},
		Answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeAAAA, lnetodns.ClassINET, 1, netip.MustParseAddr("2001:db8::1").AsSlice()),
			lnetodns.NewResource(unrelated, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
		},
	}).AppendTo(nil, 16, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		t.Fatal(err)
	}
	if records, _, failure, err := parseDNSResponse(unrequested, 16, aOnly, 4); err != nil || failure != 0 || len(records) != 0 {
		t.Fatalf("unrequested/irrelevant records = %+v, failure %v, err %v", records, failure, err)
	}
}

func TestDNSResponseRejectsCNAMEConflictLoopAndMalformedWire(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	name := lnetodns.MustNewName(request.Name)
	alias := lnetodns.MustNewName("alias.example.com")
	other := lnetodns.MustNewName("other.example.com")
	aliasData, _ := alias.AppendTo(nil)
	otherData, _ := other.AppendTo(nil)
	nameData, _ := name.AppendTo(nil)
	question := []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}}
	for _, test := range []struct {
		name    string
		answers []lnetodns.Resource
		limit   int
		want    namespace.Failure
	}{
		{name: "conflicting cname", answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, aliasData),
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, otherData),
		}, limit: 4, want: namespace.FailureIO},
		{name: "cname loop", answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, nameData),
		}, limit: 4, want: namespace.FailureIO},
		{name: "chain exceeds record limit", answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
		}, limit: 1, want: namespace.FailureResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := (&lnetodns.Message{Questions: question, Answers: test.answers}).AppendTo(nil, 13, lnetodns.HeaderFlags(1<<15))
			if err != nil {
				t.Fatal(err)
			}
			_, response, failure, err := parseDNSResponse(payload, 13, request, test.limit)
			if !response || failure != test.want || err == nil {
				t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
			}
		})
	}

	selfPointer := make([]byte, lnetodns.SizeHeader+6)
	binary.BigEndian.PutUint16(selfPointer[0:2], 14)
	binary.BigEndian.PutUint16(selfPointer[2:4], 1<<15)
	binary.BigEndian.PutUint16(selfPointer[4:6], 1)
	selfPointer[12], selfPointer[13] = 0xc0, 0x0c
	binary.BigEndian.PutUint16(selfPointer[14:16], uint16(lnetodns.TypeA))
	binary.BigEndian.PutUint16(selfPointer[16:18], uint16(lnetodns.ClassINET))
	if _, response, failure, err := parseDNSResponse(selfPointer, 14, request, 4); !response || failure != namespace.FailureIO || err == nil {
		t.Fatalf("self pointer = response %v, failure %v, err %v", response, failure, err)
	}

	valid, err := (&lnetodns.Message{Questions: question, Answers: []lnetodns.Resource{
		lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
	}}).AppendTo(nil, 15, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{valid[:len(valid)-1], append(append([]byte(nil), valid...), 0)} {
		if _, response, failure, err := parseDNSResponse(malformed, 15, request, 4); !response || failure != namespace.FailureIO || err == nil {
			t.Fatalf("malformed resource = response %v, failure %v, err %v", response, failure, err)
		}
	}
}

func FuzzDNSWireResponse(f *testing.F) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	name := lnetodns.MustNewName(request.Name)
	seed, err := (&lnetodns.Message{Questions: []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}, Answers: []lnetodns.Resource{
		lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
	}}).AppendTo(nil, 77, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		f.Fatal(err)
	}
	compressed, err := (&lnetodns.Message{Questions: []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}}).AppendTo(nil, 77, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		f.Fatal(err)
	}
	binary.BigEndian.PutUint16(compressed[6:8], 1)
	compressed = append(compressed, 0xc0, 0x0c, 0, byte(lnetodns.TypeA), 0, byte(lnetodns.ClassINET), 0, 0, 0, 1, 0, 4, 192, 0, 2, 1)
	f.Add(seed)
	f.Add(compressed)
	f.Add([]byte{0, 77, 0x80})
	f.Add(make([]byte, lnetodns.SizeHeader))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 2048 {
			payload = payload[:2048]
		}
		records, _, _, _ := parseDNSResponse(payload, 77, request, 8)
		if len(records) > 8 {
			t.Fatalf("returned %d records", len(records))
		}
		current := request.Name
		seen := make(map[namespace.DNSRecord]struct{}, len(records))
		for _, record := range records {
			if !record.Valid() || record.Name != current {
				t.Fatalf("invalid or unreachable record %+v after %q", record, current)
			}
			key := record
			key.TTLSeconds = 0
			if _, exists := seen[key]; exists {
				t.Fatalf("duplicate record %+v", record)
			}
			seen[key] = struct{}{}
			if record.Type == namespace.DNSRecordCNAME {
				current = record.CanonicalName
			}
		}
	})
}

func TestDNSConcurrentOperationsAndNamespaceClose(t *testing.T) {
	config := dnsTestConfig(t, 43)
	ns := newTestNamespace(t, config)
	resource, _, err := ns.TryResolve(namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
	if err != nil {
		t.Fatal(err)
	}
	query := resource.(*dnsQuery)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 200 {
				_, _, _ = query.TryNext()
				if !query.Readiness().Valid() {
					t.Error("invalid concurrent DNS readiness")
					return
				}
			}
		}()
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if got := query.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed query readiness = %v", got)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close retained DNS quota = %+v", usage)
	}
}

type namespaceTestConfig struct {
	Hostname               string
	RandSeed               int64
	HardwareAddress        [6]byte
	GatewayHardwareAddress [6]byte
	IPv4Address            netip.Addr
	MTU                    uint16
	Link                   packetlink.Config
	DNS                    Config
	Policy                 *policy.Policy
	Quotas                 *quota.Account
}

type testNamespace struct {
	core               *lnetocore.Namespace
	adapter            *Adapter
	requiredFrameBytes int
}

func newTestNamespace(t testing.TB, config namespaceTestConfig) *testNamespace {
	t.Helper()
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: config.Hostname, RandSeed: config.RandSeed,
		HardwareAddress: config.HardwareAddress, GatewayHardwareAddress: config.GatewayHardwareAddress,
		IPv4Address: config.IPv4Address, MTU: config.MTU, Link: config.Link,
		Policy: config.Policy, Quotas: config.Quotas,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(common, config.DNS)
	if err != nil {
		_ = common.Close()
		t.Fatal(err)
	}
	ns := &testNamespace{core: common, adapter: adapter, requiredFrameBytes: int(config.MTU) + 14}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func (n *testNamespace) TryResolve(request namespace.DNSRequest) (namespace.Resource, namespace.Progress, error) {
	return n.adapter.TryResolve(request)
}

func (n *testNamespace) TryService(budget namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return n.core.TryService(budget)
}

func (n *testNamespace) Link() *packetlink.Link { return n.core.Link() }
func (n *testNamespace) Close() error           { return n.core.Close() }

func setNextIngress(n *testNamespace, next bool) {
	n.core.Lock()
	n.core.SetNextIngressLocked(next)
	n.core.Unlock()
}

func requireFailure(t testing.TB, err error) namespace.Failure {
	t.Helper()
	failure, ok := namespace.FailureOf(err)
	if !ok {
		t.Fatalf("missing semantic failure: %v", err)
	}
	return failure
}

func testConfig(id byte) namespaceTestConfig {
	mtu := uint16(ethernet.MaxMTU)
	return namespaceTestConfig{
		Hostname: "dns", RandSeed: int64(id) + 1,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 3},
		IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), MTU: mtu,
		Link: packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
	}
}

func dnsTestConfig(t testing.TB, id byte) namespaceTestConfig {
	t.Helper()
	config := testConfig(id)
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDNS}, Directions: []policy.Direction{policy.DirectionOutbound}, DNSSuffixes: []string{"example.com"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	config.Policy = compiled
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 4, DNSResources: 4, QueuedBytes: 16 << 10, DNSWork: 8})
	config.DNS = Config{
		Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 2, MaxRecords: 4,
		MaxResponseBytes: 512, MaxAttempts: 2, RetryServiceAttempts: 2,
	}
	config.GatewayHardwareAddress = [6]byte{0x02, 0, 0, 0, 0, 53}
	return config
}

func serviceDNSPacket(t testing.TB, ns *testNamespace) []byte {
	t.Helper()
	setNextIngress(ns, false)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 || report.Operations != 1 || report.Bytes == 0 {
		t.Fatalf("DNS packet service = %+v, %v, %v", report, progress, err)
	}
	buffer := make([]byte, ns.Link().MaxFrameBytes())
	result, err := ns.Link().TryDequeue(packetlink.Egress, buffer)
	if err != nil || !result.Ready || result.Truncated {
		t.Fatalf("DNS packet dequeue = %+v, %v", result, err)
	}
	return append([]byte(nil), buffer[:result.FrameBytes]...)
}

func serviceDNSIngressFrame(t testing.TB, ns *testNamespace, frame []byte) namespace.ServiceReport {
	t.Helper()
	if err := ns.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
		t.Fatal(err)
	}
	setNextIngress(ns, true)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidResult(budget, progress) {
		t.Fatalf("DNS ingress service = %+v, %v, %v", report, progress, err)
	}
	return report
}

func serviceDNSMaintenance(t testing.TB, ns *testNamespace) namespace.ServiceReport {
	t.Helper()
	setNextIngress(ns, false)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidResult(budget, progress) {
		t.Fatalf("DNS maintenance = %+v, %v, %v", report, progress, err)
	}
	return report
}

func dnsPacketIdentity(t testing.TB, packet []byte) (uint16, uint16) {
	t.Helper()
	ipFrame, err := ipv4.NewFrame(packet[14:])
	if err != nil {
		t.Fatal(err)
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	dnsFrame, err := lnetodns.NewFrame(udpFrame.RawData()[8:udpFrame.Length()])
	if err != nil {
		t.Fatal(err)
	}
	return dnsFrame.TxID(), udpFrame.SourcePort()
}

func buildDNSResponseFrame(t testing.TB, config namespaceTestConfig, txid, destinationPort uint16, question string) []byte {
	t.Helper()
	return buildDNSResponseFrameWithRecords(t, config, txid, destinationPort, question, []namespace.DNSRecord{
		{Name: "example.com", Type: namespace.DNSRecordCNAME, TTLSeconds: 60, CanonicalName: "canonical.example.com"},
		{Name: "canonical.example.com", Type: namespace.DNSRecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.99")},
		{Name: "canonical.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 180, Address: netip.MustParseAddr("2001:db8::99")},
	})
}

func buildDNSResponseFrameWithRecords(t testing.TB, config namespaceTestConfig, txid, destinationPort uint16, question string, records []namespace.DNSRecord) []byte {
	t.Helper()
	questionName := lnetodns.MustNewName(question)
	answers := make([]lnetodns.Resource, 0, len(records))
	for _, record := range records {
		name := lnetodns.MustNewName(record.Name)
		switch record.Type {
		case namespace.DNSRecordA:
			answers = append(answers, lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, record.TTLSeconds, record.Address.AsSlice()))
		case namespace.DNSRecordAAAA:
			answers = append(answers, lnetodns.NewResource(name, lnetodns.TypeAAAA, lnetodns.ClassINET, record.TTLSeconds, record.Address.AsSlice()))
		case namespace.DNSRecordCNAME:
			canonical := lnetodns.MustNewName(record.CanonicalName)
			canonicalData, err := canonical.AppendTo(nil)
			if err != nil {
				t.Fatal(err)
			}
			answers = append(answers, lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, record.TTLSeconds, canonicalData))
		default:
			t.Fatalf("unsupported DNS record type %v", record.Type)
		}
	}
	message := lnetodns.Message{
		Questions: []lnetodns.Question{
			{Name: questionName, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
			{Name: questionName, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
		},
		Answers: answers,
	}
	return buildDNSFrame(t, config, txid, destinationPort, message, lnetodns.HeaderFlags(1<<15|1<<8|1<<7))
}

func buildDNSFrame(t testing.TB, config namespaceTestConfig, txid, destinationPort uint16, message lnetodns.Message, flags lnetodns.HeaderFlags) []byte {
	t.Helper()
	payload, err := message.AppendTo(nil, txid, flags)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 14+20+8+len(payload))
	ethernetFrame, _ := ethernet.NewFrame(frame)
	*ethernetFrame.DestinationHardwareAddr() = config.HardwareAddress
	*ethernetFrame.SourceHardwareAddr() = config.GatewayHardwareAddress
	ethernetFrame.SetEtherType(ethernet.TypeIPv4)
	ipFrame, _ := ipv4.NewFrame(frame[14:])
	ipFrame.SetVersionAndIHL(4, 5)
	ipFrame.SetTotalLength(uint16(20 + 8 + len(payload)))
	ipFrame.SetTTL(64)
	ipFrame.SetProtocol(lneto.IPProtoUDP)
	*ipFrame.SourceAddr() = config.DNS.Server.As4()
	*ipFrame.DestinationAddr() = config.IPv4Address.As4()
	ipFrame.SetCRC(0)
	ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
	udpFrame, _ := lnetoudp.NewFrame(frame[14+20:])
	udpFrame.SetSourcePort(lnetodns.ServerPort)
	udpFrame.SetDestinationPort(destinationPort)
	udpFrame.SetLength(uint16(8 + len(payload)))
	copy(frame[14+20+8:], payload)
	udpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
	udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
	return frame
}
