package lnetobackend

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	lnetodns "github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestDNSBoundedQueryRecordsAndQuotaLifecycle(t *testing.T) {
	config := dnsTestConfig(t, 41)
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	resource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress || resource == nil {
		t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
	}
	query := resource.(*dnsQuery)
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
	ns.nextIngress = true
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
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed query retained quota = %+v", usage)
	}
	if got := query.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed readiness = %v", got)
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
	reused, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress || reused == query {
		t.Fatalf("query reuse = %T, %v, %v", reused, progress, err)
	}
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

func dnsTestConfig(t testing.TB, id byte) Config {
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
	config.DNS = DNSConfig{
		Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 2, MaxRecords: 4,
		MaxResponseBytes: 512, MaxAttempts: 2, RetryServiceAttempts: 2,
	}
	config.GatewayHardwareAddress = [6]byte{0x02, 0, 0, 0, 0, 53}
	return config
}

func serviceDNSPacket(t testing.TB, ns *Namespace) []byte {
	t.Helper()
	ns.nextIngress = false
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

func serviceDNSMaintenance(t testing.TB, ns *Namespace) namespace.ServiceReport {
	t.Helper()
	ns.nextIngress = false
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

func buildDNSResponseFrame(t testing.TB, config Config, txid, destinationPort uint16, question string) []byte {
	t.Helper()
	questionName := lnetodns.MustNewName(question)
	canonical := lnetodns.MustNewName("canonical.example.com")
	canonicalData, err := canonical.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := lnetodns.Message{
		Questions: []lnetodns.Question{
			{Name: questionName, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
			{Name: questionName, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
		},
		Answers: []lnetodns.Resource{
			lnetodns.NewResource(questionName, lnetodns.TypeCNAME, lnetodns.ClassINET, 60, canonicalData),
			lnetodns.NewResource(canonical, lnetodns.TypeA, lnetodns.ClassINET, 120, []byte{192, 0, 2, 99}),
			lnetodns.NewResource(canonical, lnetodns.TypeAAAA, lnetodns.ClassINET, 180, netip.MustParseAddr("2001:db8::99").AsSlice()),
		},
	}
	payload, err := message.AppendTo(nil, txid, lnetodns.HeaderFlags(1<<15|1<<8|1<<7))
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
