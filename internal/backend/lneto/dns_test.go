package lnetobackend

import (
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
