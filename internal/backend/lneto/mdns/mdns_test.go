package mdns

import (
	"net/netip"
	"testing"

	lneto "github.com/soypat/lneto"
	lnetodns "github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestMDNSQueryResponseAnnouncementAndAutomaticService(t *testing.T) {
	service := testService("device", "192.0.2.11")
	core, adapter, account := newTestAdapter(t, Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 2, MaxAnnouncements: 2,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 2, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 16, MaxAttempts: 1, RetryServiceAttempts: 2,
	}, testPolicy())
	core.Lock()
	if got := core.UDPPortLeaseCountLocked(); got != 1 {
		core.Unlock()
		t.Fatalf("UDP leases = %d, want mDNS port", got)
	}
	if lease, ok := core.TryLeaseUDPPortLocked(Port); ok || lease != nil {
		core.Unlock()
		t.Fatal("mDNS port did not collide in shared UDP domain")
	}
	core.Unlock()

	resource, progress, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryQuery = %T, %v, %v", resource, progress, err)
	}
	query := resource.(*query)
	outgoing := serviceEgress(t, core)
	assertMDNSFrame(t, outgoing, false)
	peer := testService("peer", "192.0.2.22")
	responsePayload, err := buildServicePacket(peer, lnetodns.TypeA, 1200)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, responsePayload, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22")))
	if got := query.Readiness(); got != nscore.ReadyMDNSResult {
		t.Fatalf("query readiness = %v", got)
	}
	record, next, err := query.TryNext()
	if err != nil || next != mdnsns.NextReady || record.Type != mdnsns.RecordA || record.Address != netip.MustParseAddr("192.0.2.22") {
		t.Fatalf("query result = %+v, %v, %v", record, next, err)
	}
	if _, next, err := query.TryNext(); err != nil || next != mdnsns.NextEOF {
		t.Fatalf("query EOF = %v, %v", next, err)
	}

	questionPayload, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, 1200)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, questionPayload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33")))
	automatic := serviceEgress(t, core)
	assertMDNSFrame(t, automatic, true)

	announceResource, progress, err := adapter.TryAnnounce(0)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryAnnounce = %T, %v, %v", announceResource, progress, err)
	}
	announcement := announceResource.(*announcement)
	announced := serviceEgress(t, core)
	assertMDNSFrame(t, announced, true)
	if next, err := announcement.TryFinish(); err != nil || next != mdnsns.NextReady || announcement.Readiness() != nscore.ReadyMDNSAnnouncement {
		t.Fatalf("announcement finish = %v, %v readiness=%v", next, err, announcement.Readiness())
	}
	if usage, closed := account.Snapshot(); closed || usage.MDNSResources != 2 || usage.MDNSWork != 0 {
		t.Fatalf("terminal quota = %+v, closed=%v", usage, closed)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if err := announcement.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage.Resources != 0 || usage.MDNSResources != 0 || usage.MDNSWork != 0 || usage.QueuedBytes == 0 {
		t.Fatalf("resource close quota = %+v", usage)
	}
}

func TestMDNSDenyWinsTimeoutCancelAndCloseRelease(t *testing.T) {
	deny := testPolicy()
	deny.Rules = append(deny.Rules, policy.Rule{
		Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportMDNS},
		Directions: []policy.Direction{policy.DirectionOutbound}, DNSSuffixes: []string{"secret.local"},
	})
	core, adapter, account := newTestAdapter(t, queryOnlyConfig(), deny)
	if _, _, err := adapter.TryQuery(mdnsns.Request{Name: "secret.local", Types: mdnsns.RecordsA}); failureOf(t, err) != nscore.FailureAccessDenied {
		t.Fatalf("deny-wins query = %v", err)
	}
	resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	q := resource.(*query)
	_ = serviceEgress(t, core)
	serviceMaintenance(t, core)
	if _, _, err := q.TryNext(); failureOf(t, err) != nscore.FailureTimedOut {
		t.Fatalf("timeout = %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	resource, _, err = adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	q = resource.(*query)
	if err := q.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.TryNext(); failureOf(t, err) != nscore.FailureCanceled {
		t.Fatalf("cancel = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if q.Readiness() != nscore.ReadyClosed {
		t.Fatal("closed query did not report closed")
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("close retained quota = %+v", usage)
	}
}

func TestMDNSRejectsMalformedOrIrrelevantResponses(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, queryOnlyConfig(), testPolicy())
	resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	q := resource.(*query)
	_ = serviceEgress(t, core)
	irrelevant, err := buildServicePacket(testService("other", "192.0.2.44"), lnetodns.TypeA, 1200)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, irrelevant, [6]byte{2, 0, 0, 0, 0, 44}, netip.MustParseAddr("192.0.2.44")))
	if q.Readiness() != 0 {
		t.Fatal("irrelevant response completed query")
	}
	bad := wrapMDNSFrame(t, irrelevant, [6]byte{2, 0, 0, 0, 0, 44}, netip.MustParseAddr("192.0.2.44"))
	eth, _ := ethernet.NewFrame(bad)
	ip, _ := ipv4.NewFrame(eth.Payload())
	ip.SetTTL(64)
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	serviceIngress(t, core, bad)
	if q.Readiness() != 0 {
		t.Fatal("wrong-hop-limit packet affected query")
	}
}

func TestMDNSZeroConfigRetainsTruthfulServiceSemantics(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, Config{}, policy.Config{})
	for name, call := range map[string]func() error{
		"invalid query": func() error { _, _, err := adapter.TryQuery(mdnsns.Request{}); return err },
		"valid query": func() error {
			_, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
			return err
		},
		"announcement": func() error { _, _, err := adapter.TryAnnounce(0); return err },
	} {
		if err := call(); failureOf(t, err) != nscore.FailureNotSupported {
			t.Fatalf("%s = %v", name, err)
		}
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA}); failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("closed disabled query = %v", err)
	}
}

func TestMDNSConfigIsFiniteAndCopiesServices(t *testing.T) {
	if !ValidConfig(Config{}, 1500, nil, nil, false) {
		t.Fatal("zero disabled config rejected")
	}
	valid := queryOnlyConfig()
	if !ValidConfig(valid, 1500, nil, nil, false) {
		t.Fatal("valid query config rejected")
	}
	for _, config := range []Config{
		{MaxQueries: 1},
		{MaxQueries: 1, MaxRecords: 1, MaxPacketBytes: 2000, MaxQuestionsPerPacket: 1, MaxRecordsPerPacket: 1, MaxAttempts: 1, RetryServiceAttempts: 1},
		{Services: []mdnsns.Service{testService("device", "192.0.2.11")}, MaxQueries: 1, MaxRecords: 1, MaxPacketBytes: 1200, MaxQuestionsPerPacket: 1, MaxRecordsPerPacket: 4, MaxAttempts: 1, RetryServiceAttempts: 1},
	} {
		if ValidConfig(config, 1500, nil, nil, false) {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
	cloned := cloneConfig(Config{Services: []mdnsns.Service{testService("device", "192.0.2.11")}})
	original := cloned.Services[0].Name
	cloned.Services[0].Name = "changed.local"
	if original == cloned.Services[0].Name {
		t.Fatal("service test did not mutate clone")
	}
}

func queryOnlyConfig() Config {
	return Config{MaxQueries: 1, MaxRecords: 8, MaxPacketBytes: 1200, MaxQuestionsPerPacket: 4, MaxRecordsPerPacket: 16, MaxAttempts: 1, RetryServiceAttempts: 1}
}

func testService(host, address string) mdnsns.Service {
	service := mdnsns.Service{
		Name: host + "._demo._udp.local", Host: host + ".local", Address: netip.MustParseAddr(address),
		TTLSeconds: 120, Port: 9000, TXTLength: 4,
	}
	copy(service.TXT[:], []byte{3, 'k', '=', 'v'})
	return service
}

func testPolicy() policy.Config {
	return policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportMDNS}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("224.0.0.251/32")}, Ports: []policy.PortRange{{First: Port, Last: Port}}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportMDNS}, Directions: []policy.Direction{policy.DirectionOutbound}, DNSSuffixes: []string{"local"}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportMDNS}, Directions: []policy.Direction{policy.DirectionInbound}, DNSSuffixes: []string{"local"}},
		},
		MulticastTransports: []policy.Transport{policy.TransportMDNS},
	}
}

func newTestAdapter(t testing.TB, config Config, policyConfig policy.Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	compiled, err := policy.Compile(policyConfig)
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 16, MDNSResources: 16, QueuedBytes: 1 << 20, MDNSWork: 16})
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "mdns", RandSeed: 21,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 11}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.11"), MTU: 1500,
		Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	adapter, err := New(core, config)
	if err != nil {
		t.Fatal(err)
	}
	return core, adapter, account
}

func serviceEgress(t testing.TB, core *lnetocore.Namespace) []byte {
	t.Helper()
	core.Lock()
	core.SetNextIngressLocked(false)
	core.Unlock()
	report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("egress service = %+v, %v, %v", report, progress, err)
	}
	frame := make([]byte, 1514)
	result, err := core.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready || result.Truncated {
		t.Fatalf("egress dequeue = %+v, %v", result, err)
	}
	return append([]byte(nil), frame[:result.FrameBytes]...)
}

func serviceIngress(t testing.TB, core *lnetocore.Namespace, frame []byte) {
	t.Helper()
	if err := core.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	core.SetNextIngressLocked(true)
	core.Unlock()
	report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("ingress service = %+v, %v, %v", report, progress, err)
	}
}

func serviceMaintenance(t testing.TB, core *lnetocore.Namespace) {
	t.Helper()
	core.Lock()
	core.SetNextIngressLocked(false)
	core.Unlock()
	report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Operations: 1}) {
		t.Fatalf("maintenance service = %+v, %v, %v", report, progress, err)
	}
}

func wrapMDNSFrame(t testing.TB, payload []byte, sourceMAC [6]byte, sourceIP netip.Addr) []byte {
	t.Helper()
	frame := make([]byte, 14+20+8+len(payload))
	eth, _ := ethernet.NewFrame(frame)
	*eth.DestinationHardwareAddr() = multicastMAC
	*eth.SourceHardwareAddr() = sourceMAC
	eth.SetEtherType(ethernet.TypeIPv4)
	ip, _ := ipv4.NewFrame(frame[14:])
	ip.SetVersionAndIHL(4, 5)
	ip.SetTotalLength(uint16(20 + 8 + len(payload)))
	ip.SetID(1)
	ip.SetFlags(0)
	ip.SetTTL(255)
	ip.SetProtocol(lneto.IPProtoUDP)
	*ip.SourceAddr() = sourceIP.As4()
	*ip.DestinationAddr() = multicastAddress.As4()
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp, _ := lnetoudp.NewFrame(frame[34:])
	udp.SetSourcePort(Port)
	udp.SetDestinationPort(Port)
	udp.SetLength(uint16(8 + len(payload)))
	copy(frame[42:], payload)
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func assertMDNSFrame(t testing.TB, frame []byte, response bool) {
	t.Helper()
	eth, err := ethernet.NewFrame(frame)
	if err != nil || *eth.DestinationHardwareAddr() != multicastMAC {
		t.Fatalf("Ethernet frame = %v", err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil || ip.TTL() != 255 || netip.AddrFrom4(*ip.DestinationAddr()) != multicastAddress {
		t.Fatalf("IPv4 frame = %v ttl=%d", err, ip.TTL())
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil || udp.SourcePort() != Port || udp.DestinationPort() != Port {
		t.Fatalf("UDP frame = %v", err)
	}
	dnsFrame, err := lnetodns.NewFrame(udp.Payload())
	if err != nil || dnsFrame.TxID() != 0 || dnsFrame.Flags().IsResponse() != response {
		t.Fatalf("DNS frame = %v txid=%d flags=%v", err, dnsFrame.TxID(), dnsFrame.Flags())
	}
}

func failureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	if err == nil {
		t.Fatal("missing error")
	}
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("missing semantic failure: %v", err)
	}
	return failure
}
