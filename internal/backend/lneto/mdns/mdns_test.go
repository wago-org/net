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

func TestMDNSIngressRelevanceConsumesLocalMalformedAndLeavesForeignUnhandled(t *testing.T) {
	service := testService("device", "192.0.2.11")
	core, adapter, _ := newTestAdapter(t, Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 2, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 16, MaxAttempts: 1, RetryServiceAttempts: 1,
	}, testPolicy())
	payload, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, 1200)
	if err != nil {
		t.Fatal(err)
	}
	base := wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33"))
	for _, test := range []struct {
		name        string
		wantHandled bool
		mutate      func([]byte)
	}{
		{name: "foreign Ethernet destination", mutate: func(frame []byte) {
			eth, _ := ethernet.NewFrame(frame)
			*eth.DestinationHardwareAddr() = [6]byte{2, 0, 0, 0, 0, 99}
		}},
		{name: "foreign IPv4 destination", mutate: func(frame []byte) {
			eth, _ := ethernet.NewFrame(frame)
			ip, _ := ipv4.NewFrame(eth.Payload())
			*ip.DestinationAddr() = [4]byte{192, 0, 2, 99}
			ip.SetCRC(0)
			ip.SetCRC(ip.CalculateHeaderCRC())
		}},
		{name: "foreign UDP port", mutate: func(frame []byte) {
			eth, _ := ethernet.NewFrame(frame)
			ip, _ := ipv4.NewFrame(eth.Payload())
			udp, _ := lnetoudp.NewFrame(ip.Payload())
			udp.SetDestinationPort(9999)
			udp.SetCRC(0)
		}},
		{name: "local invalid TTL", wantHandled: true, mutate: func(frame []byte) {
			eth, _ := ethernet.NewFrame(frame)
			ip, _ := ipv4.NewFrame(eth.Payload())
			ip.SetTTL(64)
			ip.SetCRC(0)
			ip.SetCRC(ip.CalculateHeaderCRC())
		}},
		{name: "local fragmented IPv4", wantHandled: true, mutate: func(frame []byte) {
			eth, _ := ethernet.NewFrame(frame)
			ip, _ := ipv4.NewFrame(eth.Payload())
			ip.SetFlags(1)
			ip.SetCRC(0)
			ip.SetCRC(ip.CalculateHeaderCRC())
		}},
		{name: "local invalid UDP checksum", wantHandled: true, mutate: func(frame []byte) {
			eth, _ := ethernet.NewFrame(frame)
			ip, _ := ipv4.NewFrame(eth.Payload())
			udp, _ := lnetoudp.NewFrame(ip.Payload())
			udp.SetCRC(1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := append([]byte(nil), base...)
			test.mutate(frame)
			core.Lock()
			handled, ingressErr := adapter.ingressLocked(frame)
			queued := adapter.responseCount
			core.Unlock()
			if ingressErr != nil || handled != test.wantHandled {
				t.Fatalf("ingress = handled %v, err %v; want handled %v", handled, ingressErr, test.wantHandled)
			}
			if queued != 0 {
				t.Fatalf("malformed or foreign frame queued %d responses", queued)
			}
		})
	}
}

func TestMDNSQueuedResponseNamespaceCloseAndStaleResourcesAreIsolated(t *testing.T) {
	service := testService("device", "192.0.2.11")
	config := Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 2, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 16, MaxAttempts: 2, RetryServiceAttempts: 2,
	}
	core, adapter, account := newTestAdapter(t, config, testPolicy())
	oldQueryResource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	oldAnnouncementResource, _, err := adapter.TryAnnounce(0)
	if err != nil {
		t.Fatal(err)
	}
	oldQuery := oldQueryResource.(*query)
	oldAnnouncement := oldAnnouncementResource.(*announcement)
	if err := oldQuery.Close(); err != nil {
		t.Fatal(err)
	}
	if err := oldAnnouncement.Close(); err != nil {
		t.Fatal(err)
	}
	queryResource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	announcementResource, _, err := adapter.TryAnnounce(0)
	if err != nil {
		t.Fatal(err)
	}
	query := queryResource.(*query)
	announcement := announcementResource.(*announcement)
	if err := oldQuery.Close(); err != nil {
		t.Fatal(err)
	}
	if err := oldAnnouncement.Close(); err != nil {
		t.Fatal(err)
	}
	if query.Readiness() != 0 || announcement.Readiness() != 0 {
		t.Fatalf("stale close mutated fresh resources: query=%v announcement=%v", query.Readiness(), announcement.Readiness())
	}

	payload, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, config.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33")))
	core.Lock()
	queued, leases := adapter.responseCount, core.UDPPortLeaseCountLocked()
	core.Unlock()
	if queued != 1 || leases != 1 {
		t.Fatalf("queued responses=%d UDP leases=%d", queued, leases)
	}
	wantQueuedBytes := uint64(config.MaxQueuedResponses)*uint64(config.MaxPacketBytes) + queryRetainedBytes(config) + uint64(config.MaxPacketBytes)
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{
		Resources: 2, MDNSResources: 2, QueuedBytes: wantQueuedBytes, MDNSWork: 2,
	}) {
		t.Fatalf("live quota = %+v, closed=%v; want queued bytes %d", usage, closed, wantQueuedBytes)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if query.Readiness() != nscore.ReadyClosed || announcement.Readiness() != nscore.ReadyClosed {
		t.Fatalf("namespace close readiness: query=%v announcement=%v", query.Readiness(), announcement.Readiness())
	}
	if _, _, err := query.TryNext(); failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("closed query result = %v", err)
	}
	if _, err := announcement.TryFinish(); failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("closed announcement result = %v", err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close quota = %+v", usage)
	}
	if adapter.responseCount != 0 || adapter.responseSlots != nil || adapter.responseResources != nil || adapter.serviceResources != nil || adapter.services != nil {
		t.Fatalf("namespace close retained adapter state: responses=%d slots=%v scratch=%v service records=%v services=%v",
			adapter.responseCount, adapter.responseSlots, adapter.responseResources, adapter.serviceResources, adapter.services)
	}
}

func TestMDNSCanonicalDuplicateQuestionsAndKnownAnswerSuppression(t *testing.T) {
	service := testService("device", "192.0.2.11")
	config := Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 4, MaxAttempts: 1, RetryServiceAttempts: 1,
	}
	core, adapter, _ := newTestAdapter(t, config, testPolicy())
	wireName, err := lnetodns.NewName("_DEMO._UDP.LOCAL.")
	if err != nil {
		t.Fatal(err)
	}
	question := lnetodns.Question{Name: wireName, Type: lnetodns.TypePTR, Class: lnetodns.ClassINET}
	message := lnetodns.Message{Questions: []lnetodns.Question{question, question}}
	payload, err := message.AppendTo(make([]byte, 0, config.MaxPacketBytes), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33")))
	response := serviceEgress(t, core)
	eth, _ := ethernet.NewFrame(response)
	ip, _ := ipv4.NewFrame(eth.Payload())
	udp, _ := lnetoudp.NewFrame(ip.Payload())
	dnsFrame, err := lnetodns.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if answers := dnsFrame.ANCount(); answers != 1 {
		t.Fatalf("canonical duplicate response answers = %d", answers)
	}

	known, err := serviceResources(service, lnetodns.TypePTR)
	if err != nil {
		t.Fatal(err)
	}
	message = lnetodns.Message{Questions: []lnetodns.Question{question}, Answers: known}
	payload, err = message.AppendTo(make([]byte, 0, config.MaxPacketBytes), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33")))
	core.Lock()
	queued := adapter.responseCount
	core.Unlock()
	if queued != 0 {
		t.Fatalf("known answer queued %d duplicate responses", queued)
	}

	lowTTLService := service
	lowTTLService.TTLSeconds = service.TTLSeconds/2 - 1
	lowTTL, err := serviceResources(lowTTLService, lnetodns.TypePTR)
	if err != nil {
		t.Fatal(err)
	}
	message = lnetodns.Message{Questions: []lnetodns.Question{question}, Answers: lowTTL}
	payload, err = message.AppendTo(make([]byte, 0, config.MaxPacketBytes), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33")))
	core.Lock()
	queued = adapter.responseCount
	core.Unlock()
	if queued != 1 {
		t.Fatalf("low-TTL known answer queued %d responses", queued)
	}
	_ = serviceEgress(t, core)
}

func BenchmarkIngressAutomaticResponse(b *testing.B) {
	service := testService("device", "192.0.2.11")
	core, adapter, _ := newTestAdapter(b, Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 16, MaxAttempts: 1, RetryServiceAttempts: 1,
	}, testPolicy())
	payload, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, 1200)
	if err != nil {
		b.Fatal(err)
	}
	frame := wrapMDNSFrame(b, payload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33"))
	core.Lock()
	defer core.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		adapter.responseCount = 0
		adapter.responseHead = 0
		adapter.responseSlots[0] = adapter.responseSlots[0][:0]
		handled, err := adapter.ingressLocked(frame)
		if err != nil || !handled || adapter.responseCount != 1 {
			b.Fatalf("ingress = handled %v, err %v, responses %d", handled, err, adapter.responseCount)
		}
	}
}
