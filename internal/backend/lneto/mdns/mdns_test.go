package mdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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

func TestEgressShortBufferPreservesMixedRoundRobinStateAndPendingWork(t *testing.T) {
	service := testService("device", "192.0.2.11")
	config := Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 16, MaxAttempts: 2, RetryServiceAttempts: 2,
	}
	core, adapter, account := newTestAdapter(t, config, testPolicy())
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
	queryPacket := append([]byte(nil), query.packet...)
	announcementPacket := append([]byte(nil), announcement.packet...)
	queryReady, announcementReady := query.Readiness(), announcement.Readiness()
	usageBefore, _ := account.Snapshot()
	short := bytes.Repeat([]byte{0xa5}, 14+20+8+len(query.packet)-1)

	core.Lock()
	written, worked, err := adapter.egressLocked(short)
	cursor := adapter.cursor
	core.Unlock()
	if written != 0 || worked || !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short egress = %d, %v, %v", written, worked, err)
	}
	if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
		t.Fatalf("short egress mutated destination = %x", short)
	}
	if cursor != 0 || query.state != statePending || announcement.state != statePending || query.attempts != 0 || announcement.attempts != 0 || query.retry != 0 || announcement.retry != 0 || !bytes.Equal(query.packet, queryPacket) || !bytes.Equal(announcement.packet, announcementPacket) {
		t.Fatalf("short egress mutated scheduler or work: cursor=%d query=%v/%d/%d announcement=%v/%d/%d", cursor, query.state, query.attempts, query.retry, announcement.state, announcement.attempts, announcement.retry)
	}
	if query.Readiness() != queryReady || announcement.Readiness() != announcementReady {
		t.Fatalf("short egress changed readiness: query=%v/%v announcement=%v/%v", query.Readiness(), queryReady, announcement.Readiness(), announcementReady)
	}
	if usage, _ := account.Snapshot(); usage != usageBefore {
		t.Fatalf("short egress changed quota = %+v, want %+v", usage, usageBefore)
	}

	frame := make([]byte, core.Link().MaxFrameBytes())
	core.Lock()
	queryBytes, queryWorked, err := adapter.egressLocked(frame)
	cursorAfterQuery := adapter.cursor
	core.Unlock()
	if err != nil || !queryWorked || queryBytes == 0 || cursorAfterQuery != 1 {
		t.Fatalf("query retry = %d, %v, %v, cursor=%d", queryBytes, queryWorked, err, cursorAfterQuery)
	}
	queryIP, err := ipv4.NewFrame(frame[14:queryBytes])
	if err != nil {
		t.Fatal(err)
	}
	queryUDP, err := lnetoudp.NewFrame(queryIP.Payload())
	if err != nil {
		t.Fatal(err)
	}
	queryDNS, err := lnetodns.NewFrame(queryUDP.Payload())
	if err != nil || queryIP.ID() != 21 || queryDNS.Flags().IsResponse() {
		t.Fatalf("query retry frame = id=%d response=%v err=%v", queryIP.ID(), queryDNS.Flags().IsResponse(), err)
	}

	core.Lock()
	announcementBytes, announcementWorked, err := adapter.egressLocked(frame)
	cursorAfterAnnouncement := adapter.cursor
	core.Unlock()
	if err != nil || !announcementWorked || announcementBytes == 0 || cursorAfterAnnouncement != 0 {
		t.Fatalf("announcement egress = %d, %v, %v, cursor=%d", announcementBytes, announcementWorked, err, cursorAfterAnnouncement)
	}
	announcementIP, err := ipv4.NewFrame(frame[14:announcementBytes])
	if err != nil {
		t.Fatal(err)
	}
	announcementUDP, err := lnetoudp.NewFrame(announcementIP.Payload())
	if err != nil {
		t.Fatal(err)
	}
	announcementDNS, err := lnetodns.NewFrame(announcementUDP.Payload())
	if err != nil || announcementIP.ID() != 22 || !announcementDNS.Flags().IsResponse() {
		t.Fatalf("announcement frame = id=%d response=%v err=%v", announcementIP.ID(), announcementDNS.Flags().IsResponse(), err)
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

func TestMDNSQueryAcceptsRecordsFromEveryResponseSection(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, queryOnlyConfig(), testPolicy())
	resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	q := resource.(*query)
	_ = serviceEgress(t, core)
	addresses := []string{"192.0.2.41", "192.0.2.42", "192.0.2.43"}
	resources := make([]lnetodns.Resource, len(addresses))
	for i, address := range addresses {
		resources[i] = resourceOfType(t, testService("peer", address), lnetodns.TypeA)
	}
	message := lnetodns.Message{
		Answers:     resources[:1],
		Authorities: resources[1:2],
		Additionals: resources[2:],
	}
	payload, err := message.AppendTo(make([]byte, 0, 1200), 0, lnetodns.HeaderFlags(1<<15|1<<10))
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 41}, netip.MustParseAddr("192.0.2.41")))
	if q.Readiness() != nscore.ReadyMDNSResult {
		t.Fatalf("query readiness = %v", q.Readiness())
	}
	for _, address := range addresses {
		record, next, err := q.TryNext()
		if err != nil || next != mdnsns.NextReady || record.Address != netip.MustParseAddr(address) {
			t.Fatalf("next record = %+v, %v, %v; want %s", record, next, err, address)
		}
	}
	if record, next, err := q.TryNext(); err != nil || next != mdnsns.NextEOF || record != (mdnsns.Record{}) {
		t.Fatalf("query EOF = %+v, %v, %v", record, next, err)
	}
}

func TestMDNSResponseRecordOverflowFailsAtomicallyAndIsolatesOtherQueries(t *testing.T) {
	config := queryOnlyConfig()
	config.MaxQueries = 2
	config.MaxRecords = 1
	config.MaxRecordsPerPacket = 2
	core, adapter, account := newTestAdapter(t, config, testPolicy())
	firstResource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	secondResource, _, err := adapter.TryQuery(mdnsns.Request{Name: "other.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	first := firstResource.(*query)
	second := secondResource.(*query)
	_ = serviceEgress(t, core)
	_ = serviceEgress(t, core)

	firstAnswer := resourceOfType(t, testService("peer", "192.0.2.41"), lnetodns.TypeA)
	secondAnswer := resourceOfType(t, testService("peer", "192.0.2.42"), lnetodns.TypeA)
	payload, err := (&lnetodns.Message{Answers: []lnetodns.Resource{firstAnswer, secondAnswer}}).AppendTo(make([]byte, 0, config.MaxPacketBytes), 0, lnetodns.HeaderFlags(1<<15|1<<10))
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 41}, netip.MustParseAddr("192.0.2.41")))
	if first.state != stateFailed || first.Readiness() != nscore.ReadyError || len(first.records) != 0 {
		t.Fatalf("overflowed query = state:%v readiness:%v records:%d", first.state, first.Readiness(), len(first.records))
	}
	if _, _, err := first.TryNext(); failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("overflow failure = %v", err)
	}
	if second.state != stateWaiting || second.Readiness() != 0 || len(second.records) != 0 {
		t.Fatalf("unrelated query after overflow = state:%v readiness:%v records:%d", second.state, second.Readiness(), len(second.records))
	}
	assertMDNSDecodeScratchReset(t, &adapter.decode)
	if usage, closed := account.Snapshot(); closed || usage.Resources != 2 || usage.MDNSResources != 2 || usage.MDNSWork != 1 {
		t.Fatalf("overflow quota = %+v, closed=%v", usage, closed)
	}

	valid, err := buildServicePacket(testService("other", "192.0.2.43"), lnetodns.TypeA, config.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, valid, [6]byte{2, 0, 0, 0, 0, 43}, netip.MustParseAddr("192.0.2.43")))
	if second.state != stateDone || second.Readiness() != nscore.ReadyMDNSResult {
		t.Fatalf("unrelated completion = state:%v readiness:%v", second.state, second.Readiness())
	}
	record, next, err := second.TryNext()
	if err != nil || next != mdnsns.NextReady || record.Name != "other.local" || record.Address != netip.MustParseAddr("192.0.2.43") {
		t.Fatalf("unrelated result = %+v, %v, %v", record, next, err)
	}
	if _, next, err := second.TryNext(); err != nil || next != mdnsns.NextEOF {
		t.Fatalf("unrelated EOF = %v, %v", next, err)
	}
	if first.state != stateFailed || len(first.records) != 0 {
		t.Fatalf("later response revived overflowed query: state=%v records=%d", first.state, len(first.records))
	}
	assertMDNSDecodeScratchReset(t, &adapter.decode)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed quota = %+v", usage)
	}
}

func TestMDNSQueryAcceptsCompressedNameResourceData(t *testing.T) {
	for _, test := range []struct {
		name       string
		types      mdnsns.RecordTypes
		typ        lnetodns.Type
		data       []byte
		wantType   mdnsns.RecordType
		wantPort   uint16
		wantTarget string
	}{
		{name: "PTR", types: mdnsns.RecordsPTR, typ: lnetodns.TypePTR, data: []byte{0xc0, 0x0c}, wantType: mdnsns.RecordPTR, wantTarget: "_demo._tcp.local"},
		{name: "SRV", types: mdnsns.RecordsSRV, typ: lnetodns.TypeSRV, data: []byte{0, 0, 0, 0, 0x1f, 0x90, 0xc0, 0x0c}, wantType: mdnsns.RecordSRV, wantPort: 8080, wantTarget: "_demo._tcp.local"},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, adapter, _ := newTestAdapter(t, queryOnlyConfig(), testPolicy())
			request := mdnsns.Request{Name: "_demo._tcp.local", Types: test.types}
			resource, _, err := adapter.TryQuery(request)
			if err != nil {
				t.Fatal(err)
			}
			q := resource.(*query)
			queryPacket := serviceEgress(t, core)
			eth, err := ethernet.NewFrame(queryPacket)
			if err != nil {
				t.Fatal(err)
			}
			ip, err := ipv4.NewFrame(eth.Payload())
			if err != nil {
				t.Fatal(err)
			}
			udp, err := lnetoudp.NewFrame(ip.Payload())
			if err != nil {
				t.Fatal(err)
			}
			payload := append([]byte(nil), udp.Payload()...)
			binary.BigEndian.PutUint16(payload[2:4], uint16(1<<15|1<<10))
			binary.BigEndian.PutUint16(payload[6:8], 1)
			answer := []byte{
				0xc0, 0x0c,
				0x00, byte(test.typ),
				0x00, byte(lnetodns.ClassINET),
				0x00, 0x00, 0x00, 0x78,
				0x00, byte(len(test.data)),
			}
			payload = append(payload, answer...)
			payload = append(payload, test.data...)

			serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 45}, netip.MustParseAddr("192.0.2.45")))
			if q.Readiness() != nscore.ReadyMDNSResult {
				t.Fatalf("compressed %s readiness = %v", test.name, q.Readiness())
			}
			record, next, err := q.TryNext()
			if err != nil || next != mdnsns.NextReady || record.Type != test.wantType || record.Name != request.Name || record.Target != test.wantTarget || record.Port != test.wantPort {
				t.Fatalf("compressed %s result = %+v, %v, %v", test.name, record, next, err)
			}
		})
	}
}

func TestMDNSIngressResetsDecodeScratchAfterMalformedAndValidResponses(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, queryOnlyConfig(), testPolicy())
	resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	query := resource.(*query)
	_ = serviceEgress(t, core)

	answer := resourceOfType(t, testService("peer", "192.0.2.22"), lnetodns.TypeA)
	message := lnetodns.Message{Answers: []lnetodns.Resource{answer, answer}}
	payload, err := message.AppendTo(make([]byte, 0, 1200), 0, lnetodns.HeaderFlags(1<<15|1<<10))
	if err != nil {
		t.Fatal(err)
	}
	malformed := payload[:len(payload)-1]
	serviceIngress(t, core, wrapMDNSFrame(t, malformed, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22")))
	if query.state != stateWaiting || len(query.records) != 0 || query.Readiness() != 0 {
		t.Fatalf("malformed response mutated query: state=%v records=%d readiness=%v", query.state, len(query.records), query.Readiness())
	}
	assertMDNSDecodeScratchReset(t, &adapter.decode)

	valid, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
	if err != nil {
		t.Fatal(err)
	}
	serviceIngress(t, core, wrapMDNSFrame(t, valid, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22")))
	if query.Readiness() != nscore.ReadyMDNSResult {
		t.Fatalf("valid response readiness = %v", query.Readiness())
	}
	record, next, err := query.TryNext()
	if err != nil || next != mdnsns.NextReady || record.Name != "peer.local" || record.Address != netip.MustParseAddr("192.0.2.22") {
		t.Fatalf("valid retained record = %+v, %v, %v", record, next, err)
	}
	assertMDNSDecodeScratchReset(t, &adapter.decode)
}

func assertMDNSDecodeScratchReset(t testing.TB, message *lnetodns.Message) {
	t.Helper()
	if len(message.Questions) != 0 || len(message.Answers) != 0 || len(message.Authorities) != 0 || len(message.Additionals) != 0 {
		t.Fatalf("decode scratch lengths not reset: %#v", message)
	}
}

func FuzzMDNSWireIngress(f *testing.F) {
	config := queryOnlyConfig()
	valid, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, config.MaxPacketBytes)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, lnetodns.SizeHeader))
	f.Add([]byte{0, 0, 0x84, 0, 0, 1})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > config.MaxPacketBytes {
			return
		}
		core, adapter, account := newTestAdapter(t, config, testPolicy())
		resource, progress, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
		if err != nil || progress != nscore.ProgressInProgress {
			t.Fatalf("TryQuery = %T, %v, %v", resource, progress, err)
		}
		q := resource.(*query)
		_ = serviceEgress(t, core)
		frame := wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22"))
		core.Lock()
		handled, ingressErr := adapter.ingressLocked(frame)
		core.Unlock()
		if ingressErr != nil || !handled {
			t.Fatalf("owned ingress = handled:%v err:%v", handled, ingressErr)
		}
		assertMDNSDecodeScratchReset(t, &adapter.decode)
		if len(q.records) > int(config.MaxRecords) {
			t.Fatalf("retained %d records, limit %d", len(q.records), config.MaxRecords)
		}
		for _, record := range q.records {
			if !record.Valid() || record.Name != q.request.Name {
				t.Fatalf("retained invalid or unrelated record: %+v", record)
			}
		}
		wantWork := uint64(1)
		switch q.state {
		case stateWaiting:
			if len(q.records) != 0 || q.failure != nil {
				t.Fatalf("waiting query retained terminal state: records=%d failure=%v", len(q.records), q.failure)
			}
		case stateDone:
			wantWork = 0
			if len(q.records) == 0 || q.failure != nil {
				t.Fatalf("completed query state: records=%d failure=%v", len(q.records), q.failure)
			}
		case stateFailed:
			wantWork = 0
			if len(q.records) != 0 || q.failure == nil {
				t.Fatalf("failed query state: records=%d failure=%v", len(q.records), q.failure)
			}
		default:
			t.Fatalf("unexpected query state %v", q.state)
		}
		if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{
			Resources: 1, MDNSResources: 1, QueuedBytes: queryRetainedBytes(config), MDNSWork: wantWork,
		}) {
			t.Fatalf("ingress quota = %+v, closed=%v", usage, closed)
		}
		if err := q.Close(); err != nil {
			t.Fatal(err)
		}
		if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
			t.Fatalf("closed query retained quota = %+v", usage)
		}
	})
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

func excludeLastIPv4PayloadByteFromUDP(t testing.TB, frame []byte) {
	t.Helper()
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp.SetLength(udp.Length() - 1)
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
}

func setMDNSTestDestination(t testing.TB, frame []byte, destinationMAC [6]byte, destinationIP netip.Addr) {
	t.Helper()
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	*eth.DestinationHardwareAddr() = destinationMAC
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	*ip.DestinationAddr() = destinationIP.As4()
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
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

func TestMDNSIngressDropsInvalidIPv4LengthsWithoutMutatingOperations(t *testing.T) {
	for _, destination := range []struct {
		name string
		mac  [6]byte
		ip   netip.Addr
	}{
		{name: "multicast", mac: multicastMAC, ip: multicastAddress},
		{name: "unicast", mac: [6]byte{2, 0, 0, 0, 0, 11}, ip: netip.MustParseAddr("192.0.2.11")},
	} {
		for _, malformedCase := range []struct {
			name        string
			totalLength uint16
			headerWords uint8
		}{
			{name: "shorter than header", totalLength: 19},
			{name: "beyond frame", totalLength: 1501},
			{name: "header beyond total length", totalLength: 59, headerWords: 15},
		} {
			t.Run(destination.name+"/"+malformedCase.name, func(t *testing.T) {
				service := testService("device", "192.0.2.11")
				core, adapter, _ := newTestAdapter(t, Config{
					Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
					MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
					MaxRecordsPerPacket: 16, MaxAttempts: 2, RetryServiceAttempts: 2,
				}, testPolicy())
				resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
				if err != nil {
					t.Fatal(err)
				}
				q := resource.(*query)
				_ = serviceEgress(t, core)
				responsePayload, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
				if err != nil {
					t.Fatal(err)
				}
				valid := wrapMDNSFrame(t, responsePayload, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22"))
				setMDNSTestDestination(t, valid, destination.mac, destination.ip)
				malformed := append([]byte(nil), valid...)
				eth, err := ethernet.NewFrame(malformed)
				if err != nil {
					t.Fatal(err)
				}
				ip, err := ipv4.NewFrame(eth.Payload())
				if err != nil {
					t.Fatal(err)
				}
				if malformedCase.headerWords != 0 {
					ip.SetVersionAndIHL(4, malformedCase.headerWords)
				}
				ip.SetTotalLength(malformedCase.totalLength)
				ip.SetCRC(0)
				ip.SetCRC(ip.CalculateHeaderCRC())

				var handled bool
				var ingressErr error
				var state operationState
				var records, queued int
				func() {
					core.Lock()
					defer core.Unlock()
					handled, ingressErr = adapter.ingressLocked(malformed)
					state, records, queued = q.state, len(q.records), adapter.responseCount
				}()
				if ingressErr != nil || handled || state != stateWaiting || records != 0 || queued != 0 || q.Readiness() != 0 {
					t.Fatalf("malformed ingress = handled:%v err:%v state:%v records:%d queued:%d readiness:%v", handled, ingressErr, state, records, queued, q.Readiness())
				}
				if len(adapter.decode.Questions) != 0 || len(adapter.decode.Answers) != 0 || len(adapter.decode.Authorities) != 0 || len(adapter.decode.Additionals) != 0 {
					t.Fatalf("malformed ingress mutated decode scratch: %#v", adapter.decode)
				}

				serviceIngress(t, core, valid)
				if q.Readiness() != nscore.ReadyMDNSResult {
					t.Fatalf("valid response after malformed length readiness = %v", q.Readiness())
				}
				questionPayload, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, 1200)
				if err != nil {
					t.Fatal(err)
				}
				question := wrapMDNSFrame(t, questionPayload, [6]byte{2, 0, 0, 0, 0, 33}, netip.MustParseAddr("192.0.2.33"))
				setMDNSTestDestination(t, question, destination.mac, destination.ip)
				serviceIngress(t, core, question)
				core.Lock()
				queued = adapter.responseCount
				core.Unlock()
				if queued != 1 {
					t.Fatalf("valid question after malformed length queued %d responses", queued)
				}
			})
		}
	}
}

func TestMDNSIngressContainsTruncatedUDPOnlyAfterExactPortCorrelation(t *testing.T) {
	for available := 0; available < 8; available++ {
		cases := []struct {
			name        string
			sourcePort  uint16
			destPort    uint16
			wantHandled bool
		}{{name: "uncorrelatable"}}
		if available >= 4 {
			cases = []struct {
				name        string
				sourcePort  uint16
				destPort    uint16
				wantHandled bool
			}{
				{name: "foreign", sourcePort: Port, destPort: 9999},
				{name: "owned", sourcePort: Port, destPort: Port, wantHandled: true},
			}
		}
		for _, test := range cases {
			t.Run(fmt.Sprintf("bytes=%d/%s", available, test.name), func(t *testing.T) {
				service := testService("device", "192.0.2.11")
				core, adapter, _ := newTestAdapter(t, Config{
					Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
					MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
					MaxRecordsPerPacket: 16, MaxAttempts: 2, RetryServiceAttempts: 2,
				}, testPolicy())
				resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
				if err != nil {
					t.Fatal(err)
				}
				query := resource.(*query)
				_ = serviceEgress(t, core)

				frame := make([]byte, 14+20+available)
				eth, _ := ethernet.NewFrame(frame)
				*eth.DestinationHardwareAddr() = multicastMAC
				*eth.SourceHardwareAddr() = [6]byte{2, 0, 0, 0, 0, 22}
				eth.SetEtherType(ethernet.TypeIPv4)
				ip, _ := ipv4.NewFrame(frame[14:])
				ip.SetVersionAndIHL(4, 5)
				ip.SetTotalLength(uint16(20 + available))
				ip.SetTTL(255)
				ip.SetProtocol(lneto.IPProtoUDP)
				*ip.SourceAddr() = [4]byte{192, 0, 2, 22}
				*ip.DestinationAddr() = multicastAddress.As4()
				if available >= 4 {
					binary.BigEndian.PutUint16(frame[34:36], test.sourcePort)
					binary.BigEndian.PutUint16(frame[36:38], test.destPort)
				}
				ip.SetCRC(ip.CalculateHeaderCRC())

				core.Lock()
				handled, ingressErr := adapter.ingressLocked(frame)
				state, records, queued := query.state, len(query.records), adapter.responseCount
				decode := adapter.decode
				core.Unlock()
				if ingressErr != nil || handled != test.wantHandled || state != stateWaiting || records != 0 || queued != 0 || query.Readiness() != 0 {
					t.Fatalf("truncated ingress = handled:%v err:%v state:%v records:%d queued:%d readiness:%v", handled, ingressErr, state, records, queued, query.Readiness())
				}
				if len(decode.Questions) != 0 || len(decode.Answers) != 0 || len(decode.Authorities) != 0 || len(decode.Additionals) != 0 {
					t.Fatalf("truncated ingress mutated decode scratch: %#v", decode)
				}

				response, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
				if err != nil {
					t.Fatal(err)
				}
				serviceIngress(t, core, wrapMDNSFrame(t, response, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22")))
				if query.Readiness() != nscore.ReadyMDNSResult {
					t.Fatalf("valid response after truncated UDP readiness = %v", query.Readiness())
				}
			})
		}
	}
}

func TestMDNSIngressRejectsTrailingIPv4PayloadOutsideUDPDatagram(t *testing.T) {
	for _, test := range []struct {
		name     string
		payload  func(testing.TB) []byte
		response bool
	}{
		{
			name: "query",
			payload: func(t testing.TB) []byte {
				packet, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, 1200)
				if err != nil {
					t.Fatal(err)
				}
				return packet
			},
		},
		{
			name: "response",
			payload: func(t testing.TB) []byte {
				packet, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
				if err != nil {
					t.Fatal(err)
				}
				return packet
			},
			response: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := testService("device", "192.0.2.11")
			core, adapter, _ := newTestAdapter(t, Config{
				Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
				MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
				MaxRecordsPerPacket: 16, MaxAttempts: 2, RetryServiceAttempts: 2,
			}, testPolicy())
			resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
			if err != nil {
				t.Fatal(err)
			}
			query := resource.(*query)
			_ = serviceEgress(t, core)

			payload := test.payload(t)
			malformedPayload := append(append([]byte(nil), payload...), 0xa5)
			malformed := wrapMDNSFrame(t, malformedPayload, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22"))
			excludeLastIPv4PayloadByteFromUDP(t, malformed)
			core.Lock()
			handled, ingressErr := adapter.ingressLocked(malformed)
			state, records, queued := query.state, len(query.records), adapter.responseCount
			core.Unlock()
			if ingressErr != nil || !handled || state != stateWaiting || records != 0 || queued != 0 || query.Readiness() != 0 {
				t.Fatalf("mismatched UDP length = handled:%v err:%v state:%v records:%d queued:%d readiness:%v", handled, ingressErr, state, records, queued, query.Readiness())
			}

			valid := wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22"))
			serviceIngress(t, core, valid)
			core.Lock()
			state, records, queued = query.state, len(query.records), adapter.responseCount
			core.Unlock()
			if test.response {
				if state != stateDone || records == 0 || query.Readiness() != nscore.ReadyMDNSResult {
					t.Fatalf("valid response after mismatch = state:%v records:%d readiness:%v", state, records, query.Readiness())
				}
			} else if queued != 1 {
				t.Fatalf("valid query after mismatch queued %d responses", queued)
			}
		})
	}
}

func TestMDNSIngressContainsMismatchedLocalDestinationPairs(t *testing.T) {
	service := testService("device", "192.0.2.11")
	core, adapter, _ := newTestAdapter(t, Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 16, MaxAttempts: 2, RetryServiceAttempts: 2,
	}, testPolicy())
	resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		t.Fatal(err)
	}
	query := resource.(*query)
	_ = serviceEgress(t, core)
	responsePayload, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
	if err != nil {
		t.Fatal(err)
	}
	base := wrapMDNSFrame(t, responsePayload, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22"))
	localAddress := netip.MustParseAddr("192.0.2.11")
	for _, destination := range []struct {
		name string
		mac  [6]byte
		ip   netip.Addr
	}{
		{name: "multicast IP with unicast MAC", mac: adapter.hardwareAddress, ip: multicastAddress},
		{name: "unicast IP with multicast MAC", mac: multicastMAC, ip: localAddress},
	} {
		t.Run(destination.name, func(t *testing.T) {
			frame := append([]byte(nil), base...)
			setMDNSTestDestination(t, frame, destination.mac, destination.ip)
			core.Lock()
			handled, ingressErr := adapter.ingressLocked(frame)
			state, records, queued := query.state, len(query.records), adapter.responseCount
			core.Unlock()
			if ingressErr != nil || !handled {
				t.Fatalf("mismatched destination ingress = handled:%v err:%v", handled, ingressErr)
			}
			if state != stateWaiting || records != 0 || queued != 0 || query.Readiness() != 0 {
				t.Fatalf("mismatched destination mutated operation: state=%v records=%d queued=%d readiness=%v", state, records, queued, query.Readiness())
			}
		})
	}
	serviceIngress(t, core, base)
	if query.Readiness() != nscore.ReadyMDNSResult {
		t.Fatalf("valid response after mismatched destinations readiness = %v", query.Readiness())
	}
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
		{name: "foreign protocol with invalid source MAC", mutate: func(frame []byte) {
			eth, _ := ethernet.NewFrame(frame)
			*eth.SourceHardwareAddr() = [6]byte{1, 0, 0, 0, 0, 1}
			ip, _ := ipv4.NewFrame(eth.Payload())
			ip.SetProtocol(lneto.IPProtoTCP)
			ip.SetCRC(0)
			ip.SetCRC(ip.CalculateHeaderCRC())
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

func TestMDNSRejectsInvalidIPv4SourcesWithoutMutatingOperations(t *testing.T) {
	for _, sourceIP := range []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("255.255.255.255"),
	} {
		t.Run(sourceIP.String(), func(t *testing.T) {
			service := testService("device", "192.0.2.11")
			core, adapter, _ := newTestAdapter(t, Config{
				Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
				MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
				MaxRecordsPerPacket: 16, MaxAttempts: 1, RetryServiceAttempts: 1,
			}, testPolicy())
			resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
			if err != nil {
				t.Fatal(err)
			}
			query := resource.(*query)
			_ = serviceEgress(t, core)

			question, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, 1200)
			if err != nil {
				t.Fatal(err)
			}
			response, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
			if err != nil {
				t.Fatal(err)
			}
			for _, payload := range [][]byte{question, response} {
				frame := wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 22}, sourceIP)
				core.Lock()
				handled, ingressErr := adapter.ingressLocked(frame)
				queued := adapter.responseCount
				core.Unlock()
				if ingressErr != nil || !handled {
					t.Fatalf("ingress = handled %v, err %v", handled, ingressErr)
				}
				if queued != 0 || query.Readiness() != 0 {
					t.Fatalf("invalid source mutated operations: queued=%d readiness=%v", queued, query.Readiness())
				}
			}
		})
	}
}

func TestMDNSRejectsInvalidEthernetSourcesWithoutMutatingOperations(t *testing.T) {
	for _, sourceMAC := range [][6]byte{
		{},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x01, 0, 0x5e, 0, 0, 1},
	} {
		t.Run(net.HardwareAddr(sourceMAC[:]).String(), func(t *testing.T) {
			service := testService("device", "192.0.2.11")
			core, adapter, _ := newTestAdapter(t, Config{
				Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
				MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
				MaxRecordsPerPacket: 16, MaxAttempts: 1, RetryServiceAttempts: 1,
			}, testPolicy())
			resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
			if err != nil {
				t.Fatal(err)
			}
			query := resource.(*query)
			_ = serviceEgress(t, core)

			question, err := buildQueryPacket(mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}, 1200)
			if err != nil {
				t.Fatal(err)
			}
			response, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
			if err != nil {
				t.Fatal(err)
			}
			for _, payload := range [][]byte{question, response} {
				frame := wrapMDNSFrame(t, payload, sourceMAC, netip.MustParseAddr("192.0.2.22"))
				core.Lock()
				handled, ingressErr := adapter.ingressLocked(frame)
				queued := adapter.responseCount
				core.Unlock()
				if ingressErr != nil || !handled {
					t.Fatalf("ingress = handled %v, err %v", handled, ingressErr)
				}
				if queued != 0 || query.Readiness() != 0 {
					t.Fatalf("invalid source mutated operations: queued=%d readiness=%v", queued, query.Readiness())
				}
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

func TestMDNSCompressedKnownAnswerSuppressesResponseAndRejectsForwardPointer(t *testing.T) {
	service := testService("device", "192.0.2.11")
	config := Config{
		Services: []mdnsns.Service{service}, MaxServices: 1, MaxQueries: 1, MaxAnnouncements: 1,
		MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 4,
		MaxRecordsPerPacket: 4, MaxAttempts: 1, RetryServiceAttempts: 1,
	}
	core, adapter, _ := newTestAdapter(t, config, testPolicy())
	serviceType, err := lnetodns.NewName("_demo._udp.local")
	if err != nil {
		t.Fatal(err)
	}
	question := lnetodns.Question{Name: serviceType, Type: lnetodns.TypePTR, Class: lnetodns.ClassINET}
	message := lnetodns.Message{Questions: []lnetodns.Question{question}}
	payload, err := message.AppendTo(make([]byte, 0, config.MaxPacketBytes), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(payload[6:8], 1)
	answer := []byte{
		0xc0, 0x0c,
		0x00, byte(lnetodns.TypePTR),
		0x00, byte(lnetodns.ClassINET),
		0x00, 0x00, 0x00, 0x78,
		0x00, 0x09,
		0x06, 'd', 'e', 'v', 'i', 'c', 'e', 0xc0, 0x0c,
	}
	payload = append(payload, answer...)
	serviceIngress(t, core, wrapMDNSFrame(t, payload, [6]byte{2, 0, 0, 0, 0, 34}, netip.MustParseAddr("192.0.2.34")))
	core.Lock()
	queued := adapter.responseCount
	working := adapter.hasWorkLocked()
	core.Unlock()
	if queued != 0 || working {
		t.Fatalf("compressed known answer queued response: queued=%d working=%v", queued, working)
	}

	known, err := serviceResources(service, lnetodns.TypePTR)
	if err != nil || len(known) != 1 {
		t.Fatalf("service PTR resources = %d, %v", len(known), err)
	}
	decoded := lnetodns.Message{Questions: []lnetodns.Question{question}, Answers: known}
	malformed := append([]byte(nil), payload...)
	pointer := len(malformed) - 2
	malformed[pointer], malformed[pointer+1] = 0xc0, byte(pointer+1)
	if normalizeCompressedResourceNames(malformed, &decoded) {
		t.Fatal("forward compressed known-answer pointer accepted")
	}
}

func TestMDNSKnownAnswerComparisonCoversEveryServiceRecord(t *testing.T) {
	service := testService("device", "192.0.2.11")
	records, err := serviceResources(service, 0)
	if err != nil {
		t.Fatal(err)
	}
	byType := make(map[lnetodns.Type]lnetodns.Resource, len(records))
	for _, record := range records {
		byType[record.Header().Type] = record
	}
	for _, typ := range []lnetodns.Type{lnetodns.TypeA, lnetodns.TypePTR, lnetodns.TypeSRV, lnetodns.TypeTXT} {
		t.Run(typ.String(), func(t *testing.T) {
			candidate := byType[typ]
			if !sameKnownAnswer(candidate, candidate) {
				t.Fatal("exact known answer did not suppress")
			}
			threshold := service
			threshold.TTLSeconds = service.TTLSeconds / 2
			if !sameKnownAnswer(resourceOfType(t, threshold, typ), candidate) {
				t.Fatal("half-TTL known answer did not suppress")
			}
			low := service
			low.TTLSeconds = service.TTLSeconds/2 - 1
			if sameKnownAnswer(resourceOfType(t, low, typ), candidate) {
				t.Fatal("below-half-TTL known answer suppressed")
			}
			mismatch := service
			switch typ {
			case lnetodns.TypeA:
				mismatch.Address = netip.MustParseAddr("192.0.2.99")
			case lnetodns.TypePTR:
				mismatch.Name = "other._demo._udp.local"
			case lnetodns.TypeSRV:
				mismatch.Port++
			case lnetodns.TypeTXT:
				mismatch.TXT[3] = 'x'
			}
			if sameKnownAnswer(resourceOfType(t, mismatch, typ), candidate) {
				t.Fatal("mismatched RDATA suppressed")
			}
			if sameKnownAnswer(resourceWithHeader(t, candidate, candidate.Header().Name, lnetodns.Type(99), lnetodns.ClassINET, service.TTLSeconds), candidate) {
				t.Fatal("mismatched type suppressed")
			}
			otherName, err := lnetodns.NewName("other.local")
			if err != nil {
				t.Fatal(err)
			}
			if sameKnownAnswer(resourceWithHeader(t, candidate, otherName, typ, lnetodns.ClassINET, service.TTLSeconds), candidate) {
				t.Fatal("mismatched owner suppressed")
			}
			if sameKnownAnswer(resourceWithHeader(t, candidate, candidate.Header().Name, typ, lnetodns.Class(3), service.TTLSeconds), candidate) {
				t.Fatal("non-IN answer suppressed")
			}
		})
	}

	ptr := byType[lnetodns.TypePTR]
	malformedPTR := lnetodns.NewResource(ptr.Header().Name, lnetodns.TypePTR, lnetodns.ClassINET, service.TTLSeconds, []byte{0xc0, 0})
	if sameKnownAnswer(malformedPTR, ptr) {
		t.Fatal("malformed PTR target suppressed")
	}
	srv := byType[lnetodns.TypeSRV]
	malformedSRV := lnetodns.NewResource(srv.Header().Name, lnetodns.TypeSRV, lnetodns.ClassINET, service.TTLSeconds, []byte{0, 0, 0, 0, 0, 80, 0xc0})
	if sameKnownAnswer(malformedSRV, srv) {
		t.Fatal("malformed SRV target suppressed")
	}
}

func TestMDNSAutomaticResponsesPreserveDistinctServiceRDATAAndRecordLimit(t *testing.T) {
	first := testService("device", "192.0.2.11")
	second := testService("printer", "192.0.2.12")
	third := testService("camera", "192.0.2.13")
	third.Host = first.Host
	for _, test := range []struct {
		name       string
		queryName  string
		queryType  mdnsns.RecordTypes
		limit      uint16
		wantAnswer uint16
	}{
		{name: "distinct PTR targets", queryName: "_demo._udp.local", queryType: mdnsns.RecordsPTR, limit: 8, wantAnswer: 3},
		{name: "distinct host addresses", queryName: first.Host, queryType: mdnsns.RecordsA, limit: 8, wantAnswer: 2},
		{name: "bounded distinct PTR targets", queryName: "_demo._udp.local", queryType: mdnsns.RecordsPTR, limit: 2, wantAnswer: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := Config{
				Services: []mdnsns.Service{first, second, third}, MaxServices: 3, MaxQueries: 1, MaxAnnouncements: 1,
				MaxRecords: 8, MaxPacketBytes: 1200, MaxQueuedResponses: 1, MaxQuestionsPerPacket: 1,
				MaxRecordsPerPacket: test.limit, MaxAttempts: 1, RetryServiceAttempts: 1,
			}
			core, _, _ := newTestAdapter(t, config, testPolicy())
			payload, err := buildQueryPacket(mdnsns.Request{Name: test.queryName, Types: test.queryType}, config.MaxPacketBytes)
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
			if got := dnsFrame.ANCount(); got != test.wantAnswer {
				t.Fatalf("answers = %d, want %d", got, test.wantAnswer)
			}
		})
	}
}

func resourceOfType(t testing.TB, service mdnsns.Service, typ lnetodns.Type) lnetodns.Resource {
	t.Helper()
	resources, err := serviceResources(service, typ)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range resources {
		if resource.Header().Type == typ {
			return resource
		}
	}
	t.Fatalf("service resource %v missing", typ)
	return lnetodns.Resource{}
}

func resourceWithHeader(t testing.TB, source lnetodns.Resource, name lnetodns.Name, typ lnetodns.Type, class lnetodns.Class, ttl uint32) lnetodns.Resource {
	t.Helper()
	return lnetodns.NewResource(name, typ, class, ttl, append([]byte(nil), source.RawData()...))
}

func BenchmarkIngressQueryResponse(b *testing.B) {
	core, adapter, _ := newTestAdapter(b, queryOnlyConfig(), testPolicy())
	resource, _, err := adapter.TryQuery(mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA})
	if err != nil {
		b.Fatal(err)
	}
	q := resource.(*query)
	payload, err := buildServicePacket(testService("peer", "192.0.2.22"), lnetodns.TypeA, 1200)
	if err != nil {
		b.Fatal(err)
	}
	frame := wrapMDNSFrame(b, payload, [6]byte{2, 0, 0, 0, 0, 22}, netip.MustParseAddr("192.0.2.22"))
	core.Lock()
	defer core.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		q.records = q.records[:0]
		q.cursor = 0
		q.state = stateWaiting
		q.attempts = 1
		handled, err := adapter.ingressLocked(frame)
		if err != nil || !handled || q.state != stateDone || len(q.records) != 1 {
			b.Fatalf("ingress = handled %v, err %v, state %v, records %d", handled, err, q.state, len(q.records))
		}
	}
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
