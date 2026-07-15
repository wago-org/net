package ntp

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetontp "github.com/soypat/lneto/ntp"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

type manualClock struct {
	now   time.Time
	calls int
}

func (c *manualClock) Now() time.Time {
	c.calls++
	return c.now
}

func TestAdapterRequiresUnicastGatewayHardwareAddressWhenEnabled(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	config := Config{Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1, MaxAttempts: 1, RetryServiceAttempts: 1, Precision: -20}
	for name, gateway := range map[string][6]byte{
		"zero":      {},
		"multicast": {0x01, 0, 0, 0, 0, 1},
		"broadcast": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			common := newGatewayConfigTestCore(t, gateway)
			if _, err := New(common, config); err == nil {
				t.Fatalf("enabled NTP accepted gateway hardware address %v", gateway)
			}
			if _, err := New(common, Config{}); err != nil {
				t.Fatalf("disabled NTP rejected irrelevant gateway hardware address %v: %v", gateway, err)
			}
		})
	}
}

func TestNTPExchangeUsesExplicitClockValidatesRepliesAndReleasesQuota(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC)}
	core, adapter, account := newTestAdapter(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 2,
		MaxAttempts: 2, RetryServiceAttempts: 2, Precision: -20,
	})
	resource, progress, err := adapter.TrySync()
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TrySync = %T, %v, %v", resource, progress, err)
	}
	sync := resource.(*syncResource)
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, NTPResources: 1, NTPWork: 1}) {
		t.Fatalf("active quota = %+v, closed=%v", usage, closed)
	}
	if _, next, err := sync.TryResult(); err != nil || next != ntpns.NextWouldBlock {
		t.Fatalf("pending result = %v, %v", next, err)
	}

	request1 := serviceEgress(t, core)
	response1, arrival1 := makeNTPResponse(t, request1, 500*time.Millisecond, 20*time.Millisecond)
	clock.now = arrival1
	serviceIngress(t, core, response1)
	if got := sync.Readiness(); got != 0 {
		t.Fatalf("first exchange readiness = %v", got)
	}

	clock.now = arrival1.Add(100 * time.Millisecond)
	request2 := serviceEgress(t, core)
	response2, arrival2 := makeNTPResponse(t, request2, 500*time.Millisecond, 30*time.Millisecond)
	clock.now = ntpPayload(t, request2).TransmitTime().Time().Add(10 * time.Millisecond)
	serviceIngress(t, core, response1)
	if got := sync.Readiness(); got != 0 || sync.state != syncWaiting {
		t.Fatalf("stale first response during second exchange = readiness %v, state %v", got, sync.state)
	}
	clock.now = arrival2
	serviceIngress(t, core, response2)
	if got := sync.Readiness(); got != nscore.ReadyNTPResult {
		t.Fatalf("result readiness = %v", got)
	}
	sample, next, err := sync.TryResult()
	if err != nil || next != ntpns.NextReady || !sample.Valid() || sample.Server != netip.MustParseAddr("192.0.2.123") || sample.Stratum != 2 || sample.RoundTripDelay < 0 {
		t.Fatalf("sample = %+v, %v, %v", sample, next, err)
	}
	if usage, _ := account.Snapshot(); usage.NTPWork != 0 || usage.NTPResources != 1 {
		t.Fatalf("terminal quota = %+v", usage)
	}
	if err := sync.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed quota = %+v", usage)
	}
	if sync.sample != (ntpns.Sample{}) || sync.failure != nil || sync.portLease.UDPPort() != 0 {
		t.Fatalf("close retained state: %+v", sync)
	}
}

func TestEgressShortBufferPreservesPrepareStateClockAndRoundRobinOrder(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 14, 17, 0, 0, 0, time.UTC)}
	core, adapter, account := newTestAdapter(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 2,
		MaxAttempts: 2, RetryServiceAttempts: 2, Precision: -20,
	})
	firstResource, _, err := adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	secondResource, _, err := adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	first := firstResource.(*syncResource)
	second := secondResource.(*syncResource)
	firstRequest, secondRequest := first.request, second.request
	firstSample, secondSample := first.clockSample, second.clockSample
	clockCalls := clock.calls
	usageBefore, _ := account.Snapshot()
	firstReady, secondReady := first.Readiness(), second.Readiness()
	short := bytes.Repeat([]byte{0xa5}, 14+20+8+lnetontp.SizeHeader-1)

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
	if cursor != 0 || clock.calls != clockCalls || first.state != syncPrepare || second.state != syncPrepare || first.attempts != 0 || second.attempts != 0 || first.retry != 0 || second.retry != 0 || first.request != firstRequest || second.request != secondRequest || first.clockSample != firstSample || second.clockSample != secondSample {
		t.Fatalf("short egress mutated scheduler or syncs: cursor=%d clock=%d/%d first=%v/%d/%d second=%v/%d/%d", cursor, clock.calls, clockCalls, first.state, first.attempts, first.retry, second.state, second.attempts, second.retry)
	}
	if first.Readiness() != firstReady || second.Readiness() != secondReady {
		t.Fatalf("short egress changed readiness: first=%v/%v second=%v/%v", first.Readiness(), firstReady, second.Readiness(), secondReady)
	}
	if usage, _ := account.Snapshot(); usage != usageBefore {
		t.Fatalf("short egress changed quota = %+v, want %+v", usage, usageBefore)
	}

	frame := make([]byte, core.Link().MaxFrameBytes())
	core.Lock()
	firstBytes, firstWorked, err := adapter.egressLocked(frame)
	cursorAfterFirst := adapter.cursor
	core.Unlock()
	if err != nil || !firstWorked || firstBytes != 14+20+8+lnetontp.SizeHeader || cursorAfterFirst != 1 {
		t.Fatalf("first retry = %d, %v, %v, cursor=%d", firstBytes, firstWorked, err, cursorAfterFirst)
	}
	firstIP := ipv4Payload(t, frame[:firstBytes])
	firstUDP := udpPayload(t, frame[:firstBytes])
	if firstIP.ID() != 11 || firstUDP.SourcePort() != first.portLease.UDPPort() || first.state != syncWaiting || first.attempts != 1 || first.retry != 2 {
		t.Fatalf("first retry frame/state = id=%d port=%d state=%v attempts=%d retry=%d", firstIP.ID(), firstUDP.SourcePort(), first.state, first.attempts, first.retry)
	}

	core.Lock()
	secondBytes, secondWorked, err := adapter.egressLocked(frame)
	cursorAfterSecond := adapter.cursor
	core.Unlock()
	if err != nil || !secondWorked || secondBytes != 14+20+8+lnetontp.SizeHeader || cursorAfterSecond != 0 {
		t.Fatalf("second egress = %d, %v, %v, cursor=%d", secondBytes, secondWorked, err, cursorAfterSecond)
	}
	secondIP := ipv4Payload(t, frame[:secondBytes])
	secondUDP := udpPayload(t, frame[:secondBytes])
	if secondIP.ID() != 12 || secondUDP.SourcePort() != second.portLease.UDPPort() || second.state != syncWaiting || second.attempts != 1 || second.retry != 2 {
		t.Fatalf("second frame/state = id=%d port=%d state=%v attempts=%d retry=%d", secondIP.ID(), secondUDP.SourcePort(), second.state, second.attempts, second.retry)
	}
}

func TestNTPIngressRequiresLocalEthernetDestinationAndValidSource(t *testing.T) {
	for _, test := range []struct {
		name        string
		mutate      func(*ethernet.Frame)
		wantHandled bool
	}{
		{
			name: "foreign destination",
			mutate: func(frame *ethernet.Frame) {
				*frame.DestinationHardwareAddr() = [6]byte{2, 0, 0, 0, 0, 99}
			},
		},
		{
			name: "zero source",
			mutate: func(frame *ethernet.Frame) {
				*frame.SourceHardwareAddr() = [6]byte{}
			},
			wantHandled: true,
		},
		{
			name: "broadcast source",
			mutate: func(frame *ethernet.Frame) {
				*frame.SourceHardwareAddr() = ethernet.BroadcastAddr()
			},
			wantHandled: true,
		},
		{
			name: "multicast source",
			mutate: func(frame *ethernet.Frame) {
				*frame.SourceHardwareAddr() = [6]byte{1, 0, 0, 0, 0, 1}
			},
			wantHandled: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &manualClock{now: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC)}
			core, adapter, _ := newTestAdapter(t, clock, Config{
				Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
				MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
			})
			resource, _, err := adapter.TrySync()
			if err != nil {
				t.Fatal(err)
			}
			sync := resource.(*syncResource)
			request := serviceEgress(t, core)
			response, arrival := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
			clock.now = arrival
			ethernetFrame, err := ethernet.NewFrame(response)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&ethernetFrame)
			beforeClockSample, beforeRequest := sync.clockSample, sync.request

			core.Lock()
			handled, err := adapter.ingressLocked(response)
			core.Unlock()
			if err != nil || handled != test.wantHandled {
				t.Fatalf("ingress = handled %v, err %v; want handled %v", handled, err, test.wantHandled)
			}
			if sync.state != syncWaiting || sync.Readiness() != 0 || sync.sample != (ntpns.Sample{}) || sync.clockSample != beforeClockSample || sync.request != beforeRequest {
				t.Fatalf("foreign L2 frame mutated sync: state=%v readiness=%v sample=%+v clock_changed=%v request_changed=%v", sync.state, sync.Readiness(), sync.sample, sync.clockSample != beforeClockSample, sync.request != beforeRequest)
			}
		})
	}
}

func TestNTPRejectsMalformedServerResponseAndIgnoresOriginMismatch(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC)}
	core, adapter, _ := newTestAdapter(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
		MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
	})
	resource, _, err := adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	sync := resource.(*syncResource)
	request := serviceEgress(t, core)
	mismatch, arrival := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
	ntpFrame := ntpPayload(t, mismatch)
	ntpFrame.SetOriginTime(lnetontp.TimestampFromUint64(1))
	rechecksumUDP(t, mismatch)
	clock.now = arrival
	serviceIngress(t, core, mismatch)
	if got := sync.Readiness(); got != 0 {
		t.Fatalf("origin mismatch became terminal: %v", got)
	}

	malformedMismatch, _ := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
	ntpFrame = ntpPayload(t, malformedMismatch)
	ntpFrame.SetOriginTime(lnetontp.TimestampFromUint64(1))
	ntpFrame.SetFlags(lnetontp.ModeClient, lnetontp.Version4, lnetontp.LeapNoWarning)
	rechecksumUDP(t, malformedMismatch)
	serviceIngress(t, core, malformedMismatch)
	if got := sync.Readiness(); got != 0 {
		t.Fatalf("malformed origin mismatch became terminal: %v", got)
	}

	malformed, _ := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
	ntpFrame = ntpPayload(t, malformed)
	ntpFrame.SetFlags(lnetontp.ModeClient, lnetontp.Version4, lnetontp.LeapNoWarning)
	rechecksumUDP(t, malformed)
	serviceIngress(t, core, malformed)
	if got := sync.Readiness(); got != nscore.ReadyError {
		t.Fatalf("malformed readiness = %v", got)
	}
	if _, _, err := sync.TryResult(); failureOf(t, err) != nscore.FailureTemporary {
		t.Fatalf("malformed result = %v", err)
	}
}

func TestNTPMalformedTransportCannotRetireCorrelatedSynchronization(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(testing.TB, []byte) []byte
	}{
		{name: "declared IPv4 oversize", mutate: func(t testing.TB, frame []byte) []byte {
			ipFrame := ipv4Payload(t, frame)
			ipFrame.SetTotalLength(ipFrame.TotalLength() + 1)
			ipFrame.SetCRC(0)
			ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
			return frame
		}},
		{name: "declared IPv4 undersize", mutate: func(t testing.TB, frame []byte) []byte {
			ipFrame := ipv4Payload(t, frame)
			ipFrame.SetTotalLength(uint16(ipFrame.HeaderLength() + 7))
			ipFrame.SetCRC(0)
			ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
			return frame
		}},
		{name: "bad IPv4 checksum", mutate: func(t testing.TB, frame []byte) []byte {
			ipFrame := ipv4Payload(t, frame)
			ipFrame.SetCRC(ipFrame.CRC() ^ 1)
			return frame
		}},
		{name: "UDP and IPv4 length mismatch", mutate: func(t testing.TB, frame []byte) []byte {
			frame = append(frame, 0xa5)
			ipFrame := ipv4Payload(t, frame)
			ipFrame.SetTotalLength(ipFrame.TotalLength() + 1)
			ipFrame.SetCRC(0)
			ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
			return frame
		}},
		{name: "bad UDP checksum", mutate: func(t testing.TB, frame []byte) []byte {
			udpFrame := udpPayload(t, frame)
			udpFrame.SetCRC(udpFrame.CRC() ^ 1)
			return frame
		}},
		{name: "short NTP payload", mutate: func(t testing.TB, frame []byte) []byte {
			frame = frame[:len(frame)-1]
			ipFrame := ipv4Payload(t, frame)
			ipFrame.SetTotalLength(ipFrame.TotalLength() - 1)
			ipFrame.SetCRC(0)
			ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
			udpFrame := udpPayload(t, frame)
			udpFrame.SetLength(udpFrame.Length() - 1)
			rechecksumUDP(t, frame)
			return frame
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &manualClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
			core, adapter, account := newTestAdapter(t, clock, Config{
				Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
				MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
			})
			resource, _, err := adapter.TrySync()
			if err != nil {
				t.Fatal(err)
			}
			sync := resource.(*syncResource)
			request := serviceEgress(t, core)
			response, arrival := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
			malformed := test.mutate(t, append([]byte(nil), response...))
			clock.now = arrival

			core.Lock()
			handled, ingressErr := adapter.ingressLocked(malformed)
			core.Unlock()
			if ingressErr != nil || !handled {
				t.Fatalf("malformed ingress = handled %v, err %v", handled, ingressErr)
			}
			if sync.state != syncWaiting || sync.Readiness() != 0 || adapter.byPort[sync.portLease.UDPPort()] != sync {
				t.Fatalf("malformed transport retired synchronization: state=%v readiness=%v mapped=%v", sync.state, sync.Readiness(), adapter.byPort[sync.portLease.UDPPort()] == sync)
			}
			if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, NTPResources: 1, NTPWork: 1}) {
				t.Fatalf("malformed transport quota = %+v, closed=%v", usage, closed)
			}

			serviceIngress(t, core, response)
			if sync.state != syncPrepare || sync.Readiness() != 0 {
				t.Fatalf("valid response after malformed transport = state %v readiness %v", sync.state, sync.Readiness())
			}
		})
	}
}

func TestNTPIngressAcceptsIPv4OptionsAndIgnoresLinkPadding(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	core, adapter, _ := newTestAdapter(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
		MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
	})
	resource, _, err := adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	sync := resource.(*syncResource)
	request1 := serviceEgress(t, core)
	response1, arrival1 := makeNTPResponse(t, request1, 100*time.Millisecond, 20*time.Millisecond)
	response1 = addIPv4Options(t, response1, [4]byte{1, 1, 0, 0})
	response1 = append(response1, 0xa5, 0x5a, 0xc3)
	clock.now = arrival1
	serviceIngress(t, core, response1)
	if sync.state != syncPrepare || sync.Readiness() != 0 || sync.attempts != 0 || sync.retry != 0 {
		t.Fatalf("first response with options/padding = state %v readiness %v attempts %d retry %d", sync.state, sync.Readiness(), sync.attempts, sync.retry)
	}

	clock.now = arrival1.Add(100 * time.Millisecond)
	request2 := serviceEgress(t, core)
	response2, arrival2 := makeNTPResponse(t, request2, 100*time.Millisecond, 20*time.Millisecond)
	clock.now = arrival2
	serviceIngress(t, core, response2)
	if sync.Readiness() != nscore.ReadyNTPResult {
		t.Fatalf("second response readiness = %v", sync.Readiness())
	}
	if sample, next, err := sync.TryResult(); err != nil || next != ntpns.NextReady || !sample.Valid() {
		t.Fatalf("result after option-bearing first response = %+v, %v, %v", sample, next, err)
	}
}

func TestNTPMalformedTerminalRetiresTransportBeforeCloseAndStaleCloseCannotAffectFreshSync(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	core, adapter, account := newTestAdapter(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
		MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
	})
	resource, _, err := adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	failed := resource.(*syncResource)
	request := serviceEgress(t, core)
	failedPort := failed.portLease.UDPPort()
	malformed, arrival := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
	ntpFrame := ntpPayload(t, malformed)
	ntpFrame.SetFlags(lnetontp.ModeClient, lnetontp.Version4, lnetontp.LeapNoWarning)
	rechecksumUDP(t, malformed)
	clock.now = arrival
	serviceIngress(t, core, malformed)

	if failed.Readiness() != nscore.ReadyError {
		t.Fatalf("failed readiness = %v", failed.Readiness())
	}
	if _, _, err := failed.TryResult(); failureOf(t, err) != nscore.FailureTemporary {
		t.Fatalf("failed result = %v", err)
	}
	core.Lock()
	mapped := adapter.byPort[failedPort]
	leases := core.UDPPortLeaseCountLocked()
	core.Unlock()
	if mapped != nil || failed.portLease.UDPPort() != 0 || leases != 0 {
		t.Fatalf("terminal transport retained: mapped=%p port=%d leases=%d", mapped, failed.portLease.UDPPort(), leases)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, NTPResources: 1}) {
		t.Fatalf("terminal quota = %+v", usage)
	}

	valid, _ := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
	core.Lock()
	handled, err := adapter.ingressLocked(valid)
	core.Unlock()
	if err != nil || handled || failed.Readiness() != nscore.ReadyError {
		t.Fatalf("retired transport accepted late response: handled=%v err=%v readiness=%v", handled, err, failed.Readiness())
	}
	if _, _, err := adapter.TrySync(); failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("terminal resource concurrency = %v", err)
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	if failed.Readiness() != nscore.ReadyClosed || failed.request != ([lnetontp.SizeHeader]byte{}) || failed.sample != (ntpns.Sample{}) || failed.failure != nil || failed.clockSample != (time.Time{}) || failed.attempts != 0 || failed.retry != 0 {
		t.Fatalf("closed terminal resource retained state: %+v", failed)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed terminal quota = %+v", usage)
	}

	resource, _, err = adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	fresh := resource.(*syncResource)
	freshPort := fresh.portLease.UDPPort()
	if fresh == failed || freshPort == 0 || freshPort == failedPort || adapter.byPort[freshPort] != fresh {
		t.Fatalf("fresh sync transport = stale:%p fresh:%p ports:%d/%d mapped:%p", failed, fresh, failedPort, freshPort, adapter.byPort[freshPort])
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, NTPResources: 1, NTPWork: 1}) || adapter.byPort[freshPort] != fresh {
		t.Fatalf("stale close affected fresh sync: usage=%+v mapped=%p", usage, adapter.byPort[freshPort])
	}
}

func TestNTPStaleResponsesCannotMutateForcedPortReuseAfterTerminalFailure(t *testing.T) {
	for _, terminalize := range []struct {
		name string
		do   func(testing.TB, *lnetocore.Namespace, *syncResource)
	}{
		{
			name: "cancel",
			do: func(t testing.TB, _ *lnetocore.Namespace, sync *syncResource) {
				if err := sync.Cancel(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "timeout",
			do: func(t testing.TB, core *lnetocore.Namespace, _ *syncResource) {
				serviceMaintenance(t, core)
			},
		},
	} {
		t.Run(terminalize.name, func(t *testing.T) {
			clock := &manualClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
			core, adapter, account := newTestAdapter(t, clock, Config{
				Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 2,
				MaxAttempts: 1, RetryServiceAttempts: 1, Precision: -20,
			})
			resource, _, err := adapter.TrySync()
			if err != nil {
				t.Fatal(err)
			}
			stale := resource.(*syncResource)
			staleRequest := serviceEgress(t, core)
			stalePort := stale.portLease.UDPPort()
			staleResponse, _ := makeNTPResponse(t, staleRequest, 100*time.Millisecond, 20*time.Millisecond)
			terminalize.do(t, core, stale)
			if stale.state != syncFailed || stale.portLease.UDPPort() != 0 || adapter.byPort[stalePort] != nil {
				t.Fatalf("terminal stale transport = state %v port %d mapped %p", stale.state, stale.portLease.UDPPort(), adapter.byPort[stalePort])
			}

			adapter.nextPort = stalePort
			clock.now = clock.now.Add(time.Second)
			resource, _, err = adapter.TrySync()
			if err != nil {
				t.Fatal(err)
			}
			fresh := resource.(*syncResource)
			if fresh.portLease.UDPPort() != stalePort || adapter.byPort[stalePort] != fresh {
				t.Fatalf("forced port reuse = port %d mapped %p, want %d/%p", fresh.portLease.UDPPort(), adapter.byPort[stalePort], stalePort, fresh)
			}
			freshRequest1 := serviceEgress(t, core)
			beforeRequest, beforeClockSample, beforeCalls := fresh.request, fresh.clockSample, clock.calls
			core.Lock()
			handled, ingressErr := adapter.ingressLocked(staleResponse)
			core.Unlock()
			if ingressErr != nil || !handled {
				t.Fatalf("stale response on reused port = handled %v, err %v", handled, ingressErr)
			}
			if fresh.state != syncWaiting || fresh.Readiness() != 0 || fresh.request != beforeRequest || fresh.clockSample != beforeClockSample || clock.calls != beforeCalls {
				t.Fatalf("stale response mutated fresh sync: state=%v readiness=%v request_changed=%v clock_changed=%v calls=%d/%d", fresh.state, fresh.Readiness(), fresh.request != beforeRequest, fresh.clockSample != beforeClockSample, clock.calls, beforeCalls)
			}

			freshResponse1, arrival1 := makeNTPResponse(t, freshRequest1, 100*time.Millisecond, 20*time.Millisecond)
			clock.now = arrival1
			serviceIngress(t, core, freshResponse1)
			if fresh.state != syncPrepare || fresh.Readiness() != 0 {
				t.Fatalf("fresh first exchange = state %v readiness %v", fresh.state, fresh.Readiness())
			}
			clock.now = arrival1.Add(time.Second)
			freshRequest2 := serviceEgress(t, core)
			freshResponse2, arrival2 := makeNTPResponse(t, freshRequest2, 100*time.Millisecond, 20*time.Millisecond)
			clock.now = arrival2
			serviceIngress(t, core, freshResponse2)
			if fresh.Readiness() != nscore.ReadyNTPResult {
				t.Fatalf("fresh completion readiness = %v", fresh.Readiness())
			}
			if sample, next, err := fresh.TryResult(); err != nil || next != ntpns.NextReady || !sample.Valid() {
				t.Fatalf("fresh result = %+v, %v, %v", sample, next, err)
			}
			if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 2, NTPResources: 2}) {
				t.Fatalf("terminal and completed quota = %+v, closed=%v", usage, closed)
			}
		})
	}
}

func TestNTPClockFailuresRetireTransportAndReleaseWork(t *testing.T) {
	validTime := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		clockTime func([]byte, time.Time) time.Time
		wantCause error
	}{
		{
			name: "clock moved backward",
			clockTime: func(request []byte, _ time.Time) time.Time {
				return ntpPayload(t, request).TransmitTime().Time().Add(-time.Nanosecond)
			},
			wantCause: errClockBackward,
		},
		{
			name: "clock left NTP timestamp range",
			clockTime: func(_ []byte, _ time.Time) time.Time {
				return time.Date(1800, 1, 1, 0, 0, 0, 0, time.UTC)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &manualClock{now: validTime}
			core, adapter, account := newTestAdapter(t, clock, Config{
				Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
				MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
			})
			resource, _, err := adapter.TrySync()
			if err != nil {
				t.Fatal(err)
			}
			sync := resource.(*syncResource)
			request := serviceEgress(t, core)
			port := sync.portLease.UDPPort()
			response, arrival := makeNTPResponse(t, request, 100*time.Millisecond, 20*time.Millisecond)
			clock.now = test.clockTime(request, arrival)
			serviceIngress(t, core, response)

			if sync.state != syncFailed || sync.Readiness() != nscore.ReadyError || sync.portLease.UDPPort() != 0 {
				t.Fatalf("clock failure state = %v readiness=%v port=%d", sync.state, sync.Readiness(), sync.portLease.UDPPort())
			}
			_, _, resultErr := sync.TryResult()
			if failureOf(t, resultErr) != nscore.FailureInvalidState || test.wantCause != nil && !errors.Is(resultErr, test.wantCause) {
				t.Fatalf("clock failure result = %v", resultErr)
			}
			core.Lock()
			mapped := adapter.byPort[port]
			leases := core.UDPPortLeaseCountLocked()
			core.Unlock()
			if mapped != nil || leases != 0 {
				t.Fatalf("clock failure retained transport: mapped=%p leases=%d", mapped, leases)
			}
			if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, NTPResources: 1}) {
				t.Fatalf("clock failure quota = %+v", usage)
			}

			clock.now = arrival
			core.Lock()
			handled, ingressErr := adapter.ingressLocked(response)
			core.Unlock()
			if ingressErr != nil || handled || sync.Readiness() != nscore.ReadyError {
				t.Fatalf("late response after clock failure = handled:%v err:%v readiness:%v", handled, ingressErr, sync.Readiness())
			}
			if err := sync.Close(); err != nil {
				t.Fatal(err)
			}
			if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
				t.Fatalf("closed clock failure quota = %+v", usage)
			}
		})
	}
}

func TestNTPPrepareRejectsOutOfRangeClockWithoutPublishingPacket(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	core, adapter, account := newTestAdapter(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
		MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
	})
	resource, _, err := adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	sync := resource.(*syncResource)
	port := sync.portLease.UDPPort()
	clock.now = time.Date(1800, 1, 1, 0, 0, 0, 0, time.UTC)
	frame := bytes.Repeat([]byte{0xa5}, core.Link().MaxFrameBytes())
	core.Lock()
	written, worked, egressErr := adapter.egressLocked(frame)
	mapped := adapter.byPort[port]
	leases := core.UDPPortLeaseCountLocked()
	core.Unlock()
	if egressErr != nil || !worked || written != 0 {
		t.Fatalf("out-of-range prepare = %d, %v, %v", written, worked, egressErr)
	}
	if !bytes.Equal(frame, bytes.Repeat([]byte{0xa5}, len(frame))) {
		t.Fatal("out-of-range prepare mutated packet destination")
	}
	if sync.state != syncFailed || sync.Readiness() != nscore.ReadyError || mapped != nil || leases != 0 || sync.portLease.UDPPort() != 0 {
		t.Fatalf("out-of-range prepare retained lifecycle: state=%v readiness=%v mapped=%p leases=%d port=%d", sync.state, sync.Readiness(), mapped, leases, sync.portLease.UDPPort())
	}
	if _, _, resultErr := sync.TryResult(); failureOf(t, resultErr) != nscore.FailureInvalidState {
		t.Fatalf("out-of-range prepare result = %v", resultErr)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, NTPResources: 1}) {
		t.Fatalf("out-of-range prepare quota = %+v", usage)
	}
}

func TestNTPPolicyLimitsTimeoutCancelAndClose(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC)}
	core, adapter, account := newTestAdapterWithPolicy(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
		MaxAttempts: 1, RetryServiceAttempts: 1, Precision: -20,
	}, policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportNTP},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.123/32")},
	}, {
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportNTP},
		Directions: []policy.Direction{policy.DirectionOutbound}, Ports: []policy.PortRange{{First: 123, Last: 123}},
	}}})
	if _, _, err := adapter.TrySync(); failureOf(t, err) != nscore.FailureAccessDenied {
		t.Fatalf("deny-wins sync = %v", err)
	}
	_ = core.Close()
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("denied operation leaked quota: %+v", usage)
	}

	core, adapter, account = newTestAdapter(t, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
		MaxAttempts: 1, RetryServiceAttempts: 1, Precision: -20,
	})
	resource, _, err := adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	sync := resource.(*syncResource)
	if _, _, err := adapter.TrySync(); failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("concurrency limit = %v", err)
	}
	_ = serviceEgress(t, core)
	serviceMaintenance(t, core)
	if _, _, err := sync.TryResult(); failureOf(t, err) != nscore.FailureTimedOut {
		t.Fatalf("timeout result = %v", err)
	}
	if err := sync.Close(); err != nil {
		t.Fatal(err)
	}
	resource, _, err = adapter.TrySync()
	if err != nil {
		t.Fatal(err)
	}
	sync = resource.(*syncResource)
	if err := sync.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sync.TryResult(); failureOf(t, err) != nscore.FailureCanceled {
		t.Fatalf("canceled result = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if got := sync.Readiness(); got != nscore.ReadyClosed {
		t.Fatalf("closed readiness = %v", got)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close retained quota = %+v", usage)
	}
}

func TestNTPZeroConfigRetainsTruthfulServiceSemantics(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, nil, Config{})
	if _, _, err := adapter.TrySync(); failureOf(t, err) != nscore.FailureNotSupported {
		t.Fatalf("disabled sync = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TrySync(); failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("closed disabled sync = %v", err)
	}
}

func TestNTPConfigIsFiniteExplicitClockAndZeroDisables(t *testing.T) {
	if !ValidConfig(Config{}, nil, nil, false) {
		t.Fatal("zero disabled config rejected")
	}
	clock := &manualClock{now: time.Now().UTC()}
	for _, invalid := range []Config{
		{MaxSyncs: 1},
		{Server: netip.MustParseAddr("127.0.0.1"), Clock: clock, MaxSyncs: 1, MaxAttempts: 1, RetryServiceAttempts: 1, Precision: -20},
		{Server: netip.MustParseAddr("224.0.0.1"), Clock: clock, MaxSyncs: 1, MaxAttempts: 1, RetryServiceAttempts: 1, Precision: -20},
		{Server: netip.MustParseAddr("192.0.2.1"), Clock: clock, MaxSyncs: 1, RetryServiceAttempts: 1, Precision: -20},
		{Server: netip.MustParseAddr("192.0.2.1"), Clock: clock, MaxSyncs: 1, MaxAttempts: 1, Precision: 1},
	} {
		if ValidConfig(invalid, nil, nil, false) {
			t.Fatalf("invalid config accepted: %+v", invalid)
		}
	}
	var nilClock *manualClock
	if ValidConfig(Config{Server: netip.MustParseAddr("192.0.2.1"), Clock: nilClock, MaxSyncs: 1, MaxAttempts: 1, RetryServiceAttempts: 1, Precision: -20}, nil, nil, false) {
		t.Fatal("typed nil clock accepted")
	}
}

func newGatewayConfigTestCore(t testing.TB, gateway [6]byte) *lnetocore.Namespace {
	t.Helper()
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportNTP},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		Ports: []policy.PortRange{{First: 123, Last: 123}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "ntp-config", RandSeed: 12,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 12}, GatewayHardwareAddress: gateway,
		IPv4Address: netip.MustParseAddr("192.0.2.12"), MTU: 1500,
		Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1}, Policy: compiled, Quotas: quota.NewAccount(quota.DefaultLimits()),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	return core
}

func newTestAdapter(t testing.TB, clock *manualClock, config Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	return newTestAdapterWithPolicy(t, clock, config, policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportNTP},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		Ports: []policy.PortRange{{First: 123, Last: 123}},
	}}})
}

func newTestAdapterWithPolicy(t testing.TB, _ *manualClock, config Config, policyConfig policy.Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	compiled, err := policy.Compile(policyConfig)
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 4, NTPResources: 4, NTPWork: 4})
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "ntp", RandSeed: 11,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 11}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.11"), MTU: 1500,
		Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4}, Policy: compiled, Quotas: account,
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

func makeNTPResponse(t testing.TB, request []byte, serverOffset, roundTrip time.Duration) ([]byte, time.Time) {
	t.Helper()
	frame := append([]byte(nil), request...)
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	sourceMAC, destinationMAC := *ethernetFrame.SourceHardwareAddr(), *ethernetFrame.DestinationHardwareAddr()
	*ethernetFrame.SourceHardwareAddr() = destinationMAC
	*ethernetFrame.DestinationHardwareAddr() = sourceMAC
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	sourceIP, destinationIP := *ipFrame.SourceAddr(), *ipFrame.DestinationAddr()
	*ipFrame.SourceAddr() = destinationIP
	*ipFrame.DestinationAddr() = sourceIP
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	sourcePort, destinationPort := udpFrame.SourcePort(), udpFrame.DestinationPort()
	udpFrame.SetSourcePort(destinationPort)
	udpFrame.SetDestinationPort(sourcePort)
	ntpFrame := ntpPayload(t, frame)
	origin := ntpFrame.TransmitTime()
	clientSend := origin.Time()
	serverReceive, err := lnetontp.TimestampFromTime(clientSend.Add(serverOffset + roundTrip/4))
	if err != nil {
		t.Fatal(err)
	}
	serverTransmit, err := lnetontp.TimestampFromTime(clientSend.Add(serverOffset + roundTrip/2))
	if err != nil {
		t.Fatal(err)
	}
	ntpFrame.ClearHeader()
	ntpFrame.SetFlags(lnetontp.ModeServer, lnetontp.Version4, lnetontp.LeapNoWarning)
	ntpFrame.SetStratum(2)
	*ntpFrame.ReferenceID() = [4]byte{'G', 'P', 'S', 0}
	ntpFrame.SetOriginTime(origin)
	ntpFrame.SetReceiveTime(serverReceive)
	ntpFrame.SetTransmitTime(serverTransmit)
	ipFrame.SetCRC(0)
	ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
	rechecksumUDP(t, frame)
	return frame, clientSend.Add(roundTrip)
}

func addIPv4Options(t testing.TB, frame []byte, options [4]byte) []byte {
	t.Helper()
	if ip := ipv4Payload(t, frame); ip.HeaderLength() != 20 {
		t.Fatalf("test frame IPv4 header length = %d", ip.HeaderLength())
	}
	withOptions := make([]byte, len(frame)+len(options))
	copy(withOptions[:14+20], frame[:14+20])
	copy(withOptions[14+20:14+24], options[:])
	copy(withOptions[14+24:], frame[14+20:])
	ethernetFrame, err := ethernet.NewFrame(withOptions)
	if err != nil {
		t.Fatal(err)
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	ipFrame.SetVersionAndIHL(4, 6)
	ipFrame.SetTotalLength(ipFrame.TotalLength() + uint16(len(options)))
	ipFrame.SetCRC(0)
	ipFrame.SetCRC(ipv4HeaderChecksum(ipFrame.RawData()[:24]))
	udpFrame, err := lnetoudp.NewFrame(ipFrame.RawData()[24:int(ipFrame.TotalLength())])
	if err != nil {
		t.Fatal(err)
	}
	udpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
	udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
	return withOptions
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for offset := 0; offset < len(header); offset += 2 {
		sum += uint32(header[offset])<<8 | uint32(header[offset+1])
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipv4Payload(t testing.TB, frame []byte) ipv4.Frame {
	t.Helper()
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	return ipFrame
}

func udpPayload(t testing.TB, frame []byte) lnetoudp.Frame {
	t.Helper()
	ipFrame := ipv4Payload(t, frame)
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	return udpFrame
}

func ntpPayload(t testing.TB, frame []byte) lnetontp.Frame {
	t.Helper()
	udpFrame := udpPayload(t, frame)
	ntpFrame, err := lnetontp.NewFrame(udpFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	return ntpFrame
}

func rechecksumUDP(t testing.TB, frame []byte) {
	t.Helper()
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
	udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
}

var (
	benchmarkNTPHandled bool
	benchmarkNTPErr     error
)

func BenchmarkIngressNTPOriginMismatch(b *testing.B) {
	clock := &manualClock{now: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC)}
	core, adapter, _ := newTestAdapter(b, clock, Config{
		Server: netip.MustParseAddr("192.0.2.123"), Clock: clock, MaxSyncs: 1,
		MaxAttempts: 1, RetryServiceAttempts: 2, Precision: -20,
	})
	resource, _, err := adapter.TrySync()
	if err != nil {
		b.Fatal(err)
	}
	request := serviceEgress(b, core)
	response, arrival := makeNTPResponse(b, request, 100*time.Millisecond, 20*time.Millisecond)
	ntpFrame := ntpPayload(b, response)
	ntpFrame.SetOriginTime(lnetontp.TimestampFromUint64(1))
	rechecksumUDP(b, response)
	clock.now = arrival
	b.SetBytes(int64(len(response)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		core.Lock()
		benchmarkNTPHandled, benchmarkNTPErr = adapter.ingressLocked(response)
		core.Unlock()
		if benchmarkNTPErr != nil || !benchmarkNTPHandled || resource.(*syncResource).state != syncWaiting {
			b.Fatalf("ingress = %v, %v, state %v", benchmarkNTPHandled, benchmarkNTPErr, resource.(*syncResource).state)
		}
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
