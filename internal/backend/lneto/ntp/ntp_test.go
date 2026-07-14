package ntp

import (
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

type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time { return c.now }

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

func ntpPayload(t testing.TB, frame []byte) lnetontp.Frame {
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
