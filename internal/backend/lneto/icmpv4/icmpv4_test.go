package icmpv4

import (
	"bytes"
	"net/netip"
	"testing"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoicmp "github.com/soypat/lneto/ipv4/icmpv4"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestICMPv4ExchangeCopiesPayloadValidatesReplyAndReleasesQuota(t *testing.T) {
	core, adapter, account := newTestAdapter(t, Config{MaxEchoes: 2, MaxPayloadBytes: 64, MaxAttempts: 2, RetryServiceAttempts: 2})
	guestPayload := []byte("bounded-echo")
	resource, progress, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: guestPayload})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryEcho = %T, %v, %v", resource, progress, err)
	}
	exchange := resource.(*echo)
	guestPayload[0] = 'X'
	if string(exchange.payload) != "bounded-echo" {
		t.Fatalf("adapter retained guest payload: %q", exchange.payload)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, ICMPv4Resources: 1, QueuedBytes: 12, ICMPv4Work: 1}) {
		t.Fatalf("active quota = %+v, closed=%v", usage, closed)
	}
	if _, next, err := exchange.TryResult(nil); err != nil || next != icmpns.NextWouldBlock {
		t.Fatalf("pending result = %v, %v", next, err)
	}

	requestFrame := serviceEgress(t, core)
	reply := makeEchoReply(t, requestFrame, nil)
	serviceIngress(t, core, reply)
	if got := exchange.Readiness(); got != nscore.ReadyICMPv4Reply {
		t.Fatalf("reply readiness = %v", got)
	}
	var dst [4]byte
	result, next, err := exchange.TryResult(dst[:])
	if err != nil || next != icmpns.NextReady || !result.Valid(len(dst)) || string(dst[:]) != "boun" || result.PayloadBytes != 12 || result.Source != netip.MustParseAddr("192.0.2.99") {
		t.Fatalf("reply result = %+v, %v, %v, payload=%q", result, next, err, dst[:])
	}
	if usage, _ := account.Snapshot(); usage.ICMPv4Work != 0 || usage.ICMPv4Resources != 1 || usage.QueuedBytes != 12 {
		t.Fatalf("terminal quota = %+v", usage)
	}
	if err := exchange.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed quota = %+v", usage)
	}
	if exchange.payload != nil || exchange.destination.IsValid() || exchange.identifier != 0 || exchange.sequence != 0 || exchange.failure != nil {
		t.Fatalf("close retained state: %+v", exchange)
	}
}

func TestICMPv4ReplyMismatchFailsClosedAndLateReplyCannotMutate(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, Config{MaxEchoes: 1, MaxPayloadBytes: 32, MaxAttempts: 1, RetryServiceAttempts: 1})
	resource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("exact")})
	if err != nil {
		t.Fatal(err)
	}
	exchange := resource.(*echo)
	request := serviceEgress(t, core)
	serviceIngress(t, core, makeEchoReply(t, request, []byte("wrong")))
	if got := exchange.Readiness(); got != nscore.ReadyError {
		t.Fatalf("mismatch readiness = %v", got)
	}
	if _, _, err := exchange.TryResult(make([]byte, 8)); failureOf(t, err) != nscore.FailureIO {
		t.Fatalf("mismatch result error = %v", err)
	}
	serviceIngress(t, core, makeEchoReply(t, request, nil))
	if _, _, err := exchange.TryResult(make([]byte, 8)); failureOf(t, err) != nscore.FailureIO {
		t.Fatalf("late reply changed failure = %v", err)
	}
	if err := exchange.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestICMPv4PolicyLimitsTimeoutCancelAndClose(t *testing.T) {
	core, adapter, account := newTestAdapter(t, Config{MaxEchoes: 1, MaxPayloadBytes: 4, MaxAttempts: 1, RetryServiceAttempts: 1})
	if _, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("198.51.100.1")}); failureOf(t, err) != nscore.FailureAccessDenied {
		t.Fatalf("policy denial = %v", err)
	}
	if _, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: make([]byte, 5)}); failureOf(t, err) != nscore.FailureMessageTooLarge {
		t.Fatalf("payload limit = %v", err)
	}
	resource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99")})
	if err != nil {
		t.Fatal(err)
	}
	exchange := resource.(*echo)
	if _, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.100")}); failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("concurrency limit = %v", err)
	}
	_ = serviceEgress(t, core)
	serviceMaintenance(t, core)
	if got := exchange.Readiness(); got != nscore.ReadyError {
		t.Fatalf("timeout readiness = %v", got)
	}
	if _, _, err := exchange.TryResult(nil); failureOf(t, err) != nscore.FailureTimedOut {
		t.Fatalf("timeout result = %v", err)
	}
	if err := exchange.Close(); err != nil {
		t.Fatal(err)
	}

	resource, _, err = adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("ok")})
	if err != nil {
		t.Fatal(err)
	}
	exchange = resource.(*echo)
	if err := exchange.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := exchange.TryResult(nil); failureOf(t, err) != nscore.FailureCanceled {
		t.Fatalf("canceled result = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if got := exchange.Readiness(); got != nscore.ReadyClosed {
		t.Fatalf("closed readiness = %v", got)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close retained quota = %+v", usage)
	}
}

func TestICMPv4ZeroConfigRetainsTruthfulServiceSemantics(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, Config{})
	if _, _, err := adapter.TryEcho(icmpns.Request{}); failureOf(t, err) != nscore.FailureInvalidArgument {
		t.Fatalf("invalid disabled echo = %v", err)
	}
	request := icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99")}
	if _, _, err := adapter.TryEcho(request); failureOf(t, err) != nscore.FailureNotSupported {
		t.Fatalf("disabled echo = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TryEcho(request); failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("closed disabled echo = %v", err)
	}
}

func TestICMPv4ConfigIsFiniteAndZeroDisables(t *testing.T) {
	if !ValidConfig(Config{}, 1500, nil, nil, false) {
		t.Fatal("zero disabled config rejected")
	}
	for _, invalid := range []Config{
		{MaxEchoes: 1},
		{MaxEchoes: 1, MaxPayloadBytes: 1473, MaxAttempts: 1, RetryServiceAttempts: 1},
		{MaxEchoes: 1, MaxPayloadBytes: 1, MaxAttempts: 0, RetryServiceAttempts: 1},
		{MaxEchoes: 1, MaxPayloadBytes: 1, MaxAttempts: 1, RetryServiceAttempts: 0},
	} {
		if ValidConfig(invalid, 1500, nil, nil, false) {
			t.Fatalf("invalid config accepted: %+v", invalid)
		}
	}
	tooLarge := Config{MaxEchoes: 1, MaxPayloadBytes: icmpns.MaxEchoPayloadBytes + 1, MaxAttempts: 1, RetryServiceAttempts: 1}
	if ValidConfig(tooLarge, tooLarge.MaxPayloadBytes+28, nil, nil, false) {
		t.Fatal("unrepresentable ICMPv4 payload config accepted")
	}
}

func newTestAdapter(t testing.TB, adapterConfig Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportICMPv4},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 4, ICMPv4Resources: 4, QueuedBytes: 1024, ICMPv4Work: 4})
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "icmpv4", RandSeed: 9,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 9}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.9"), MTU: 1500,
		Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	adapter, err := New(core, adapterConfig)
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
	budget := nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1}
	report, progress, err := core.TryService(budget)
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

func makeEchoReply(t testing.TB, request []byte, payloadOverride []byte) []byte {
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
	ipFrame.SetCRC(0)
	ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
	icmpFrame, err := lnetoicmp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	echoFrame := lnetoicmp.FrameEcho{Frame: icmpFrame}
	echoFrame.SetType(lnetoicmp.TypeEchoReply)
	if payloadOverride != nil {
		if len(payloadOverride) != len(echoFrame.Data()) {
			t.Fatalf("override bytes = %d, want %d", len(payloadOverride), len(echoFrame.Data()))
		}
		copy(echoFrame.Data(), payloadOverride)
	}
	echoFrame.SetCRC(0)
	var checksum lneto.CRC791
	echoFrame.SetCRC(checksum.PayloadSum16(echoFrame.RawData()))
	return frame
}

func failureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("missing semantic failure: %v", err)
	}
	return failure
}

func TestEchoReplyBuilderPreservesWirePayload(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, Config{MaxEchoes: 1, MaxPayloadBytes: 16, MaxAttempts: 1, RetryServiceAttempts: 1})
	_, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("wire")})
	if err != nil {
		t.Fatal(err)
	}
	request := serviceEgress(t, core)
	reply := makeEchoReply(t, request, nil)
	if bytes.Equal(request[:12], reply[:12]) || !bytes.Equal(request[42:], reply[42:]) {
		t.Fatalf("reply framing did not swap endpoints and preserve payload")
	}
}

func TestICMPv4IngressRejectsForeignEthernetIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ethernet.Frame)
	}{
		{
			name: "foreign destination",
			mutate: func(frame *ethernet.Frame) {
				*frame.DestinationHardwareAddr() = [6]byte{2, 0, 0, 0, 0, 8}
			},
		},
		{
			name: "multicast source",
			mutate: func(frame *ethernet.Frame) {
				*frame.SourceHardwareAddr() = [6]byte{1, 0, 0, 0, 0, 1}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, adapter, _ := newTestAdapter(t, Config{MaxEchoes: 1, MaxPayloadBytes: 16, MaxAttempts: 1, RetryServiceAttempts: 2})
			resource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("wire")})
			if err != nil {
				t.Fatal(err)
			}
			exchange := resource.(*echo)
			request := serviceEgress(t, core)
			reply := makeEchoReply(t, request, nil)
			frame, err := ethernet.NewFrame(reply)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&frame)
			serviceIngress(t, core, reply)
			if _, next, err := exchange.TryResult(nil); err != nil || next != icmpns.NextWouldBlock {
				t.Fatalf("foreign frame completed exchange: next=%v err=%v", next, err)
			}
		})
	}
}

func TestICMPv4ClosedExchangeLateReplyAndStaleCloseCannotMutateFreshExchange(t *testing.T) {
	core, adapter, account := newTestAdapter(t, Config{MaxEchoes: 1, MaxPayloadBytes: 16, MaxAttempts: 2, RetryServiceAttempts: 2})
	request := icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("fresh")}
	resource, _, err := adapter.TryEcho(request)
	if err != nil {
		t.Fatal(err)
	}
	stale := resource.(*echo)
	staleRequest := serviceEgress(t, core)
	staleIdentifier, staleSequence := stale.identifier, stale.sequence
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	resource, _, err = adapter.TryEcho(request)
	if err != nil {
		t.Fatal(err)
	}
	fresh := resource.(*echo)
	if fresh.identifier == staleIdentifier && fresh.sequence == staleSequence {
		t.Fatalf("fresh exchange reused live-stale identity %d/%d", fresh.identifier, fresh.sequence)
	}
	freshRequest := serviceEgress(t, core)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	handled, ingressErr := adapter.ingressLocked(makeEchoReply(t, staleRequest, nil))
	freshState, freshAttempts := fresh.state, fresh.attempts
	core.Unlock()
	if ingressErr != nil || handled {
		t.Fatalf("late stale reply = handled %v, err %v", handled, ingressErr)
	}
	if freshState != echoWaiting || freshAttempts != 1 || fresh.Readiness() != 0 {
		t.Fatalf("late stale reply mutated fresh exchange: state=%v attempts=%d readiness=%v", freshState, freshAttempts, fresh.Readiness())
	}
	serviceIngress(t, core, makeEchoReply(t, freshRequest, nil))
	var payload [8]byte
	result, next, err := fresh.TryResult(payload[:])
	if err != nil || next != icmpns.NextReady || result.Source != request.Destination || result.Copied != len(request.Payload) || result.PayloadBytes != len(request.Payload) || string(payload[:len(request.Payload)]) != string(request.Payload) {
		t.Fatalf("fresh result = %+v, %v, %v payload=%q", result, next, err, payload[:])
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, ICMPv4Resources: 1, QueuedBytes: uint64(len(request.Payload))}) {
		t.Fatalf("fresh terminal quota = %+v, closed=%v", usage, closed)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("fresh close quota = %+v", usage)
	}
}

func TestICMPv4DropsMalformedCorrelatedIPv4AndAcceptsFollowingReply(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, []byte)
	}{
		{
			name: "bad IPv4 checksum",
			mutate: func(_ *testing.T, frame []byte) {
				frame[14+8] ^= 1
			},
		},
		{
			name: "fragmented IPv4",
			mutate: func(t *testing.T, frame []byte) {
				ethernetFrame, err := ethernet.NewFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				ipFrame.SetFlags(ipv4.FlagMoreFragments)
				ipFrame.SetCRC(0)
				ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, adapter, _ := newTestAdapter(t, Config{MaxEchoes: 1, MaxPayloadBytes: 16, MaxAttempts: 2, RetryServiceAttempts: 2})
			resource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("live")})
			if err != nil {
				t.Fatal(err)
			}
			exchange := resource.(*echo)
			request := serviceEgress(t, core)
			malformed := makeEchoReply(t, request, nil)
			test.mutate(t, malformed)

			core.Lock()
			handled, ingressErr := adapter.ingressLocked(malformed)
			state, mapped := exchange.state, adapter.byIdentity[identityKey(exchange.identifier, exchange.sequence)]
			core.Unlock()
			if ingressErr != nil || !handled || state != echoWaiting || mapped != exchange || exchange.Readiness() != 0 {
				t.Fatalf("malformed reply = handled %v, err %v, state %v, mapped %p, readiness %v", handled, ingressErr, state, mapped, exchange.Readiness())
			}

			core.Lock()
			handled, ingressErr = adapter.ingressLocked(makeEchoReply(t, request, nil))
			core.Unlock()
			if ingressErr != nil || !handled || exchange.Readiness() != nscore.ReadyICMPv4Reply {
				t.Fatalf("following valid reply = handled %v, err %v, readiness %v", handled, ingressErr, exchange.Readiness())
			}
		})
	}
}

func TestICMPv4ChecksumFailureAndNamespaceCloseClearTerminalAndActiveState(t *testing.T) {
	core, adapter, account := newTestAdapter(t, Config{MaxEchoes: 2, MaxPayloadBytes: 16, MaxAttempts: 2, RetryServiceAttempts: 2})
	failedResource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.98"), Payload: []byte("bad")})
	if err != nil {
		t.Fatal(err)
	}
	failed := failedResource.(*echo)
	failedRequest := serviceEgress(t, core)
	badReply := makeEchoReply(t, failedRequest, nil)
	icmpFrame, err := lnetoicmp.NewFrame(badReply[14+20:])
	if err != nil {
		t.Fatal(err)
	}
	icmpFrame.SetCRC(icmpFrame.CRC() ^ 1)
	core.Lock()
	handled, ingressErr := adapter.ingressLocked(badReply)
	core.Unlock()
	if ingressErr != nil || !handled || failed.Readiness() != nscore.ReadyError {
		t.Fatalf("checksum failure = handled %v, err %v, readiness %v", handled, ingressErr, failed.Readiness())
	}
	if _, _, err := failed.TryResult(make([]byte, 3)); failureOf(t, err) != nscore.FailureIO {
		t.Fatalf("checksum result = %v", err)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, ICMPv4Resources: 1, QueuedBytes: 3}) {
		t.Fatalf("checksum terminal quota = %+v, closed=%v", usage, closed)
	}
	core.Lock()
	handled, ingressErr = adapter.ingressLocked(makeEchoReply(t, failedRequest, nil))
	core.Unlock()
	if ingressErr != nil || handled {
		t.Fatalf("late valid reply after checksum failure = handled %v, err %v", handled, ingressErr)
	}

	activeResource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("live")})
	if err != nil {
		t.Fatal(err)
	}
	active := activeResource.(*echo)
	_ = serviceEgress(t, core)
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 2, ICMPv4Resources: 2, QueuedBytes: 7, ICMPv4Work: 1}) {
		t.Fatalf("mixed terminal/active quota = %+v, closed=%v", usage, closed)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if failed.Readiness() != nscore.ReadyClosed || active.Readiness() != nscore.ReadyClosed {
		t.Fatalf("namespace close readiness: failed=%v active=%v", failed.Readiness(), active.Readiness())
	}
	if _, _, err := active.TryResult(make([]byte, 4)); failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("closed active result = %v", err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close quota = %+v", usage)
	}
	if len(adapter.echoes) != 0 || adapter.byIdentity != nil || failed.payload != nil || active.payload != nil || failed.failure != nil || active.failure != nil || failed.destination.IsValid() || active.destination.IsValid() {
		t.Fatalf("namespace close retained state: echoes=%d identities=%v failed=%+v active=%+v", len(adapter.echoes), adapter.byIdentity, failed, active)
	}
}

func FuzzICMPv4IngressBoundedMalformedFrames(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(make([]byte, 14))
	f.Add(make([]byte, 42))
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > 1514 {
			frame = frame[:1514]
		}
		core, adapter, _ := newTestAdapter(t, Config{MaxEchoes: 1, MaxPayloadBytes: 16, MaxAttempts: 1, RetryServiceAttempts: 1})
		resource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("fuzz")})
		if err != nil {
			t.Fatal(err)
		}
		exchange := resource.(*echo)
		core.Lock()
		_, _ = adapter.ingressLocked(frame)
		state := exchange.state
		core.Unlock()
		if state != echoPending && state != echoWaiting && state != echoDone && state != echoFailed {
			t.Fatalf("invalid state after ingress: %v", state)
		}
	})
}

func BenchmarkIngressEchoReply(b *testing.B) {
	core, adapter, _ := newTestAdapter(b, Config{MaxEchoes: 1, MaxPayloadBytes: 16, MaxAttempts: 1, RetryServiceAttempts: 2})
	resource, _, err := adapter.TryEcho(icmpns.Request{Destination: netip.MustParseAddr("192.0.2.99"), Payload: []byte("wire")})
	if err != nil {
		b.Fatal(err)
	}
	exchange := resource.(*echo)
	request := serviceEgress(b, core)
	reply := makeEchoReply(b, request, nil)
	key := identityKey(exchange.identifier, exchange.sequence)
	core.Lock()
	defer core.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		exchange.state = echoWaiting
		adapter.byIdentity[key] = exchange
		_, _ = adapter.ingressLocked(reply)
	}
}
