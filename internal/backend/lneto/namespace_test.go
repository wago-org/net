package lnetobackend

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/packetlink"
)

func TestNamespacesExchangePacketsDeterministically(t *testing.T) {
	aConfig := testConfig(1)
	bConfig := testConfig(2)
	a := newTestNamespace(t, aConfig)
	b := newTestNamespace(t, bConfig)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	if err := a.stack.StartResolveHardwareAddress6(bConfig.IPv4Address); err != nil {
		t.Fatalf("start ARP resolution: %v", err)
	}
	budget := namespace.ServiceBudget{Packets: 4, Bytes: 4 * uint32(a.requiredFrameBytes), Operations: 4}
	report, progress, err := a.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidResult(budget, progress) || report.Packets != 1 {
		t.Fatalf("client service = %+v, %v, %v", report, progress, err)
	}
	transferOne(t, a.Link(), b.Link())

	report, progress, err = b.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidResult(budget, progress) || report.Packets != 2 {
		t.Fatalf("server service = %+v, %v, %v", report, progress, err)
	}
	transferOne(t, b.Link(), a.Link())

	report, progress, err = a.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidResult(budget, progress) || report.Packets != 1 {
		t.Fatalf("client receive service = %+v, %v, %v", report, progress, err)
	}
	got, err := a.stack.ResultResolveHardwareAddress6(bConfig.IPv4Address)
	if err != nil || got != bConfig.HardwareAddress {
		t.Fatalf("resolved hardware address = %v, %v; want %v", got, err, bConfig.HardwareAddress)
	}
}

func TestTryServiceEnforcesEveryBudgetWithoutConsumingBlockedWork(t *testing.T) {
	aConfig := testConfig(3)
	bConfig := testConfig(4)
	a := newTestNamespace(t, aConfig)
	b := newTestNamespace(t, bConfig)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	if err := a.stack.StartResolveHardwareAddress6(bConfig.IPv4Address); err != nil {
		t.Fatal(err)
	}
	a.nextIngress = false // Exercise the egress byte gate on the first attempt.
	tooSmall := namespace.ServiceBudget{Packets: 1, Bytes: uint32(a.requiredFrameBytes - 1), Operations: 1}
	report, progress, err := a.TryService(tooSmall)
	if err != nil || progress != namespace.ProgressWouldBlock || report != (namespace.ServiceReport{}) {
		t.Fatalf("short egress budget = %+v, %v, %v", report, progress, err)
	}
	if a.Link().Snapshot().EgressFrames != 0 {
		t.Fatal("short egress budget committed a frame")
	}

	exactAttempt := namespace.ServiceBudget{Packets: 1, Bytes: uint32(a.requiredFrameBytes), Operations: 2}
	report, progress, err = a.TryService(exactAttempt)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 || report.Operations != 1 || report.Bytes == 0 || report.Bytes > exactAttempt.Bytes {
		t.Fatalf("exact egress attempt = %+v, %v, %v", report, progress, err)
	}
	frameBytes := transferOne(t, a.Link(), b.Link())

	blockedIngress := namespace.ServiceBudget{Packets: 1, Bytes: uint32(frameBytes - 1), Operations: 1}
	report, progress, err = b.TryService(blockedIngress)
	if err != nil || progress != namespace.ProgressWouldBlock || report != (namespace.ServiceReport{}) {
		t.Fatalf("short ingress budget = %+v, %v, %v", report, progress, err)
	}
	if got := b.Link().Snapshot().IngressFrames; got != 1 {
		t.Fatalf("short ingress budget consumed frame: %d", got)
	}

	exactIngress := namespace.ServiceBudget{Packets: 1, Bytes: uint32(frameBytes), Operations: 2}
	report, progress, err = b.TryService(exactIngress)
	if err != nil || progress != namespace.ProgressDone || report != (namespace.ServiceReport{Packets: 1, Bytes: uint32(frameBytes), Operations: 1}) {
		t.Fatalf("exact ingress budget = %+v, %v, %v", report, progress, err)
	}
	if got := b.Link().Snapshot().IngressFrames; got != 0 {
		t.Fatalf("exact ingress left %d frames", got)
	}
}

func TestTryServiceOperationBudgetBoundsDirectionAttempts(t *testing.T) {
	ns := newTestNamespace(t, testConfig(10))
	t.Cleanup(func() { _ = ns.Close() })
	if err := ns.Link().TryEnqueue(packetlink.Ingress, []byte{0}); err != nil {
		t.Fatal(err)
	}
	ns.nextIngress = false
	oneAttempt := namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1}
	report, progress, err := ns.TryService(oneAttempt)
	if err != nil || progress != namespace.ProgressWouldBlock || report != (namespace.ServiceReport{}) {
		t.Fatalf("egress-only attempt = %+v, %v, %v", report, progress, err)
	}
	if got := ns.Link().Snapshot().IngressFrames; got != 1 {
		t.Fatalf("one operation attempted both directions; ingress frames = %d", got)
	}
	report, progress, err = ns.TryService(oneAttempt)
	if requireFailure(t, err) != namespace.FailureInvalidArgument || progress != namespace.ProgressDone || report.Operations != 1 {
		t.Fatalf("next ingress attempt = %+v, %v, %v", report, progress, err)
	}
}

func TestTryServiceEmptyAndMalformedIngress(t *testing.T) {
	ns := newTestNamespace(t, testConfig(5))
	t.Cleanup(func() { _ = ns.Close() })
	budget := namespace.ServiceBudget{Packets: 2, Bytes: 64, Operations: 2}
	for i := 0; i < 100; i++ {
		report, progress, err := ns.TryService(budget)
		if err != nil || progress != namespace.ProgressWouldBlock || report != (namespace.ServiceReport{}) {
			t.Fatalf("empty service %d = %+v, %v, %v", i, report, progress, err)
		}
	}
	if err := ns.Link().TryEnqueue(packetlink.Ingress, []byte{0}); err != nil {
		t.Fatal(err)
	}
	report, progress, err := ns.TryService(budget)
	if failure := requireFailure(t, err); failure != namespace.FailureInvalidArgument {
		t.Fatalf("malformed ingress failure = %v", failure)
	}
	if progress != namespace.ProgressDone || report != (namespace.ServiceReport{Packets: 1, Bytes: 1, Operations: 1}) {
		t.Fatalf("malformed ingress service = %+v, %v, %v", report, progress, err)
	}
}

func TestProtocolConstructorsRemainTruthfullyUnsupported(t *testing.T) {
	ns := newTestNamespace(t, testConfig(6))
	valid := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 8080}
	invalid := namespace.Endpoint{}

	if _, progress, err := ns.TryBindUDP(valid); progress != 0 || requireFailure(t, err) != namespace.FailureNotSupported {
		t.Fatalf("TryBindUDP = %v, %v", progress, err)
	}
	if _, progress, err := ns.TryListenTCP(valid); progress != 0 || requireFailure(t, err) != namespace.FailureNotSupported {
		t.Fatalf("TryListenTCP = %v, %v", progress, err)
	}
	if _, progress, err := ns.TryConnectTCP(valid); progress != 0 || requireFailure(t, err) != namespace.FailureNotSupported {
		t.Fatalf("TryConnectTCP = %v, %v", progress, err)
	}
	if _, progress, err := ns.TryResolve(namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}); progress != 0 || requireFailure(t, err) != namespace.FailureNotSupported {
		t.Fatalf("TryResolve = %v, %v", progress, err)
	}
	if _, _, err := ns.TryBindUDP(invalid); requireFailure(t, err) != namespace.FailureInvalidArgument {
		t.Fatalf("invalid endpoint error = %v", err)
	}
	if _, _, err := ns.TryResolve(namespace.DNSRequest{}); requireFailure(t, err) != namespace.FailureInvalidArgument {
		t.Fatalf("invalid DNS error = %v", err)
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ns.TryConnectTCP(valid); requireFailure(t, err) != namespace.FailureClosed {
		t.Fatalf("closed constructor error = %v", err)
	}
}

func TestReadinessAndCloseAreLevelTriggeredAndDeterministic(t *testing.T) {
	ns := newTestNamespace(t, testConfig(7))
	link := ns.Link()
	if got := ns.Readiness(); got != namespace.ReadyWritable {
		t.Fatalf("initial readiness = %v", got)
	}
	if err := link.TryEnqueue(packetlink.Egress, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if got := ns.Readiness(); got != namespace.ReadyReadable|namespace.ReadyWritable {
		t.Fatalf("egress readiness = %v", got)
	}
	for link.Snapshot().IngressFrames < link.Snapshot().IngressCapacity {
		if err := link.TryEnqueue(packetlink.Ingress, nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := ns.Readiness(); got != namespace.ReadyReadable {
		t.Fatalf("full ingress readiness = %v", got)
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if ns.stack != nil || ns.scratch != nil {
		t.Fatal("close retained stack or scratch")
	}
	if got := ns.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed readiness = %v", got)
	}
	if snapshot := link.Snapshot(); !snapshot.Closed || snapshot.IngressFrames != 0 || snapshot.EgressFrames != 0 {
		t.Fatalf("closed link snapshot = %+v", snapshot)
	}
	if err := ns.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestNamespaceCloseRacesWithService(t *testing.T) {
	ns := newTestNamespace(t, testConfig(8))
	budget := namespace.ServiceBudget{Packets: 2, Bytes: uint32(ns.requiredFrameBytes * 2), Operations: 2}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = ns.Link().TryEnqueue(packetlink.Ingress, []byte{0})
				_, _, err := ns.TryService(budget)
				if err != nil {
					failure, ok := namespace.FailureOf(err)
					if !ok || (failure != namespace.FailureInvalidArgument && failure != namespace.FailureClosed) {
						t.Errorf("service error = %v", err)
						return
					}
				}
				if !ns.Readiness().Valid() {
					t.Error("invalid readiness")
					return
				}
			}
		}()
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestLnetoErrorsMapToStableFailures(t *testing.T) {
	tests := []struct {
		err  error
		want namespace.Failure
	}{
		{net.ErrClosed, namespace.FailureClosed},
		{lneto.ErrUnsupported, namespace.FailureNotSupported},
		{lneto.ErrExhausted, namespace.FailureResourceLimit},
		{lneto.ErrAlreadyRegistered, namespace.FailureAddressInUse},
		{lneto.ErrBadState, namespace.FailureInvalidState},
		{io.ErrShortBuffer, namespace.FailureMessageTooLarge},
		{lneto.ErrInvalidAddr, namespace.FailureInvalidArgument},
		{lneto.ErrPacketDrop, namespace.FailureTemporary},
		{lneto.ErrBug, namespace.FailureIO},
	}
	for _, test := range tests {
		if got := requireFailure(t, mapError(test.err)); got != test.want {
			t.Fatalf("mapError(%v) = %v, want %v", test.err, got, test.want)
		}
	}
}

func TestNewRejectsInvalidOrUndersizedConfigurations(t *testing.T) {
	config := testConfig(9)
	config.Link.MaxFrameBytes--
	if _, err := New(config); requireFailure(t, err) != namespace.FailureInvalidArgument {
		t.Fatalf("undersized link error = %v", err)
	}
	config = testConfig(9)
	config.IPv4Address = netip.MustParseAddr("2001:db8::1")
	if _, err := New(config); requireFailure(t, err) != namespace.FailureInvalidArgument {
		t.Fatalf("IPv6 config error = %v", err)
	}
}

func transferOne(t testing.TB, from, to *packetlink.Link) int {
	t.Helper()
	buffer := make([]byte, from.MaxFrameBytes())
	result, err := from.TryDequeue(packetlink.Egress, buffer)
	if err != nil || !result.Ready || result.Truncated || result.FrameBytes == 0 {
		t.Fatalf("dequeue transfer frame = %+v, %v", result, err)
	}
	if err := to.TryEnqueue(packetlink.Ingress, buffer[:result.FrameBytes]); err != nil {
		t.Fatalf("enqueue transfer frame: %v", err)
	}
	return result.FrameBytes
}

func testConfig(id byte) Config {
	mtu := uint16(ethernet.MaxMTU)
	return Config{
		Hostname:               "namespace" + string(rune('0'+id)),
		RandSeed:               int64(id) + 1,
		HardwareAddress:        [6]byte{0x02, 0, 0, 0, 0, id},
		GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 3},
		IPv4Address:            netip.AddrFrom4([4]byte{192, 0, 2, id}),
		MTU:                    mtu,
		Link: packetlink.Config{
			MaxFrameBytes: int(mtu) + 14,
			IngressFrames: 4,
			EgressFrames:  4,
		},
	}
}

func newTestNamespace(t testing.TB, config Config) *Namespace {
	t.Helper()
	ns, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func requireFailure(t testing.TB, err error) namespace.Failure {
	t.Helper()
	failure, ok := namespace.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}
