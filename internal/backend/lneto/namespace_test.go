package lnetobackend

import (
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
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
	setNextIngress(a, false) // Exercise the egress byte gate on the first attempt.
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
	setNextIngress(ns, false)
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

func TestUDPNonblockingExchangeEmptyTruncationAndQueueBounds(t *testing.T) {
	aConfig := udpTestConfig(t, 21)
	bConfig := udpTestConfig(t, 22)
	aConfig.GatewayHardwareAddress = bConfig.HardwareAddress
	bConfig.GatewayHardwareAddress = aConfig.HardwareAddress
	a := newTestNamespace(t, aConfig)
	b := newTestNamespace(t, bConfig)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	aLocal := namespace.Endpoint{Address: aConfig.IPv4Address, Port: 4021}
	bLocal := namespace.Endpoint{Address: bConfig.IPv4Address, Port: 4022}
	aSocket := bindUDP(t, a, aLocal)
	bSocket := bindUDP(t, b, bLocal)
	if got := aSocket.Readiness(); got != namespace.ReadyWritable {
		t.Fatalf("initial UDP readiness = %v", got)
	}

	if progress, err := aSocket.TrySend(nil, bLocal); err != nil || progress != namespace.ProgressDone {
		t.Fatalf("send empty = %v, %v", progress, err)
	}
	if progress, err := aSocket.TrySend([]byte("abcdef"), bLocal); err != nil || progress != namespace.ProgressDone {
		t.Fatalf("send payload = %v, %v", progress, err)
	}
	if progress, err := aSocket.TrySend([]byte("full"), bLocal); err != nil || progress != namespace.ProgressWouldBlock {
		t.Fatalf("send queue full = %v, %v", progress, err)
	}
	if got := aSocket.Readiness(); got != 0 {
		t.Fatalf("full transmit readiness = %v", got)
	}

	serviceTransfer(t, a, b)
	serviceTransfer(t, a, b)
	if got := bSocket.Readiness(); got != namespace.ReadyReadable|namespace.ReadyWritable {
		t.Fatalf("received readiness = %v", got)
	}
	empty, err := bSocket.TryReceive(nil)
	if err != nil || !empty.Ready || empty.DatagramBytes != 0 || empty.Copied != 0 || empty.Truncated || empty.Source != aLocal {
		t.Fatalf("empty receive = %+v, %v", empty, err)
	}
	buffer := make([]byte, 3)
	truncated, err := bSocket.TryReceive(buffer)
	if err != nil || !truncated.Ready || truncated.DatagramBytes != 6 || truncated.Copied != 3 || !truncated.Truncated || string(buffer) != "abc" || truncated.Source != aLocal {
		t.Fatalf("truncated receive = %+v %q, %v", truncated, buffer, err)
	}
	blocked, err := bSocket.TryReceive(buffer)
	if err != nil || blocked.Ready {
		t.Fatalf("empty queue receive = %+v, %v", blocked, err)
	}
}

func TestUDPPolicyQuotaCloseAndRegistrationReuse(t *testing.T) {
	config := udpTestConfig(t, 23)
	config.UDP.MaxSockets = 2
	config.UDP.ReceiveBytes = 16
	config.UDP.TransmitBytes = 16
	config.UDP.ReceiveDatagrams = 1
	config.UDP.TransmitDatagrams = 1
	config.UDP.MaxPayloadBytes = 16
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 1, UDPResources: 1, QueuedBytes: 32})
	ns := newTestNamespace(t, config)
	local := namespace.Endpoint{Address: config.IPv4Address, Port: 4023}
	socket := bindUDP(t, ns, local)
	usage, closed := config.Quotas.Snapshot()
	if closed || usage.Resources != 1 || usage.UDPResources != 1 || usage.QueuedBytes != 32 {
		t.Fatalf("exact UDP quota = %+v, closed=%v", usage, closed)
	}
	other := namespace.Endpoint{Address: config.IPv4Address, Port: 4024}
	if _, _, err := ns.TryBindUDP(other); requireFailure(t, err) != namespace.FailureResourceLimit {
		t.Fatalf("second bind quota error = %v", err)
	}
	denied := namespace.Endpoint{Address: netip.MustParseAddr("198.51.100.1"), Port: 53}
	if _, err := socket.TrySend(nil, denied); requireFailure(t, err) != namespace.FailureAccessDenied {
		t.Fatalf("denied send error = %v", err)
	}
	if progress, err := socket.TrySend(make([]byte, config.UDP.MaxPayloadBytes+1), other); progress != 0 || requireFailure(t, err) != namespace.FailureMessageTooLarge {
		t.Fatalf("oversized send = %v, %v", progress, err)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if got := socket.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed socket readiness = %v", got)
	}
	if _, err := socket.TrySend(nil, other); requireFailure(t, err) != namespace.FailureClosed {
		t.Fatalf("closed send error = %v", err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("quota after close = %+v", usage)
	}
	rebound := bindUDP(t, ns, local)
	if rebound == socket {
		t.Fatal("rebind reused closed socket object")
	}
	if err := rebound.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("quota after rebound close = %+v", usage)
	}
}

func TestUDPConcurrentOperationsAndDeterministicClose(t *testing.T) {
	config := udpTestConfig(t, 25)
	ns := newTestNamespace(t, config)
	local := namespace.Endpoint{Address: config.IPv4Address, Port: 4125}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.26"), Port: 4126}
	socket := bindUDP(t, ns, local)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			buffer := make([]byte, 8)
			for range 200 {
				_, sendErr := socket.TrySend([]byte("packet"), remote)
				if sendErr != nil && requireConcurrentFailure(sendErr) != namespace.FailureClosed {
					t.Errorf("concurrent send error = %v", sendErr)
					return
				}
				_, receiveErr := socket.TryReceive(buffer)
				if receiveErr != nil && requireConcurrentFailure(receiveErr) != namespace.FailureClosed {
					t.Errorf("concurrent receive error = %v", receiveErr)
					return
				}
				if !socket.Readiness().Valid() {
					t.Error("invalid concurrent UDP readiness")
					return
				}
			}
		}()
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if got := socket.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed concurrent readiness = %v", got)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("concurrent close retained quota = %+v", usage)
	}
}

func TestUDPBindDenialAndUnsupportedFamilies(t *testing.T) {
	config := udpTestConfig(t, 24)
	ns := newTestNamespace(t, config)
	t.Cleanup(func() { _ = ns.Close() })
	denied := namespace.Endpoint{Address: netip.MustParseAddr("198.51.100.24"), Port: 4024}
	if _, _, err := ns.TryBindUDP(denied); requireFailure(t, err) != namespace.FailureAddressUnavailable {
		t.Fatalf("unavailable bind error = %v", err)
	}
	v6 := namespace.Endpoint{Address: netip.MustParseAddr("2001:db8::1"), Port: 4024}
	if _, _, err := ns.TryBindUDP(v6); requireFailure(t, err) != namespace.FailureInvalidArgument {
		t.Fatalf("IPv6 bind error = %v", err)
	}
	wildcard := namespace.Endpoint{Address: netip.IPv4Unspecified(), Port: 4024}
	if _, _, err := ns.TryBindUDP(wildcard); requireFailure(t, err) != namespace.FailureAccessDenied {
		t.Fatalf("wildcard policy error = %v", err)
	}
}

func TestTCPImmediateConnectAcceptPartialIOAndEOF(t *testing.T) {
	aConfig := tcpTestConfig(t, 31)
	bConfig := tcpTestConfig(t, 32)
	aConfig.GatewayHardwareAddress = bConfig.HardwareAddress
	bConfig.GatewayHardwareAddress = aConfig.HardwareAddress
	a := newTestNamespace(t, aConfig)
	b := newTestNamespace(t, bConfig)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	serverEndpoint := namespace.Endpoint{Address: bConfig.IPv4Address, Port: 4232}
	listenerResource, progress, err := b.TryListenTCP(serverEndpoint)
	if err != nil || progress != namespace.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerResource, progress, err)
	}
	listener := listenerResource.(*tcpListener)
	clientResource, progress, err := a.TryConnectTCP(serverEndpoint)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", clientResource, progress, err)
	}
	client := clientResource.(*tcpStream)
	if progress, err := client.TryFinishConnect(); err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("initial finish connect = %v, %v", progress, err)
	}
	if result, err := client.TryWrite([]byte("early")); err != nil || result.State != namespace.IOWouldBlock {
		t.Fatalf("pre-connect write = %+v, %v", result, err)
	}

	tcpTransfer(t, a, b)
	tcpTransfer(t, b, a)
	tcpTransfer(t, a, b)
	if progress, err := client.TryFinishConnect(); err != nil || progress != namespace.ProgressDone {
		t.Fatalf("finish connect = %v, %v", progress, err)
	}
	if got := listener.Readiness(); got != namespace.ReadyAccept {
		t.Fatalf("listener readiness = %v", got)
	}
	serverResource, progress, err := listener.TryAccept()
	if err != nil || progress != namespace.ProgressDone {
		t.Fatalf("accept = %T, %v, %v", serverResource, progress, err)
	}
	server := serverResource.(*tcpStream)
	if result, err := server.TryRead(make([]byte, 8)); err != nil || result.State != namespace.IOWouldBlock {
		t.Fatalf("empty read = %+v, %v", result, err)
	}

	payload := make([]byte, aConfig.TCP.TransmitBytes+17)
	for i := range payload {
		payload[i] = byte(i)
	}
	written, err := client.TryWrite(payload)
	if err != nil || written.State != namespace.IOReady || written.Bytes != aConfig.TCP.TransmitBytes {
		t.Fatalf("partial write = %+v, %v", written, err)
	}
	if blocked, err := client.TryWrite(payload[written.Bytes:]); err != nil || blocked.State != namespace.IOWouldBlock {
		t.Fatalf("full-buffer write = %+v, %v", blocked, err)
	}
	tcpTransfer(t, a, b)
	first := make([]byte, 31)
	read, err := server.TryRead(first)
	if err != nil || read != (namespace.IOResult{Bytes: len(first), State: namespace.IOReady}) || string(first) != string(payload[:len(first)]) {
		t.Fatalf("partial read = %+v, %v", read, err)
	}
	rest := make([]byte, len(payload))
	read, err = server.TryRead(rest)
	if err != nil || read.State != namespace.IOReady || read.Bytes != written.Bytes-len(first) || string(rest[:read.Bytes]) != string(payload[len(first):written.Bytes]) {
		t.Fatalf("remaining read = %+v, %v", read, err)
	}

	tcpTransfer(t, b, a) // ACK frees the client's bounded transmit buffer.
	if result, err := client.TryWrite(payload[written.Bytes:]); err != nil || result.Bytes != len(payload)-written.Bytes {
		t.Fatalf("write after ACK = %+v, %v", result, err)
	}
	tcpTransfer(t, a, b)
	if _, err := server.TryRead(rest); err != nil {
		t.Fatalf("read final payload: %v", err)
	}
	tcpTransfer(t, b, a)
	if progress, err := client.TryShutdownWrite(); err != nil || progress != namespace.ProgressDone {
		t.Fatalf("shutdown write = %v, %v", progress, err)
	}
	tcpTransfer(t, a, b)
	if result, err := server.TryRead(rest); err != nil || result.State != namespace.IOEOF {
		t.Fatalf("read after FIN = %+v, %v", result, err)
	}
}

func TestTCPAcceptedCloseReclaimsPoolSlotAsChargedMaintenance(t *testing.T) {
	clientConfig := tcpTestConfig(t, 37)
	serverConfig := tcpTestConfig(t, 38)
	clientConfig.GatewayHardwareAddress = serverConfig.HardwareAddress
	serverConfig.GatewayHardwareAddress = clientConfig.HardwareAddress
	serverConfig.TCP.AcceptBacklog = 1
	client := newTestNamespace(t, clientConfig)
	server := newTestNamespace(t, serverConfig)
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })

	serverEndpoint := namespace.Endpoint{Address: serverConfig.IPv4Address, Port: 4238}
	listenerResource, progress, err := server.TryListenTCP(serverEndpoint)
	if err != nil || progress != namespace.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerResource, progress, err)
	}
	listener := listenerResource.(*tcpListener)
	connectAndAccept := func() (*tcpStream, *tcpStream) {
		clientResource, progress, err := client.TryConnectTCP(serverEndpoint)
		if err != nil || progress != namespace.ProgressInProgress {
			t.Fatalf("connect = %T, %v, %v", clientResource, progress, err)
		}
		clientStream := clientResource.(*tcpStream)
		tcpTransfer(t, client, server)
		tcpTransfer(t, server, client)
		tcpTransfer(t, client, server)
		if progress, err := clientStream.TryFinishConnect(); err != nil || progress != namespace.ProgressDone {
			t.Fatalf("finish connect = %v, %v", progress, err)
		}
		serverResource, progress, err := listener.TryAccept()
		if err != nil || progress != namespace.ProgressDone {
			t.Fatalf("accept = %T, %v, %v", serverResource, progress, err)
		}
		return clientStream, serverResource.(*tcpStream)
	}

	firstClient, firstServer := connectAndAccept()
	if len(listener.pool.slots) != 1 || !listener.pool.slots[0].inUse {
		t.Fatalf("accepted listener pool = %+v", listener.pool.slots)
	}
	beforeUsage, _ := serverConfig.Quotas.Snapshot()
	if beforeUsage.Resources != 2 || beforeUsage.TCPResources != 2 {
		t.Fatalf("accepted quota = %+v", beforeUsage)
	}
	if err := firstServer.Close(); err != nil {
		t.Fatal(err)
	}
	afterClose, _ := serverConfig.Quotas.Snapshot()
	if afterClose.Resources != 1 || afterClose.TCPResources != 1 {
		t.Fatalf("accepted close did not release quota immediately: %+v", afterClose)
	}
	if !listener.pool.slots[0].inUse || listener.pool.slots[0].stream == nil {
		t.Fatalf("lneto released accepted slot outside charged maintenance: in_use=%v stream=%p resource=%p", listener.pool.slots[0].inUse, listener.pool.slots[0].stream, listener.pool.slots[0].resource)
	}

	setNextIngress(server, false)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(server.requiredFrameBytes), Operations: 1}
	report, progress, err := server.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report != (namespace.ServiceReport{Operations: 1}) {
		t.Fatalf("accepted close maintenance = %+v, %v, %v", report, progress, err)
	}
	if listener.pool.slots[0].inUse || listener.pool.slots[0].stream != nil || listener.pool.slots[0].resource != nil {
		t.Fatalf("accepted slot retained after bounded maintenance: in_use=%v stream=%p resource=%p", listener.pool.slots[0].inUse, listener.pool.slots[0].stream, listener.pool.slots[0].resource)
	}
	if usage, _ := serverConfig.Quotas.Snapshot(); usage != afterClose {
		t.Fatalf("maintenance changed released quota: before=%+v after=%+v", afterClose, usage)
	}

	if err := firstClient.Close(); err != nil {
		t.Fatal(err)
	}
	secondClient, secondServer := connectAndAccept()
	if secondClient == firstClient || secondServer == firstServer || !listener.pool.slots[0].inUse {
		t.Fatalf("accepted slot was not reusable: client=%p server=%p in_use=%v stream=%p resource=%p", secondClient, secondServer, listener.pool.slots[0].inUse, listener.pool.slots[0].stream, listener.pool.slots[0].resource)
	}
}

func TestTCPConnectResetBeforeEstablishment(t *testing.T) {
	config := tcpTestConfig(t, 35)
	ns := newTestNamespace(t, config)
	t.Cleanup(func() { _ = ns.Close() })
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.36"), Port: 4299}
	streamResource, progress, err := ns.TryConnectTCP(remote)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", streamResource, progress, err)
	}
	stream := streamResource.(*tcpStream)
	ns.core.Lock()
	stream.conn.Abort() // Models the terminal state lneto enters after a reset.
	ns.core.Unlock()
	if progress, err := stream.TryFinishConnect(); progress != 0 || requireFailure(t, err) != namespace.FailureConnectionRefused {
		t.Fatalf("finish reset connect = %v, %v", progress, err)
	}
	if got := stream.Readiness(); got&namespace.ReadyError == 0 || got&namespace.ReadyClosed == 0 {
		t.Fatalf("reset readiness = %v", got)
	}
}

func TestTCPPolicyQuotaPortReuseAndImmediateSourceScan(t *testing.T) {
	config := tcpTestConfig(t, 33)
	retained := uint64(config.TCP.AcceptBacklog) * uint64(config.TCP.ReceiveBytes+config.TCP.TransmitBytes)
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 1, TCPResources: 1, QueuedBytes: retained})
	ns := newTestNamespace(t, config)
	local := namespace.Endpoint{Address: config.IPv4Address, Port: 4233}
	listener, progress, err := ns.TryListenTCP(local)
	if err != nil || progress != namespace.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listener, progress, err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage.Resources != 1 || usage.TCPResources != 1 || usage.QueuedBytes != retained {
		t.Fatalf("listener quota = %+v", usage)
	}
	if _, _, err := ns.TryListenTCP(namespace.Endpoint{Address: config.IPv4Address, Port: 4234}); requireFailure(t, err) != namespace.FailureResourceLimit {
		t.Fatalf("second listener quota error = %v", err)
	}
	denied := namespace.Endpoint{Address: netip.MustParseAddr("198.51.100.33"), Port: 443}
	if _, _, err := ns.TryConnectTCP(denied); requireFailure(t, err) != namespace.FailureAccessDenied {
		t.Fatalf("denied connect error = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("quota after listener close = %+v", usage)
	}
	if rebound, progress, err := ns.TryListenTCP(local); err != nil || progress != namespace.ProgressDone || rebound == listener {
		t.Fatalf("listener port reuse = %T, %v, %v", rebound, progress, err)
	}

	source, err := os.ReadFile("tcp.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"conn.Read(", "conn.Write(", "conn.Flush(", "StackBlocking", "StackGo("} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("host-facing TCP adapter references blocking wrapper %q", forbidden)
		}
	}
}

func TestTCPConcurrentOperationsAndNamespaceClose(t *testing.T) {
	config := tcpTestConfig(t, 34)
	ns := newTestNamespace(t, config)
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.35"), Port: 4235}
	streamResource, progress, err := ns.TryConnectTCP(remote)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", streamResource, progress, err)
	}
	stream := streamResource.(*tcpStream)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			buffer := make([]byte, 8)
			for range 100 {
				_, _ = stream.TryFinishConnect()
				_, _ = stream.TryRead(buffer)
				_, _ = stream.TryWrite(buffer)
				if !stream.Readiness().Valid() {
					t.Error("invalid TCP readiness")
					return
				}
			}
		}()
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if got := stream.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed stream readiness = %v", got)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close retained quota = %+v", usage)
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
	if ns.stack != nil {
		t.Fatal("close retained stack")
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

func FuzzUDPIngress(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 14+20+8))
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > 1514 {
			frame = frame[:1514]
		}
		config := udpTestConfig(t, 27)
		ns := newTestNamespace(t, config)
		defer ns.Close()
		bindUDP(t, ns, namespace.Endpoint{Address: config.IPv4Address, Port: 4127})
		ns.core.Lock()
		handled, err := ns.ingressUDPLocked(frame)
		ns.core.Unlock()
		if err != nil {
			if failure := requireFailure(t, mapError(err)); !failure.Valid() {
				t.Fatalf("invalid mapped ingress failure = %v", failure)
			}
		}
		_ = handled
	})
}

func FuzzUDPOperationSequence(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4})
	f.Add([]byte{2, 2, 0, 1, 3})
	f.Fuzz(func(t *testing.T, operations []byte) {
		if len(operations) > 64 {
			operations = operations[:64]
		}
		config := udpTestConfig(t, 28)
		ns := newTestNamespace(t, config)
		defer ns.Close()
		local := namespace.Endpoint{Address: config.IPv4Address, Port: 4128}
		remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.29"), Port: 4129}
		socket := bindUDP(t, ns, local)
		buffer := make([]byte, 8)
		for _, operation := range operations {
			switch operation % 5 {
			case 0:
				payload := make([]byte, int(operation)%33)
				_, _ = socket.TrySend(payload, remote)
			case 1:
				_, _ = socket.TryReceive(buffer)
			case 2:
				_ = socket.Readiness()
			case 3:
				_ = socket.Close()
			case 4:
				if socket.Readiness() == namespace.ReadyClosed {
					candidate, progress, err := ns.TryBindUDP(local)
					if err == nil && progress == namespace.ProgressDone {
						socket = candidate.(namespace.UDPSocket)
					}
				}
			}
		}
	})
}

func BenchmarkUDPDatagramQueueRoundTrip(b *testing.B) {
	queue := newDatagramQueue(8, 64, 512)
	endpoint := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 53}
	payload := make([]byte, 64)
	buffer := make([]byte, 64)
	b.ReportAllocs()
	for b.Loop() {
		if !queue.push(payload, endpoint) {
			b.Fatal("queue push blocked")
		}
		result, ok := queue.pop(buffer)
		if !ok || !result.Ready || result.Copied != len(payload) {
			b.Fatalf("queue pop = %+v, %v", result, ok)
		}
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

func udpTestConfig(t testing.TB, id byte) Config {
	t.Helper()
	config := testConfig(id)
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action:     policy.ActionAllow,
		Transports: []policy.Transport{policy.TransportUDP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	config.Policy = compiled
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 4, UDPResources: 4, QueuedBytes: 512})
	config.UDP = UDPConfig{
		MaxSockets:        4,
		ReceiveBytes:      64,
		TransmitBytes:     64,
		ReceiveDatagrams:  2,
		TransmitDatagrams: 2,
		MaxPayloadBytes:   32,
	}
	return config
}

func tcpTestConfig(t testing.TB, id byte) Config {
	t.Helper()
	config := testConfig(id)
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action:     policy.ActionAllow,
		Transports: []policy.Transport{policy.TransportTCP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	config.Policy = compiled
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 16, TCPResources: 16, QueuedBytes: 16 << 10})
	config.TCP = TCPConfig{
		MaxListeners: 2, MaxOutboundStreams: 2, AcceptBacklog: 2,
		ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4,
	}
	return config
}

func tcpTransfer(t testing.TB, from, to *Namespace) {
	t.Helper()
	setNextIngress(from, false)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(from.requiredFrameBytes), Operations: 1}
	report, progress, err := from.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 {
		t.Fatalf("TCP egress service = %+v, %v, %v", report, progress, err)
	}
	transferOne(t, from.Link(), to.Link())
	setNextIngress(to, true)
	report, progress, err = to.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 {
		t.Fatalf("TCP ingress service = %+v, %v, %v", report, progress, err)
	}
}

func bindUDP(t testing.TB, ns *Namespace, local namespace.Endpoint) namespace.UDPSocket {
	t.Helper()
	socket, progress, err := ns.TryBindUDP(local)
	if err != nil || progress != namespace.ProgressDone || socket == nil {
		t.Fatalf("bind UDP %v = %T, %v, %v", local, socket, progress, err)
	}
	return socket.(namespace.UDPSocket)
}

func serviceTransfer(t testing.TB, from, to *Namespace) {
	t.Helper()
	setNextIngress(from, false)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(from.requiredFrameBytes), Operations: 1}
	report, progress, err := from.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 {
		t.Fatalf("UDP egress service = %+v, %v, %v", report, progress, err)
	}
	transferOne(t, from.Link(), to.Link())
	setNextIngress(to, true)
	report, progress, err = to.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 {
		t.Fatalf("UDP ingress service = %+v, %v, %v", report, progress, err)
	}
}

func setNextIngress(ns *Namespace, next bool) {
	ns.core.Lock()
	ns.core.SetNextIngressLocked(next)
	ns.core.Unlock()
}

func newTestNamespace(t testing.TB, config Config) *Namespace {
	t.Helper()
	ns, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func requireConcurrentFailure(err error) namespace.Failure {
	failure, _ := namespace.FailureOf(err)
	return failure
}

func requireFailure(t testing.TB, err error) namespace.Failure {
	t.Helper()
	failure, ok := namespace.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}
