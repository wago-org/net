package tcp

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestAcceptedCloseRetainsSlotUntilChargedMaintenance(t *testing.T) {
	clientCore, client := newTestAdapter(t, 1, 0, 2)
	serverCore, server := newTestAdapter(t, 2, 1, 0)
	setGateways(clientCore, [6]byte{0x02, 0, 0, 0, 0, 2})
	setGateways(serverCore, [6]byte{0x02, 0, 0, 0, 0, 1})

	serverEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 4238}
	listenerResource, progress, err := server.TryListen(serverEndpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerResource, progress, err)
	}
	listener := listenerResource.(*tcpListener)
	clientResource, progress, err := client.TryConnect(serverEndpoint)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", clientResource, progress, err)
	}
	clientStream := clientResource.(*tcpStream)
	transferTCP(t, clientCore, serverCore)
	transferTCP(t, serverCore, clientCore)
	transferTCP(t, clientCore, serverCore)
	if progress, err := clientStream.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("finish connect = %v, %v", progress, err)
	}
	serverResource, progress, err := listener.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("accept = %T, %v, %v", serverResource, progress, err)
	}
	serverStream := serverResource.(*tcpStream)
	if len(listener.pool.slots) != 1 || !listener.pool.slots[0].inUse {
		t.Fatalf("accepted pool = %+v", listener.pool.slots)
	}
	if err := serverStream.Close(); err != nil {
		t.Fatal(err)
	}
	if !listener.pool.slots[0].inUse || listener.pool.slots[0].stream == nil || listener.pool.slots[0].resource != nil {
		t.Fatalf("close bypassed bounded maintenance: in_use=%v stream=%p resource=%p", listener.pool.slots[0].inUse, listener.pool.slots[0].stream, listener.pool.slots[0].resource)
	}

	serverCore.Lock()
	serverCore.SetNextIngressLocked(false)
	required := serverCore.RequiredFrameBytesLocked()
	serverCore.Unlock()
	report, progress, err := serverCore.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Operations: 1}) {
		t.Fatalf("maintenance = %+v, %v, %v", report, progress, err)
	}
	if listener.pool.slots[0].inUse || listener.pool.slots[0].stream != nil || listener.pool.slots[0].resource != nil {
		t.Fatalf("maintenance retained slot: in_use=%v stream=%p resource=%p", listener.pool.slots[0].inUse, listener.pool.slots[0].stream, listener.pool.slots[0].resource)
	}
}

func TestConnectResetBeforeEstablishment(t *testing.T) {
	common, adapter := newTestAdapter(t, 3, 0, 1)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.4"), Port: 4299}
	resource, progress, err := adapter.TryConnect(remote)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", resource, progress, err)
	}
	stream := resource.(*tcpStream)
	common.Lock()
	stream.conn.Abort()
	common.Unlock()
	if progress, err := stream.TryFinishConnect(); progress != 0 || failureOf(t, err) != nscore.FailureConnectionRefused {
		t.Fatalf("finish reset = %v, %v", progress, err)
	}
	if got := stream.Readiness(); got&nscore.ReadyError == 0 || got&nscore.ReadyClosed == 0 {
		t.Fatalf("reset readiness = %v", got)
	}
}

func newTestAdapter(t testing.TB, id byte, listeners, outbound uint16) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	mtu := uint16(ethernet.MaxMTU)
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "tcp", RandSeed: int64(id) + 1,
		HardwareAddress:        [6]byte{0x02, 0, 0, 0, 0, id},
		GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 3},
		IPv4Address:            netip.AddrFrom4([4]byte{192, 0, 2, id}), MTU: mtu,
		Link:              packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
		MaxActiveTCPPorts: listeners + outbound,
		Policy:            compiled,
		Quotas:            quota.NewAccount(quota.Limits{Resources: 16, TCPResources: 16, QueuedBytes: 16 << 10}),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(common, Config{
		MaxListeners: listeners, MaxOutboundStreams: outbound,
		AcceptBacklog: func() uint16 {
			if listeners > 0 {
				return 1
			}
			return 0
		}(),
		ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4,
	})
	if err != nil {
		_ = common.Close()
		t.Fatal(err)
	}
	if err := common.Install(lnetocore.Participant{Close: adapter.CloseLocked}); err != nil {
		_ = common.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = common.Close() })
	return common, adapter
}

func setGateways(common *lnetocore.Namespace, gateway [6]byte) {
	common.Lock()
	common.StackLocked().SetGatewayHardwareAddr(gateway)
	common.Unlock()
}

func transferTCP(t testing.TB, from, to *lnetocore.Namespace) {
	t.Helper()
	from.Lock()
	from.SetNextIngressLocked(false)
	required := from.RequiredFrameBytesLocked()
	from.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1}
	report, progress, err := from.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		t.Fatalf("egress = %+v, %v, %v", report, progress, err)
	}
	buffer := make([]byte, from.Link().MaxFrameBytes())
	result, err := from.Link().TryDequeue(packetlink.Egress, buffer)
	if err != nil || !result.Ready || result.Truncated || result.FrameBytes == 0 {
		t.Fatalf("dequeue = %+v, %v", result, err)
	}
	if err := to.Link().TryEnqueue(packetlink.Ingress, buffer[:result.FrameBytes]); err != nil {
		t.Fatal(err)
	}
	to.Lock()
	to.SetNextIngressLocked(true)
	to.Unlock()
	report, progress, err = to.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		t.Fatalf("ingress = %+v, %v, %v", report, progress, err)
	}
}

func failureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}
