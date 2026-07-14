package tcp

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	ipv6backend "github.com/wago-org/net/internal/backend/lneto/ipv6"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestValidConfigRejectsOverflowAndKeepsAdapterCreationBounded(t *testing.T) {
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 16, TCPResources: 16, QueuedBytes: 1 << 20})
	for _, test := range []struct {
		name    string
		config  Config
		maxInt  uint64
		wantErr bool
	}{
		{name: "normal defaults", config: Config{MaxListeners: 1, MaxOutboundStreams: 8, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}},
		{name: "listener only", config: Config{MaxListeners: 1, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}},
		{name: "outbound only", config: Config{MaxOutboundStreams: 8, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}},
		{name: "max listener values remain valid", config: Config{MaxListeners: ^uint16(0), AcceptBacklog: ^uint16(0), ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}},
		{name: "max outbound values remain valid", config: Config{MaxOutboundStreams: ^uint16(0), ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}},
		{name: "combined port count overflow", config: Config{MaxListeners: ^uint16(0), MaxOutboundStreams: 1, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}, wantErr: true},
		{name: "listener backlog requires unreasonable eager allocation", config: Config{MaxListeners: 1, AcceptBacklog: 256, ReceiveBytes: 1 << 20, TransmitBytes: 1 << 20, TransmitPackets: 4}, wantErr: true},
		{name: "simulated 32-bit outbound storage overflow", config: Config{MaxOutboundStreams: 1, ReceiveBytes: 1 << 30, TransmitBytes: 1 << 30, TransmitPackets: 4}, maxInt: uint64(^uint32(0) >> 1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			maxIntValue := maxInt()
			if test.maxInt != 0 {
				maxIntValue = test.maxInt
			}
			if err := validateConfig(test.config, compiled, account, true, maxIntValue); (err != nil) != test.wantErr {
				t.Fatalf("validateConfig error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}

	common := newConfigTestCore(t, ^uint16(0))
	defer common.Close()
	config := Config{MaxListeners: ^uint16(0), AcceptBacklog: ^uint16(0), ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}
	var adapter *Adapter
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("adapter creation panicked: %v", recovered)
			}
		}()
		var err error
		adapter, err = New(common, config)
		if err != nil {
			t.Fatalf("New error = %v", err)
		}
	}()
	if cap(adapter.streams) != maxTCPStreamCapacityHint {
		t.Fatalf("stream capacity hint = %d, want %d", cap(adapter.streams), maxTCPStreamCapacityHint)
	}
	if len(adapter.streams) != 0 {
		t.Fatalf("new adapter eagerly populated streams = %d", len(adapter.streams))
	}
}

func TestListenerAndConnectReuseReduceSteadyStateAllocations(t *testing.T) {
	_, adapter := newTestAdapter(t, 3, 1, 1)
	listen := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.3"), Port: 4203}
	listenAllocs := testing.AllocsPerRun(1000, func() {
		value, progress, err := adapter.TryListen(listen)
		if err != nil || progress != nscore.ProgressDone {
			panic(err)
		}
		if err := value.Close(); err != nil {
			panic(err)
		}
	})
	if listenAllocs > 3 {
		t.Fatalf("listen/close allocations = %v, want <= 3", listenAllocs)
	}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.4"), Port: 4204}
	connectAllocs := testing.AllocsPerRun(1000, func() {
		value, progress, err := adapter.TryConnect(remote)
		if err != nil || progress != nscore.ProgressInProgress {
			panic(err)
		}
		if err := value.Close(); err != nil {
			panic(err)
		}
	})
	if connectAllocs > 4 {
		t.Fatalf("connect/close allocations = %v, want <= 4", connectAllocs)
	}
}

func TestOutboundStreamCountTracksReuseAndCoreClose(t *testing.T) {
	core, adapter := newTestAdapter(t, 4, 0, 2)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.5"), Port: 4205}
	firstValue, _, err := adapter.TryConnect(remote)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, _, err := adapter.TryConnect(remote)
	if err != nil {
		t.Fatal(err)
	}
	if got := adapter.outboundTCPStreamsLocked(); got != 2 {
		t.Fatalf("active outbound streams = %d", got)
	}
	if _, _, err := adapter.TryConnect(remote); failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("outbound limit = %v", err)
	}
	if err := firstValue.Close(); err != nil {
		t.Fatal(err)
	}
	if got := adapter.outboundTCPStreamsLocked(); got != 1 {
		t.Fatalf("active outbound streams after close = %d", got)
	}
	thirdValue, _, err := adapter.TryConnect(remote)
	if err != nil {
		t.Fatal(err)
	}
	if got := adapter.outboundTCPStreamsLocked(); got != 2 {
		t.Fatalf("active outbound streams after reuse = %d", got)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if got := adapter.outboundTCPStreamsLocked(); got != 0 {
		t.Fatalf("active outbound streams after core close = %d", got)
	}
	if ready := secondValue.(*tcpStream).Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("second readiness after core close = %v", ready)
	}
	if ready := thirdValue.(*tcpStream).Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("third readiness after core close = %v", ready)
	}
	if usage, _ := adapter.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("core close quota = %+v", usage)
	}
}

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
	if usage, closed := server.quotas.Snapshot(); closed || usage != (quota.Usage{Resources: 1, TCPResources: 1, QueuedBytes: 512}) {
		t.Fatalf("listener quota = %+v, closed=%v", usage, closed)
	}
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
	if usage, closed := server.quotas.Snapshot(); closed || usage != (quota.Usage{Resources: 2, TCPResources: 2, QueuedBytes: 512}) {
		t.Fatalf("accepted quota = %+v, closed=%v", usage, closed)
	}
	if len(listener.pool.slots) != 1 || !listener.pool.slots[0].inUse {
		t.Fatalf("accepted pool = %+v", listener.pool.slots)
	}
	if err := serverStream.Close(); err != nil {
		t.Fatal(err)
	}
	if serverStream.conn != nil || serverStream.slot != nil {
		t.Fatalf("closed accepted stream retained graph state: conn=%p slot=%p", serverStream.conn, serverStream.slot)
	}
	if !listener.pool.slots[0].inUse || listener.pool.slots[0].stream == nil || listener.pool.slots[0].quotaOwned {
		t.Fatalf("close bypassed bounded maintenance: in_use=%v stream=%p quota_owned=%v", listener.pool.slots[0].inUse, listener.pool.slots[0].stream, listener.pool.slots[0].quotaOwned)
	}
	if usage, _ := server.quotas.Snapshot(); usage != (quota.Usage{Resources: 1, TCPResources: 1, QueuedBytes: 512}) {
		t.Fatalf("accepted close quota = %+v", usage)
	}

	serverCore.Lock()
	serverCore.SetNextIngressLocked(false)
	required := serverCore.RequiredFrameBytesLocked()
	serverCore.Unlock()
	report, progress, err := serverCore.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Operations: 1}) {
		t.Fatalf("maintenance = %+v, %v, %v", report, progress, err)
	}
	if listener.pool.slots[0].inUse || listener.pool.slots[0].stream != nil || listener.pool.slots[0].quotaOwned {
		t.Fatalf("maintenance retained slot: in_use=%v stream=%p quota_owned=%v", listener.pool.slots[0].inUse, listener.pool.slots[0].stream, listener.pool.slots[0].quotaOwned)
	}
	serverCore.Lock()
	reusedConn, _, _ := listener.pool.GetTCP()
	if reusedConn == nil || !listener.pool.slots[0].quotaOwned {
		serverCore.Unlock()
		t.Fatal("released embedded quota charge was not reusable")
	}
	listener.pool.PutTCP(reusedConn)
	serverCore.Unlock()
	if usage, _ := server.quotas.Snapshot(); usage != (quota.Usage{Resources: 1, TCPResources: 1, QueuedBytes: 512}) {
		t.Fatalf("reused slot quota = %+v", usage)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	listenerRetainedReset := listener.retained.ResetReleased()
	if listenerRetainedReset {
		t.Fatalf("closed listener retained graph state: retained_reset=%v", listenerRetainedReset)
	}
	if usage, _ := server.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("listener close quota = %+v", usage)
	}
}

func TestIPv6ListenerConnectAndDataExchange(t *testing.T) {
	clientCore, client := newIPv6TestAdapter(t, 41, netip.MustParseAddr("2001:db8::41"), 0, 1)
	serverCore, server := newIPv6TestAdapter(t, 42, netip.MustParseAddr("2001:db8::42"), 1, 0)
	serverEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("2001:db8::42"), Port: 4242}
	listenerResource, progress, err := server.TryListen(serverEndpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("IPv6 listen = %T, %v, %v", listenerResource, progress, err)
	}
	listener := listenerResource.(*tcpListener)
	clientResource, progress, err := client.TryConnect(serverEndpoint)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("IPv6 connect = %T, %v, %v", clientResource, progress, err)
	}
	clientStream := clientResource.(*tcpStream)
	transferTCP(t, clientCore, serverCore)
	transferTCP(t, serverCore, clientCore)
	transferTCP(t, clientCore, serverCore)
	if progress, err := clientStream.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("finish IPv6 connect = %v, %v", progress, err)
	}
	serverResource, progress, err := listener.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("IPv6 accept = %T, %v, %v", serverResource, progress, err)
	}
	serverStream := serverResource.(*tcpStream)
	if clientStream.LocalEndpoint().Address != netip.MustParseAddr("2001:db8::41") || serverStream.RemoteEndpoint().Address != netip.MustParseAddr("2001:db8::41") {
		t.Fatalf("IPv6 endpoints = client local %+v server remote %+v", clientStream.LocalEndpoint(), serverStream.RemoteEndpoint())
	}
	payload := []byte("bounded tcp6")
	if result, err := clientStream.TryWrite(payload); err != nil || result.Bytes != len(payload) || result.State != nscore.IOReady {
		t.Fatalf("IPv6 write = %+v, %v", result, err)
	}
	transferTCP(t, clientCore, serverCore)
	buffer := make([]byte, len(payload))
	if result, err := serverStream.TryRead(buffer); err != nil || result.Bytes != len(payload) || string(buffer) != string(payload) {
		t.Fatalf("IPv6 read = %+v, %v, %q", result, err, buffer)
	}
}

func TestIPv6EndpointScopeAndFlowFailClosed(t *testing.T) {
	_, adapter := newIPv6TestAdapter(t, 43, netip.MustParseAddr("fe80::43"), 0, 1)
	for _, remote := range []nscore.Endpoint{
		{Address: netip.MustParseAddr("fe80::44"), Port: 443},
		{Address: netip.MustParseAddr("fe80::44"), Port: 443, ScopeID: 8},
		{Address: netip.MustParseAddr("2001:db8::44"), Port: 443, FlowInfo: 1},
	} {
		if resource, progress, err := adapter.TryConnect(remote); err == nil || resource != nil || progress != 0 {
			t.Fatalf("invalid IPv6 endpoint accepted: %+v => %T %v %v", remote, resource, progress, err)
		}
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
	if usage, closed := adapter.quotas.Snapshot(); closed || usage != (quota.Usage{Resources: 1, TCPResources: 1, QueuedBytes: 512}) {
		t.Fatalf("outbound quota = %+v, closed=%v", usage, closed)
	}
	common.Lock()
	stream.conn.Abort()
	common.Unlock()
	if progress, err := stream.TryFinishConnect(); progress != 0 || failureOf(t, err) != nscore.FailureConnectionRefused {
		t.Fatalf("finish reset = %v, %v", progress, err)
	}
	if got := stream.Readiness(); got&nscore.ReadyError == 0 || got&nscore.ReadyClosed == 0 {
		t.Fatalf("reset readiness = %v", got)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	streamRetainedReset := stream.retained.ResetReleased()
	if stream.conn != nil || streamRetainedReset {
		t.Fatalf("closed outbound stream retained graph state: conn=%p retained_reset=%v", stream.conn, streamRetainedReset)
	}
	if usage, _ := adapter.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("outbound close quota = %+v", usage)
	}
}

func newIPv6TestAdapter(t testing.TB, id byte, address netip.Addr, listeners, outbound uint16) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	prefix := netip.MustParsePrefix("2001:db8::/32")
	scopeID := uint32(0)
	if address.IsLinkLocalUnicast() {
		prefix = netip.MustParsePrefix("fe80::/10")
		scopeID = 7
	}
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP}, Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound}, Prefixes: []netip.Prefix{prefix}},
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mtu := uint16(ethernet.MaxMTU)
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "tcp6", RandSeed: int64(id) + 1,
		HardwareAddress:        [6]byte{0x02, 0, 0, 0, 0, id},
		GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 3},
		IPv4Address:            netip.AddrFrom4([4]byte{192, 0, 2, id}),
		IPv6Address:            address, IPv6PrefixBits: 64, IPv6ScopeID: scopeID, MTU: mtu,
		Link:              packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
		MaxActiveTCPPorts: listeners + outbound,
		Policy:            compiled,
		Quotas: quota.NewAccount(quota.Limits{
			Resources: 17, TCPResources: 16, IPv6Resources: 1, QueuedBytes: 16 << 10,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipv6backend.New(common, ipv6backend.Config{Address: address, PrefixBits: 64, ScopeID: scopeID}); err != nil {
		_ = common.Close()
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
	t.Cleanup(func() { _ = common.Close() })
	return common, adapter
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

func newConfigTestCore(t testing.TB, maxActiveTCPPorts uint16) *lnetocore.Namespace {
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
		Hostname: "tcp-config", RandSeed: 99,
		HardwareAddress:        [6]byte{0x02, 0, 0, 0, 0, 99},
		GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 98},
		IPv4Address:            netip.AddrFrom4([4]byte{192, 0, 2, 99}), MTU: mtu,
		Link:              packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
		MaxActiveTCPPorts: maxActiveTCPPorts,
		Policy:            compiled,
		Quotas:            quota.NewAccount(quota.Limits{Resources: 16, TCPResources: 16, QueuedBytes: 16 << 10}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return common
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
