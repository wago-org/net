package tcp

import (
	"net/netip"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetotcp "github.com/soypat/lneto/tcp"
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

func TestEndpointSnapshotsSerializeWithResourceClose(t *testing.T) {
	core, adapter := newTestAdapter(t, 33, 1, 1)
	listenerValue, progress, err := adapter.TryListen(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.33"), Port: 4033})
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
	}
	streamValue, progress, err := adapter.TryConnect(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.34"), Port: 4034})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", streamValue, progress, err)
	}
	listener := listenerValue.(*tcpListener)
	stream := streamValue.(*tcpStream)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		<-start
		for range 10000 {
			_ = listener.LocalEndpoint()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for range 10000 {
			_, _ = stream.LocalEndpoint(), stream.RemoteEndpoint()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		if err := listener.Close(); err != nil {
			t.Errorf("listener close: %v", err)
		}
		if err := stream.Close(); err != nil {
			t.Errorf("stream close: %v", err)
		}
	}()
	close(start)
	workers.Wait()
	if endpoint := listener.LocalEndpoint(); endpoint != (nscore.Endpoint{}) {
		t.Fatalf("closed listener endpoint = %+v", endpoint)
	}
	if local, remote := stream.LocalEndpoint(), stream.RemoteEndpoint(); local != (nscore.Endpoint{}) || remote != (nscore.Endpoint{}) {
		t.Fatalf("closed stream endpoints = local %+v remote %+v", local, remote)
	}
	if usage, _ := adapter.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed resource quota = %+v", usage)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
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

func TestOutboundStorageAndPortReuseClearDataAndIsolateStaleStream(t *testing.T) {
	_, adapter := newTestAdapter(t, 5, 0, 1)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.6"), Port: 4206}
	firstValue, progress, err := adapter.TryConnect(remote)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("first connect = %T, %v, %v", firstValue, progress, err)
	}
	stale := firstValue.(*tcpStream)
	stalePort := stale.local.Port
	storage := stale.storage
	for i := range storage {
		storage[i] = byte(i | 1)
	}
	storageAddress := &storage[0]
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if stale.storage != nil || stale.conn != nil || stale.allocation != nil || !stale.closed {
		t.Fatalf("closed stale stream retained state: storage=%v conn=%p allocation=%p closed=%v", stale.storage, stale.conn, stale.allocation, stale.closed)
	}
	if len(adapter.freeOutboundStorage) != 1 || &adapter.freeOutboundStorage[0][0] != storageAddress {
		t.Fatalf("outbound storage was not retained for bounded reuse: pools=%d", len(adapter.freeOutboundStorage))
	}
	for i, value := range adapter.freeOutboundStorage[0] {
		if value != 0 {
			t.Fatalf("recycled storage byte %d = %d", i, value)
		}
	}
	adapter.nextPort = stalePort
	freshValue, progress, err := adapter.TryConnect(remote)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("fresh connect = %T, %v, %v", freshValue, progress, err)
	}
	fresh := freshValue.(*tcpStream)
	if fresh == stale || fresh.local.Port != stalePort || &fresh.storage[0] != storageAddress {
		t.Fatalf("fresh reuse = same wrapper %v, port %d want %d, storage reused %v", fresh == stale, fresh.local.Port, stalePort, &fresh.storage[0] == storageAddress)
	}
	if progress, err := stale.TryFinishConnect(); progress != 0 || failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("stale finish connect = %v, %v", progress, err)
	}
	if result, err := stale.TryRead(make([]byte, 1)); result != (nscore.IOResult{}) || failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("stale read = %+v, %v", result, err)
	}
	if result, err := stale.TryWrite([]byte{1}); result != (nscore.IOResult{}) || failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("stale write = %+v, %v", result, err)
	}
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if fresh.closed || fresh.conn == nil || fresh.storage == nil {
		t.Fatalf("stale operations mutated fresh stream: %+v", fresh)
	}
	if usage, closed := adapter.quotas.Snapshot(); closed || usage != (quota.Usage{Resources: 1, TCPResources: 1, QueuedBytes: 512}) {
		t.Fatalf("fresh quota = %+v, closed=%v", usage, closed)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := adapter.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("final quota = %+v", usage)
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

func TestConnectedStatePersistsThroughHalfClose(t *testing.T) {
	clientCore, _, client, serverCore, server := newEstablishedPair(t)
	payload := []byte("buffered before FIN")
	if result, err := client.TryWrite(payload); err != nil || result != (nscore.IOResult{Bytes: len(payload), State: nscore.IOReady}) {
		t.Fatalf("write before shutdown = %+v, %v", result, err)
	}
	if progress, err := client.TryShutdownWrite(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("shutdown write = %v, %v", progress, err)
	}
	transferTCP(t, clientCore, serverCore)
	if ready := server.Readiness(); ready&nscore.ReadyReadable == 0 || ready&nscore.ReadyClosed != 0 {
		t.Fatalf("buffered readiness before FIN = %v", ready)
	}
	buffer := make([]byte, len(payload))
	if result, err := server.TryRead(buffer); err != nil || result != (nscore.IOResult{Bytes: len(payload), State: nscore.IOReady}) || string(buffer) != string(payload) {
		t.Fatalf("buffered read = %+v, %v, %q", result, err, buffer)
	}
	if result, err := server.TryRead(buffer); err != nil || result.State != nscore.IOWouldBlock {
		t.Fatalf("read before FIN = %+v, %v", result, err)
	}
	transferTCP(t, serverCore, clientCore)
	transferTCP(t, clientCore, serverCore)
	if ready := client.Readiness(); ready&nscore.ReadyConnected == 0 || ready&(nscore.ReadyWritable|nscore.ReadyClosed|nscore.ReadyError) != 0 {
		t.Fatalf("local half-close readiness = %v", ready)
	}
	if progress, err := client.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("finish after half-close = %v, %v", progress, err)
	}
	if ready := server.Readiness(); ready&nscore.ReadyConnected == 0 || ready&nscore.ReadyWritable == 0 || ready&nscore.ReadyClosed == 0 || ready&nscore.ReadyReadable != 0 {
		t.Fatalf("peer half-close readiness = %v", ready)
	}
	if result, err := server.TryRead(buffer); err != nil || result.State != nscore.IOEOF {
		t.Fatalf("read after FIN = %+v, %v", result, err)
	}
}

func TestSimultaneousShutdownReachesStableEOFAndAcceptedSlotReuse(t *testing.T) {
	clientCore, listener, client, serverCore, server := newEstablishedPair(t)
	serverAdapter := listener.owner
	clientAdapter := client.owner
	endpoint := listener.local

	if progress, err := client.TryShutdownWrite(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("client shutdown = %v, %v", progress, err)
	}
	if progress, err := server.TryShutdownWrite(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("server shutdown = %v, %v", progress, err)
	}
	for range 8 {
		moved := tryTransferTCP(t, clientCore, serverCore)
		moved = tryTransferTCP(t, serverCore, clientCore) || moved
		clientResult, clientErr := client.TryRead(make([]byte, 1))
		serverResult, serverErr := server.TryRead(make([]byte, 1))
		if clientErr == nil && serverErr == nil && clientResult.State == nscore.IOEOF && serverResult.State == nscore.IOEOF {
			break
		}
		if !moved {
			t.Fatalf("simultaneous shutdown stalled: client=%+v/%v server=%+v/%v", clientResult, clientErr, serverResult, serverErr)
		}
	}

	for name, stream := range map[string]*tcpStream{"client": client, "server": server} {
		if ready := stream.Readiness(); ready&nscore.ReadyConnected == 0 || ready&nscore.ReadyClosed == 0 || ready&(nscore.ReadyReadable|nscore.ReadyWritable|nscore.ReadyError) != 0 {
			t.Fatalf("%s simultaneous-close readiness = %v", name, ready)
		}
		if result, err := stream.TryRead(make([]byte, 1)); err != nil || result.State != nscore.IOEOF {
			t.Fatalf("%s simultaneous-close read = %+v, %v", name, result, err)
		}
		if progress, err := stream.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
			t.Fatalf("%s finish after simultaneous close = %v, %v", name, progress, err)
		}
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if len(listener.pool.slots) != 1 || !listener.pool.slots[0].inUse || listener.pool.slots[0].stream == nil || listener.pool.slots[0].quotaOwned {
		t.Fatalf("accepted close slot = %+v", listener.pool.slots)
	}
	serverCore.Lock()
	serverCore.SetNextIngressLocked(false)
	required := serverCore.RequiredFrameBytesLocked()
	serverCore.Unlock()
	report, progress, err := serverCore.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Operations: 1}) {
		t.Fatalf("accepted retirement maintenance = %+v, %v, %v", report, progress, err)
	}
	if slot := &listener.pool.slots[0]; slot.inUse || slot.stream != nil || slot.quotaOwned {
		t.Fatalf("accepted slot retained after maintenance: in_use=%v stream=%p quota_owned=%v", slot.inUse, slot.stream, slot.quotaOwned)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	replacementValue, progress, err := clientAdapter.TryConnect(endpoint)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("replacement connect = %T, %v, %v", replacementValue, progress, err)
	}
	replacementClient := replacementValue.(*tcpStream)
	transferTCP(t, clientCore, serverCore)
	transferTCP(t, serverCore, clientCore)
	transferTCP(t, clientCore, serverCore)
	if progress, err := replacementClient.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("replacement finish = %v, %v", progress, err)
	}
	replacementServerValue, progress, err := listener.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("replacement accept = %T, %v, %v", replacementServerValue, progress, err)
	}
	replacementServer := replacementServerValue.(*tcpStream)
	if replacementServer == server || server.conn != nil || server.slot != nil || !server.closed {
		t.Fatalf("stale accepted wrapper reused: old=%p new=%p conn=%p slot=%p closed=%v", server, replacementServer, server.conn, server.slot, server.closed)
	}
	if usage, _ := serverAdapter.quotas.Snapshot(); usage != (quota.Usage{Resources: 2, TCPResources: 2, QueuedBytes: 512}) {
		t.Fatalf("replacement server quota = %+v", usage)
	}
}

func TestQueuedPeerHalfCloseAcceptsAsConnectedEOFAndRetiresSlot(t *testing.T) {
	clientCore, client := newTestAdapter(t, 71, 0, 1)
	serverCore, server := newTestAdapter(t, 72, 1, 0)
	clientMAC := [6]byte{0x02, 0, 0, 0, 0, 71}
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 72}
	setGateways(clientCore, serverMAC)
	setGateways(serverCore, clientMAC)

	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.72"), Port: 4272}
	listenerValue, progress, err := server.TryListen(endpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
	}
	listener := listenerValue.(*tcpListener)
	clientValue, progress, err := client.TryConnect(endpoint)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", clientValue, progress, err)
	}
	clientStream := clientValue.(*tcpStream)
	transferTCP(t, clientCore, serverCore)
	transferTCP(t, serverCore, clientCore)
	transferTCP(t, clientCore, serverCore)
	if progress, err := clientStream.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("finish connect = %v, %v", progress, err)
	}
	if ready := listener.Readiness(); ready != nscore.ReadyAccept {
		t.Fatalf("queued connection readiness = %v", ready)
	}

	if progress, err := clientStream.TryShutdownWrite(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("queued peer shutdown = %v, %v", progress, err)
	}
	transferTCP(t, clientCore, serverCore)
	transferTCP(t, serverCore, clientCore)
	if ready := listener.Readiness(); ready != nscore.ReadyAccept {
		t.Fatalf("half-closed queued readiness = %v", ready)
	}
	acceptedValue, progress, err := listener.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("accept half-closed = %T, %v, %v", acceptedValue, progress, err)
	}
	accepted := acceptedValue.(*tcpStream)
	if ready := accepted.Readiness(); ready&nscore.ReadyConnected == 0 || ready&nscore.ReadyClosed == 0 || ready&nscore.ReadyWritable == 0 || ready&(nscore.ReadyReadable|nscore.ReadyError) != 0 {
		t.Fatalf("accepted half-close readiness = %v", ready)
	}
	if result, err := accepted.TryRead(make([]byte, 1)); err != nil || result.State != nscore.IOEOF {
		t.Fatalf("accepted half-close read = %+v, %v", result, err)
	}
	if progress, err := accepted.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("accepted half-close finish = %v, %v", progress, err)
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
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
		t.Fatalf("accepted retirement = %+v, %v, %v", report, progress, err)
	}
	if slot := &listener.pool.slots[0]; slot.inUse || slot.stream != nil || slot.quotaOwned {
		t.Fatalf("retired slot = in_use=%v stream=%p quota_owned=%v", slot.inUse, slot.stream, slot.quotaOwned)
	}
	if ready := accepted.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("closed accepted readiness = %v", ready)
	}
	if err := accepted.Close(); err != nil {
		t.Fatalf("second accepted close = %v", err)
	}
}

func TestMultipleQueuedPeerHalfClosesAcceptReachableSlotAndReleaseTerminalPeer(t *testing.T) {
	clientCore1, client1 := newTestAdapter(t, 73, 0, 1)
	clientCore2, client2 := newTestAdapter(t, 74, 0, 1)
	serverCore, server := newTestAdapterWithBacklog(t, 75, 1, 0, 2)
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 75}
	clientMAC1 := [6]byte{0x02, 0, 0, 0, 0, 73}
	clientMAC2 := [6]byte{0x02, 0, 0, 0, 0, 74}
	setGateways(clientCore1, serverMAC)
	setGateways(clientCore2, serverMAC)

	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.75"), Port: 4275}
	listenerValue, progress, err := server.TryListen(endpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
	}
	listener := listenerValue.(*tcpListener)
	connect := func(clientCore *lnetocore.Namespace, client *Adapter, clientMAC [6]byte) *tcpStream {
		t.Helper()
		value, progress, err := client.TryConnect(endpoint)
		if err != nil || progress != nscore.ProgressInProgress {
			t.Fatalf("connect = %T, %v, %v", value, progress, err)
		}
		stream := value.(*tcpStream)
		transferTCP(t, clientCore, serverCore)
		setGateways(serverCore, clientMAC)
		transferTCP(t, serverCore, clientCore)
		transferTCP(t, clientCore, serverCore)
		if progress, err := stream.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
			t.Fatalf("finish connect = %v, %v", progress, err)
		}
		return stream
	}
	firstClient := connect(clientCore1, client1, clientMAC1)
	secondClient := connect(clientCore2, client2, clientMAC2)
	if progress, err := firstClient.TryShutdownWrite(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("first queued shutdown = %v, %v", progress, err)
	}
	transferTCP(t, clientCore1, serverCore)
	setGateways(serverCore, clientMAC1)
	transferTCP(t, serverCore, clientCore1)
	if progress, err := secondClient.TryShutdownWrite(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("second queued shutdown = %v, %v", progress, err)
	}
	transferTCP(t, clientCore2, serverCore)
	setGateways(serverCore, clientMAC2)
	transferTCP(t, serverCore, clientCore2)
	if ready := listener.Readiness(); ready != nscore.ReadyAccept {
		t.Fatalf("half-closed backlog readiness = %v", ready)
	}
	if usage, closed := server.quotas.Snapshot(); closed || usage != (quota.Usage{Resources: 3, TCPResources: 3, QueuedBytes: 1024}) {
		t.Fatalf("mixed backlog quota = %+v, closed=%v", usage, closed)
	}

	acceptedValue, progress, err := listener.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("fallback accept = %T, %v, %v", acceptedValue, progress, err)
	}
	accepted := acceptedValue.(*tcpStream)
	if accepted.RemoteEndpoint().Address != netip.MustParseAddr("192.0.2.74") {
		t.Fatalf("fallback remote = %+v", accepted.RemoteEndpoint())
	}
	if ready := accepted.Readiness(); ready&nscore.ReadyConnected == 0 || ready&nscore.ReadyClosed == 0 || ready&nscore.ReadyWritable == 0 || ready&(nscore.ReadyReadable|nscore.ReadyError) != 0 {
		t.Fatalf("fallback accepted readiness = %v", ready)
	}
	if result, err := accepted.TryRead(make([]byte, 1)); err != nil || result.State != nscore.IOEOF {
		t.Fatalf("fallback accepted read = %+v, %v", result, err)
	}
	if ready := listener.Readiness(); ready != 0 {
		t.Fatalf("terminal queued peer reported accept readiness = %v", ready)
	}
	if slot := &listener.pool.slots[0]; slot.conn.InternalHandler().State() != lnetotcp.StateLastAck || !slot.inUse || slot.stream != nil || !slot.quotaOwned {
		t.Fatalf("terminal queued slot = state=%v in_use=%v stream=%p quota_owned=%v", slot.conn.InternalHandler().State(), slot.inUse, slot.stream, slot.quotaOwned)
	}

	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := server.quotas.Snapshot(); usage != (quota.Usage{Resources: 2, TCPResources: 2, QueuedBytes: 1024}) {
		t.Fatalf("accepted close quota = %+v", usage)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := server.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("listener close quota = %+v", usage)
	}
	if accepted.Readiness() != nscore.ReadyClosed {
		t.Fatalf("stale accepted readiness = %v", accepted.Readiness())
	}
	if err := firstClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := secondClient.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEstablishedResetIsAConnectionEventNotServiceFailure(t *testing.T) {
	clientCore, _, client, serverCore, server := newEstablishedPair(t)
	if result, err := client.TryWrite([]byte{0x5a}); err != nil || result != (nscore.IOResult{Bytes: 1, State: nscore.IOReady}) {
		t.Fatalf("write = %+v, %v", result, err)
	}
	transferTCP(t, clientCore, serverCore)
	ack := nextTCPFrame(t, serverCore)
	ethernetFrame, err := ethernet.NewFrame(ack)
	if err != nil {
		t.Fatal(err)
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	tcpFrame, err := lnetotcp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	offset, _ := tcpFrame.OffsetAndFlags()
	tcpFrame.SetOffsetAndFlags(offset, lnetotcp.FlagRST|lnetotcp.FlagACK)
	tcpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWriteTCPPseudo(&checksum)
	tcpFrame.SetCRC(checksum.PayloadSum16(tcpFrame.RawData()))

	if err := clientCore.Link().TryEnqueue(packetlink.Ingress, ack); err != nil {
		t.Fatal(err)
	}
	clientCore.Lock()
	clientCore.SetNextIngressLocked(true)
	required := clientCore.RequiredFrameBytesLocked()
	clientCore.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1}
	report, progress, err := clientCore.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: uint32(len(ack)), Operations: 1}) {
		t.Fatalf("reset service = %+v, %v, %v", report, progress, err)
	}
	if ready := client.Readiness(); ready&nscore.ReadyConnected == 0 || ready&nscore.ReadyClosed == 0 || ready&nscore.ReadyWritable != 0 {
		t.Fatalf("reset readiness = %v", ready)
	}
	if progress, err := client.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("finish after reset = %v, %v", progress, err)
	}
	if result, err := client.TryRead(make([]byte, 1)); err != nil || result.State != nscore.IOEOF {
		t.Fatalf("read after reset = %+v, %v", result, err)
	}
	if result, err := client.TryWrite([]byte{1}); err == nil || failureOf(t, err) != nscore.FailureConnectionBroken {
		t.Fatalf("write after reset = %+v, %v", result, err)
	}
	if result, err := server.TryRead(make([]byte, 1)); err != nil || result != (nscore.IOResult{Bytes: 1, State: nscore.IOReady}) {
		t.Fatalf("server retained input = %+v, %v", result, err)
	}
}

func TestListenerBacklogCloseDetachesAllSlotsBeforePoolReuse(t *testing.T) {
	clientCore1, client1 := newTestAdapter(t, 61, 0, 1)
	clientCore2, client2 := newTestAdapter(t, 62, 0, 1)
	serverCore, server := newTestAdapterWithBacklog(t, 63, 1, 0, 2)
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 63}
	clientMAC1 := [6]byte{0x02, 0, 0, 0, 0, 61}
	clientMAC2 := [6]byte{0x02, 0, 0, 0, 0, 62}
	setGateways(clientCore1, serverMAC)
	setGateways(clientCore2, serverMAC)

	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.63"), Port: 4263}
	listenerValue, progress, err := server.TryListen(endpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
	}
	listener := listenerValue.(*tcpListener)
	connect := func(clientCore *lnetocore.Namespace, client *Adapter, clientMAC [6]byte) *tcpStream {
		t.Helper()
		value, progress, err := client.TryConnect(endpoint)
		if err != nil || progress != nscore.ProgressInProgress {
			t.Fatalf("connect = %T, %v, %v", value, progress, err)
		}
		stream := value.(*tcpStream)
		transferTCP(t, clientCore, serverCore)
		setGateways(serverCore, clientMAC)
		transferTCP(t, serverCore, clientCore)
		transferTCP(t, clientCore, serverCore)
		if progress, err := stream.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
			t.Fatalf("finish connect = %v, %v", progress, err)
		}
		return stream
	}
	firstClient := connect(clientCore1, client1, clientMAC1)
	connect(clientCore2, client2, clientMAC2)
	if ready := listener.Readiness(); ready != nscore.ReadyAccept {
		t.Fatalf("full backlog readiness = %v", ready)
	}
	if usage, closed := server.quotas.Snapshot(); closed || usage != (quota.Usage{Resources: 3, TCPResources: 3, QueuedBytes: 1024}) {
		t.Fatalf("full backlog quota = %+v, closed=%v", usage, closed)
	}

	acceptedValue, progress, err := listener.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("accept = %T, %v, %v", acceptedValue, progress, err)
	}
	accepted := acceptedValue.(*tcpStream)
	if len(listener.pool.slots) != 2 || (listener.pool.slots[0].stream == nil && listener.pool.slots[1].stream == nil) {
		t.Fatalf("accepted slot state = %+v", listener.pool.slots)
	}
	if ready := listener.Readiness(); ready != nscore.ReadyAccept {
		t.Fatalf("remaining backlog readiness = %v", ready)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if ready := listener.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("closed listener readiness = %v", ready)
	}
	if value, progress, err := listener.TryAccept(); value != nil || progress != 0 || failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("closed listener accept = %T, %v, %v", value, progress, err)
	}
	if ready := accepted.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("detached accepted readiness = %v", ready)
	}
	if result, err := accepted.TryRead(make([]byte, 1)); err != nil || result.State != nscore.IOEOF {
		t.Fatalf("detached accepted read = %+v, %v", result, err)
	}
	if result, err := accepted.TryWrite([]byte{1}); err == nil || failureOf(t, err) != nscore.FailureConnectionBroken {
		t.Fatalf("detached accepted write = %+v, %v", result, err)
	}
	if accepted.conn != nil || accepted.slot != nil || !accepted.terminal {
		t.Fatalf("detached accepted graph = conn=%p slot=%p terminal=%v", accepted.conn, accepted.slot, accepted.terminal)
	}
	if usage, _ := server.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("listener close quota = %+v", usage)
	}
	if len(server.freeListenerPools) != 1 {
		t.Fatalf("free listener pools = %d", len(server.freeListenerPools))
	}
	for i := range server.freeListenerPools[0].slots {
		slot := &server.freeListenerPools[0].slots[i]
		if slot.inUse || slot.stream != nil || slot.quotaOwned || slot.resource.ResetReleased() {
			t.Fatalf("released slot %d = in_use=%v stream=%p quota_owned=%v", i, slot.inUse, slot.stream, slot.quotaOwned)
		}
	}

	if err := firstClient.Close(); err != nil {
		t.Fatal(err)
	}
	replacementValue, progress, err := server.TryListen(endpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("replacement listen = %T, %v, %v", replacementValue, progress, err)
	}
	replacement := replacementValue.(*tcpListener)
	if replacement == listener || len(server.freeListenerPools) != 0 {
		t.Fatalf("replacement wrapper/pool reuse = same_wrapper=%v free_pools=%d", replacement == listener, len(server.freeListenerPools))
	}
	connect(clientCore1, client1, clientMAC1)
	thirdServerValue, progress, err := replacement.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("replacement accept = %T, %v, %v", thirdServerValue, progress, err)
	}
	thirdServer := thirdServerValue.(*tcpStream)
	if thirdServer == accepted || accepted.conn != nil || accepted.slot != nil || !accepted.terminal {
		t.Fatalf("stale accepted stream reused: old=%p new=%p conn=%p slot=%p terminal=%v", accepted, thirdServer, accepted.conn, accepted.slot, accepted.terminal)
	}
	if usage, _ := server.quotas.Snapshot(); usage != (quota.Usage{Resources: 2, TCPResources: 2, QueuedBytes: 1024}) {
		t.Fatalf("replacement quota = %+v", usage)
	}
}

func TestListenerCloseDetachesAcceptedStreamBeforePoolReuse(t *testing.T) {
	clientCore, listener, client, serverCore, server := newEstablishedPair(t)
	serverAdapter := listener.owner
	clientAdapter := client.owner
	endpoint := listener.local
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if ready := server.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("detached accepted readiness = %v", ready)
	}
	if result, err := server.TryRead(make([]byte, 1)); err != nil || result.State != nscore.IOEOF {
		t.Fatalf("detached accepted read = %+v, %v", result, err)
	}
	if usage, _ := serverAdapter.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("listener close quota = %+v", usage)
	}
	replacementValue, progress, err := serverAdapter.TryListen(endpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("replacement listen = %T, %v, %v", replacementValue, progress, err)
	}
	replacement := replacementValue.(*tcpListener)
	if replacement == listener {
		t.Fatal("listener wrapper unexpectedly reused")
	}
	secondClientValue, progress, err := clientAdapter.TryConnect(endpoint)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("second connect = %T, %v, %v", secondClientValue, progress, err)
	}
	secondClient := secondClientValue.(*tcpStream)
	transferTCP(t, clientCore, serverCore)
	transferTCP(t, serverCore, clientCore)
	transferTCP(t, clientCore, serverCore)
	if progress, err := secondClient.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("second finish connect = %v, %v", progress, err)
	}
	secondServerValue, progress, err := replacement.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("second accept = %T, %v, %v", secondServerValue, progress, err)
	}
	secondServer := secondServerValue.(*tcpStream)
	if secondServer == server || server.conn != nil || server.slot != nil || !server.terminal {
		t.Fatalf("stale accepted stream reused: old=%p new=%p conn=%p slot=%p terminal=%v", server, secondServer, server.conn, server.slot, server.terminal)
	}
	if ready := server.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("stale accepted readiness after reuse = %v", ready)
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
	backlog := uint16(0)
	if listeners > 0 {
		backlog = 1
	}
	return newTestAdapterWithBacklog(t, id, listeners, outbound, backlog)
}

func newTestAdapterWithBacklog(t testing.TB, id byte, listeners, outbound, backlog uint16) (*lnetocore.Namespace, *Adapter) {
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
		MaxListeners: listeners, MaxOutboundStreams: outbound, AcceptBacklog: backlog,
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

func tryTransferTCP(t testing.TB, from, to *lnetocore.Namespace) bool {
	t.Helper()
	from.Lock()
	from.SetNextIngressLocked(false)
	required := from.RequiredFrameBytesLocked()
	from.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1}
	report, progress, err := from.TryService(budget)
	if err != nil {
		t.Fatalf("optional egress = %+v, %v, %v", report, progress, err)
	}
	if report.Packets == 0 {
		if progress != nscore.ProgressWouldBlock && report.Operations == 0 {
			t.Fatalf("optional egress without packet = %+v, %v", report, progress)
		}
		return false
	}
	if progress != nscore.ProgressDone || report.Packets != 1 {
		t.Fatalf("optional egress = %+v, %v", report, progress)
	}
	buffer := make([]byte, from.Link().MaxFrameBytes())
	result, err := from.Link().TryDequeue(packetlink.Egress, buffer)
	if err != nil || !result.Ready || result.Truncated || result.FrameBytes == 0 {
		t.Fatalf("optional dequeue = %+v, %v", result, err)
	}
	if err := to.Link().TryEnqueue(packetlink.Ingress, buffer[:result.FrameBytes]); err != nil {
		t.Fatal(err)
	}
	to.Lock()
	to.SetNextIngressLocked(true)
	to.Unlock()
	report, progress, err = to.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		t.Fatalf("optional ingress = %+v, %v, %v", report, progress, err)
	}
	return true
}

func nextTCPFrame(t testing.TB, from *lnetocore.Namespace) []byte {
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
	frame := make([]byte, from.Link().MaxFrameBytes())
	result, err := from.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready || result.Truncated || result.FrameBytes == 0 {
		t.Fatalf("dequeue = %+v, %v", result, err)
	}
	return frame[:result.FrameBytes]
}

func failureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}
