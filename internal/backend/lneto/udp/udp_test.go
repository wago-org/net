package udp

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestAdapterExchangeTruncationPortLeaseAndClose(t *testing.T) {
	aCore, aAdapter, aAccount := newTestAdapter(t, 31)
	bCore, bAdapter, _ := newTestAdapter(t, 32)
	aLocal := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.31"), Port: 4031}
	bLocal := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.32"), Port: 4032}
	a := bindTestSocket(t, aAdapter, aLocal).(*udpSocket)
	b := bindTestSocket(t, bAdapter, bLocal).(*udpSocket)
	if _, _, err := aAdapter.TryBind(aLocal); err == nil {
		t.Fatal("duplicate bind succeeded")
	} else if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureAddressInUse {
		t.Fatalf("duplicate bind error = %v", err)
	}
	if progress, err := a.TrySend([]byte("abcdef"), bLocal); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("send = %v, %v", progress, err)
	}

	aCore.Lock()
	aCore.SetNextIngressLocked(false)
	aCore.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(aCore.Link().MaxFrameBytes()), Operations: 1}
	report, progress, err := aCore.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("egress = %+v, %v, %v", report, progress, err)
	}
	frame := make([]byte, aCore.Link().MaxFrameBytes())
	result, err := aCore.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready {
		t.Fatalf("dequeue = %+v, %v", result, err)
	}
	if err := bCore.Link().TryEnqueue(packetlink.Ingress, frame[:result.FrameBytes]); err != nil {
		t.Fatal(err)
	}
	bCore.Lock()
	bCore.SetNextIngressLocked(true)
	bCore.Unlock()
	report, progress, err = bCore.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("ingress = %+v, %v, %v", report, progress, err)
	}
	buf := make([]byte, 3)
	datagram, err := b.TryReceive(buf)
	if err != nil || !datagram.Ready || datagram.DatagramBytes != 6 || datagram.Copied != 3 || !datagram.Truncated || string(buf) != "abc" || datagram.Source != aLocal {
		t.Fatalf("receive = %+v %q, %v", datagram, buf, err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	aCore.Lock()
	if count := aCore.UDPPortLeaseCountLocked(); count != 0 {
		aCore.Unlock()
		t.Fatalf("closed socket retained %d port leases", count)
	}
	aCore.Unlock()
	if usage, _ := aAccount.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed socket retained quota = %+v", usage)
	}
	retainedReset := a.retained.ResetReleased()
	if retainedReset || a.rx.storage != nil || a.tx.storage != nil {
		t.Fatalf("closed socket retained graph state: retained_reset=%v rx=%v tx=%v", retainedReset, a.rx.storage != nil, a.tx.storage != nil)
	}
}

func TestEphemeralBindChecksFinalAllocatedPortAgainstPolicy(t *testing.T) {
	config := Config{MaxSockets: 1, ReceiveBytes: 32, TransmitBytes: 32, ReceiveDatagrams: 1, TransmitDatagrams: 1, MaxPayloadBytes: 32}
	policyConfig := policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionInbound}, Ports: []policy.PortRange{{First: firstEphemeralUDPPort, Last: firstEphemeralUDPPort}}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionInbound}, Ports: []policy.PortRange{{First: 0, Last: 0}}},
		},
		WildcardBindTransports: []policy.Transport{policy.TransportUDP},
	}
	common, adapter, account := newTestAdapterWithConfigAndPolicy(t, 35, config, policyConfig)
	local := nscore.Endpoint{Address: netip.IPv4Unspecified()}
	if resource, progress, err := adapter.TryBind(local); err == nil || resource != nil || progress != 0 {
		t.Fatalf("denied first ephemeral bind = %T, %v, %v", resource, progress, err)
	} else if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureAccessDenied {
		t.Fatalf("denied first ephemeral bind failure = %v", err)
	}
	common.Lock()
	if leases := common.UDPPortLeaseCountLocked(); leases != 0 {
		common.Unlock()
		t.Fatalf("denied ephemeral bind retained %d leases", leases)
	}
	common.Unlock()
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("denied ephemeral bind retained quota = %+v", usage)
	}
	resource, progress, err := adapter.TryBind(local)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("second ephemeral bind = %T, %v, %v", resource, progress, err)
	}
	socket := resource.(udpns.Socket)
	if got := socket.LocalEndpoint().Port; got != firstEphemeralUDPPort+1 {
		t.Fatalf("second ephemeral port = %d, want %d", got, firstEphemeralUDPPort+1)
	}
}

func TestAdapterCloseReleasesAllSocketsDeterministically(t *testing.T) {
	common, adapter, account := newTestAdapter(t, 33)
	for _, port := range []uint16{4100, 4101} {
		bindTestSocket(t, adapter, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.33"), Port: port})
	}
	if err := common.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("core close retained quota = %+v", usage)
	}
}

func TestSocketDatagramQueuesShareBackingStorage(t *testing.T) {
	config := Config{ReceiveBytes: 64, TransmitBytes: 96, ReceiveDatagrams: 2, TransmitDatagrams: 3, MaxPayloadBytes: 32}
	rx, tx := newSocketDatagramQueues(config)
	if len(rx.storage) != 64 || cap(rx.storage) != 64 || len(tx.storage) != 96 || cap(tx.storage) != 96 {
		t.Fatalf("payload layout = rx %d/%d tx %d/%d", len(rx.storage), cap(rx.storage), len(tx.storage), cap(tx.storage))
	}
	if len(rx.slots) != 2 || cap(rx.slots) != 2 || len(tx.slots) != 3 || cap(tx.slots) != 3 {
		t.Fatalf("slot layout = rx %d/%d tx %d/%d", len(rx.slots), cap(rx.slots), len(tx.slots), cap(tx.slots))
	}
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 53}
	if !rx.push([]byte("receive"), endpoint) || !tx.push([]byte("transmit"), endpoint) {
		t.Fatal("shared queues rejected independent payloads")
	}
	rxPayload, _, _ := rx.peek()
	txPayload, _, _ := tx.peek()
	if string(rxPayload) != "receive" || string(txPayload) != "transmit" {
		t.Fatalf("shared queue payloads = %q, %q", rxPayload, txPayload)
	}
}

func TestZeroPayloadSocketCreationUsesMetadataOnlyQuota(t *testing.T) {
	config := Config{MaxSockets: 1, ReceiveDatagrams: 1, TransmitDatagrams: 1}
	_, adapter, account := newTestAdapterWithConfig(t, 34, config)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.34"), Port: 4034}
	socket := bindTestSocket(t, adapter, local)
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, UDPResources: 1}) {
		t.Fatalf("metadata-only socket quota = %+v, closed=%v", usage, closed)
	}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.35"), Port: 53}
	if progress, err := socket.TrySend(nil, remote); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("empty datagram send = %v, %v", progress, err)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("metadata-only socket close retained quota = %+v", usage)
	}
}

func TestValidConfigRejectsCombinedQueueSizeOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, test := range []struct {
		name   string
		config Config
	}{
		{
			name: "zero-payload slot count",
			config: Config{
				MaxSockets: 1, ReceiveDatagrams: maxInt, TransmitDatagrams: 1,
			},
		},
		{
			name: "shared payload backing",
			config: Config{
				MaxSockets: 1, ReceiveBytes: maxInt - 1, TransmitBytes: maxInt - 1,
				ReceiveDatagrams: maxInt / 2, TransmitDatagrams: maxInt / 2, MaxPayloadBytes: 2,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if ValidConfig(test.config, ethernet.MaxMTU, nil, nil, false) {
				t.Fatalf("overflowing config accepted: %+v", test.config)
			}
		})
	}
}

func BenchmarkUDPDatagramQueueRoundTrip(b *testing.B) {
	queue := newDatagramQueue(8, 64, 512)
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 53}
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

func bindTestSocket(t testing.TB, adapter *Adapter, local nscore.Endpoint) udpns.Socket {
	t.Helper()
	resource, progress, err := adapter.TryBind(local)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("bind = %T, %v, %v", resource, progress, err)
	}
	return resource.(udpns.Socket)
}

func newTestAdapter(t testing.TB, id byte) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	return newTestAdapterWithConfig(t, id, Config{MaxSockets: 4, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32})
}

func newTestAdapterWithConfig(t testing.TB, id byte, config Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	return newTestAdapterWithConfigAndPolicy(t, id, config, policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
}

func newTestAdapterWithConfigAndPolicy(t testing.TB, id byte, config Config, policyConfig policy.Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	compiled, err := policy.Compile(policyConfig)
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 4, UDPResources: 4, QueuedBytes: 512})
	mtu := uint16(ethernet.MaxMTU)
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "udp", RandSeed: int64(id) + 1,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 3},
		IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), MTU: mtu,
		Link:   packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
		Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(common, config)
	if err != nil {
		_ = common.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = common.Close() })
	return common, adapter, account
}
