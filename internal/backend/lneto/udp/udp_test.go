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
	a := bindTestSocket(t, aAdapter, aLocal)
	b := bindTestSocket(t, bAdapter, bLocal)
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
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
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
	adapter, err := New(common, Config{MaxSockets: 4, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32})
	if err != nil {
		_ = common.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = common.Close() })
	return common, adapter, account
}
