package udp

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/packetlink"
)

var (
	benchmarkProgress nscore.Progress
	benchmarkDatagram udpns.DatagramResult
	benchmarkReady    nscore.Readiness
	benchmarkErr      error
)

func BenchmarkAdapterTryBindClose(b *testing.B) {
	_, adapter, _ := newTestAdapter(b, 91)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.91"), Port: 4091}
	b.ReportAllocs()
	for b.Loop() {
		value, progress, err := adapter.TryBind(local)
		if err != nil || progress != nscore.ProgressDone {
			b.Fatalf("bind = %T, %v, %v", value, progress, err)
		}
		if err := value.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPSocketSendEgress(b *testing.B) {
	common, adapter, _ := newTestAdapter(b, 92)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.92"), Port: 4092}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.93"), Port: 4093}
	socket := bindTestSocket(b, adapter, local)
	payload := make([]byte, 32)
	frame := make([]byte, common.Link().MaxFrameBytes())
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(len(frame)), Operations: 1}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		benchmarkProgress, benchmarkErr = socket.TrySend(payload, remote)
		if benchmarkErr != nil || benchmarkProgress != nscore.ProgressDone {
			b.Fatalf("send = %v, %v", benchmarkProgress, benchmarkErr)
		}
		common.Lock()
		common.SetNextIngressLocked(false)
		common.Unlock()
		report, progress, err := common.TryService(budget)
		if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
			b.Fatalf("service = %+v, %v, %v", report, progress, err)
		}
		result, err := common.Link().TryDequeue(packetlink.Egress, frame)
		if err != nil || !result.Ready {
			b.Fatalf("dequeue = %+v, %v", result, err)
		}
	}
}

func BenchmarkUDPSocketReceive(b *testing.B) {
	common, adapter, _ := newTestAdapter(b, 93)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.93"), Port: 4093}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.92"), Port: 4092}
	socket := bindTestSocket(b, adapter, local).(*udpSocket)
	payload := make([]byte, 32)
	dst := make([]byte, 32)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		common.Lock()
		ok := socket.rx.push(payload, remote)
		common.Unlock()
		if !ok {
			b.Fatal("queue push")
		}
		benchmarkDatagram, benchmarkErr = socket.TryReceive(dst)
		if benchmarkErr != nil || !benchmarkDatagram.Ready {
			b.Fatalf("receive = %+v, %v", benchmarkDatagram, benchmarkErr)
		}
	}
}

func BenchmarkUDPSocketReadiness(b *testing.B) {
	_, adapter, _ := newTestAdapter(b, 94)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.94"), Port: 4094}
	socket := bindTestSocket(b, adapter, local)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkReady = socket.Readiness()
	}
}
