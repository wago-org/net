package tcp

import (
	"fmt"
	"net/netip"
	"testing"

	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
)

var (
	benchmarkProgress nscore.Progress
	benchmarkIO       nscore.IOResult
	benchmarkReady    nscore.Readiness
	benchmarkErr      error
	benchmarkInt      int
	benchmarkHandled  bool
)

func BenchmarkAdapterNew(b *testing.B) {
	config := Config{MaxListeners: 1, MaxOutboundStreams: 8, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4}
	b.ReportAllocs()
	for b.Loop() {
		common := newConfigTestCore(b, config.MaxListeners+config.MaxOutboundStreams)
		adapter, err := New(common, config)
		if err != nil {
			common.Close()
			b.Fatal(err)
		}
		if err := common.Close(); err != nil {
			b.Fatal(err)
		}
		if adapter == nil {
			b.Fatal("nil adapter")
		}
	}
}

func BenchmarkAdapterTryListenClose(b *testing.B) {
	_, adapter := newTestAdapter(b, 111, 1, 0)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.111"), Port: 4211}
	b.ReportAllocs()
	for b.Loop() {
		value, progress, err := adapter.TryListen(local)
		if err != nil || progress != nscore.ProgressDone {
			b.Fatalf("listen = %T, %v, %v", value, progress, err)
		}
		if err := value.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdapterTryConnectClose(b *testing.B) {
	_, adapter := newTestAdapter(b, 112, 0, 1)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.113"), Port: 4212}
	b.ReportAllocs()
	for b.Loop() {
		value, progress, err := adapter.TryConnect(remote)
		if err != nil || progress != nscore.ProgressInProgress {
			b.Fatalf("connect = %T, %v, %v", value, progress, err)
		}
		if err := value.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOutboundStreamCountScaling(b *testing.B) {
	for _, count := range []int{1, 16, 256} {
		b.Run(fmt.Sprintf("streams=%d", count), func(b *testing.B) {
			adapter := &Adapter{outboundStreams: count, streams: make([]*tcpStream, count)}
			for i := range adapter.streams {
				adapter.streams[i] = &tcpStream{outbound: true}
			}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkInt = adapter.outboundTCPStreamsLocked()
			}
		})
	}
}

func BenchmarkIngressOwnedIPv4SYN(b *testing.B) {
	clientCore, client := newTestAdapter(b, 114, 0, 1)
	serverCore, server := newTestAdapter(b, 115, 1, 0)
	setGateways(clientCore, [6]byte{0x02, 0, 0, 0, 0, 115})
	setGateways(serverCore, [6]byte{0x02, 0, 0, 0, 0, 114})
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.115"), Port: 4215}
	if _, progress, err := server.TryListen(endpoint); err != nil || progress != nscore.ProgressDone {
		b.Fatalf("listen = %v, %v", progress, err)
	}
	if _, progress, err := client.TryConnect(endpoint); err != nil || progress != nscore.ProgressInProgress {
		b.Fatalf("connect = %v, %v", progress, err)
	}
	frame := nextTCPFrame(b, clientCore)
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		serverCore.Lock()
		benchmarkHandled, benchmarkErr = server.ingressLocked(frame)
		serverCore.Unlock()
		if benchmarkErr != nil || benchmarkHandled {
			b.Fatalf("ingress = %v, %v", benchmarkHandled, benchmarkErr)
		}
	}
}

func BenchmarkTCPStreamFinishConnect(b *testing.B) {
	_, _, client, _, _ := newEstablishedPair(b)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkProgress, benchmarkErr = client.TryFinishConnect()
		if benchmarkErr != nil || benchmarkProgress != nscore.ProgressDone {
			b.Fatalf("finish = %v, %v", benchmarkProgress, benchmarkErr)
		}
	}
}

func BenchmarkTCPStreamReadiness(b *testing.B) {
	_, _, client, _, _ := newEstablishedPair(b)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkReady = client.Readiness()
	}
}

func BenchmarkTCPListenerTryAcceptWouldBlock(b *testing.B) {
	_, listener, _, _, _ := newEstablishedPair(b)
	b.ReportAllocs()
	for b.Loop() {
		value, progress, err := listener.TryAccept()
		if err != nil || progress != nscore.ProgressWouldBlock || value != nil {
			b.Fatalf("accept = %T, %v, %v", value, progress, err)
		}
	}
}

func BenchmarkTCPStreamRoundTrip(b *testing.B) {
	clientCore, _, client, serverCore, server := newEstablishedPair(b)
	payload := make([]byte, 64)
	dst := make([]byte, 64)
	frame := make([]byte, clientCore.Link().MaxFrameBytes())
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(len(frame)), Operations: 1}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		benchmarkIO, benchmarkErr = client.TryWrite(payload)
		if benchmarkErr != nil || benchmarkIO.Bytes != len(payload) {
			b.Fatalf("write = %+v, %v", benchmarkIO, benchmarkErr)
		}
		benchmarkTransfer(b, clientCore, serverCore, frame, budget)
		benchmarkIO, benchmarkErr = server.TryRead(dst)
		if benchmarkErr != nil || benchmarkIO.Bytes != len(dst) {
			b.Fatalf("read = %+v, %v", benchmarkIO, benchmarkErr)
		}
		benchmarkTransfer(b, serverCore, clientCore, frame, budget)
	}
}

func newEstablishedPair(t testing.TB) (clientCore *lnetocore.Namespace, listener *tcpListener, client *tcpStream, serverCore *lnetocore.Namespace, server *tcpStream) {
	t.Helper()
	clientCore, clientAdapter := newTestAdapter(t, 121, 0, 2)
	serverCore, serverAdapter := newTestAdapter(t, 122, 1, 0)
	setGateways(clientCore, [6]byte{0x02, 0, 0, 0, 0, 122})
	setGateways(serverCore, [6]byte{0x02, 0, 0, 0, 0, 121})
	serverEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.122"), Port: 4222}
	listenerValue, progress, err := serverAdapter.TryListen(serverEndpoint)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
	}
	clientValue, progress, err := clientAdapter.TryConnect(serverEndpoint)
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", clientValue, progress, err)
	}
	transferTCP(t, clientCore, serverCore)
	transferTCP(t, serverCore, clientCore)
	transferTCP(t, clientCore, serverCore)
	client = clientValue.(*tcpStream)
	if progress, err := client.TryFinishConnect(); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("finish = %v, %v", progress, err)
	}
	listener = listenerValue.(*tcpListener)
	serverValue, progress, err := listener.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("accept = %T, %v, %v", serverValue, progress, err)
	}
	server = serverValue.(*tcpStream)
	return clientCore, listener, client, serverCore, server
}

func benchmarkTransfer(b *testing.B, from, to *lnetocore.Namespace, frame []byte, budget nscore.ServiceBudget) {
	b.Helper()
	from.Lock()
	from.SetNextIngressLocked(false)
	from.Unlock()
	report, progress, err := from.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		b.Fatalf("egress = %+v, %v, %v", report, progress, err)
	}
	result, err := from.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready {
		b.Fatalf("dequeue = %+v, %v", result, err)
	}
	if err := to.Link().TryEnqueue(packetlink.Ingress, frame[:result.FrameBytes]); err != nil {
		b.Fatal(err)
	}
	to.Lock()
	to.SetNextIngressLocked(true)
	to.Unlock()
	report, progress, err = to.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		b.Fatalf("ingress = %+v, %v, %v", report, progress, err)
	}
}
