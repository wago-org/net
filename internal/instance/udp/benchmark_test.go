package udp

import (
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/resource"
)

var (
	benchmarkHandle   resource.Handle
	benchmarkProgress namespace.Progress
	benchmarkDatagram namespace.DatagramResult
	benchmarkErr      error
)

func BenchmarkBindClose(b *testing.B) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4200}
	socket := &fakeSocket{local: local}
	state, manager, instance := attachState(b, &fakeNamespace{socket: socket}, 2)
	defer manager.Detach(instance)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHandle, benchmarkProgress, benchmarkErr = Bind(state, state.NamespaceHandle(), local)
		if benchmarkErr != nil || benchmarkProgress != namespace.ProgressDone {
			b.Fatalf("bind = %v, %v, %v", benchmarkHandle, benchmarkProgress, benchmarkErr)
		}
		if err := state.CloseHandle(benchmarkHandle, resource.KindUDPSocket); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSend(b *testing.B) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4200}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 53}
	state, manager, instance := attachState(b, &fakeNamespace{socket: &fakeSocket{local: local}}, 2)
	defer manager.Detach(instance)
	handle, _, err := Bind(state, state.NamespaceHandle(), local)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkProgress, benchmarkErr = Send(state, handle, payload, remote)
		if benchmarkErr != nil || benchmarkProgress != namespace.ProgressDone {
			b.Fatalf("send = %v, %v", benchmarkProgress, benchmarkErr)
		}
	}
}

func BenchmarkReceive(b *testing.B) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4200}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 53}
	socket := &fakeSocket{local: local, result: namespace.DatagramResult{Ready: true, Copied: 1200, DatagramBytes: 1200, Source: remote}}
	state, manager, instance := attachState(b, &fakeNamespace{socket: socket}, 2)
	defer manager.Detach(instance)
	handle, _, err := Bind(state, state.NamespaceHandle(), local)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 1200)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkDatagram, benchmarkErr = Receive(state, handle, dst)
		if benchmarkErr != nil || !benchmarkDatagram.Ready {
			b.Fatalf("receive = %+v, %v", benchmarkDatagram, benchmarkErr)
		}
	}
}
