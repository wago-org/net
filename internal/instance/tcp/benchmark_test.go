package tcp

import (
	"net/netip"
	"testing"

	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	"github.com/wago-org/net/internal/resource"
)

type benchmarkStream struct {
	local  nscore.Endpoint
	remote nscore.Endpoint
}

func (*benchmarkStream) Close() error { return nil }
func (*benchmarkStream) Readiness() nscore.Readiness {
	return nscore.ReadyConnected | nscore.ReadyReadable | nscore.ReadyWritable
}
func (s *benchmarkStream) LocalEndpoint() nscore.Endpoint           { return s.local }
func (s *benchmarkStream) RemoteEndpoint() nscore.Endpoint          { return s.remote }
func (*benchmarkStream) TryFinishConnect() (nscore.Progress, error) { return nscore.ProgressDone, nil }
func (*benchmarkStream) TryRead(dst []byte) (nscore.IOResult, error) {
	if len(dst) == 0 {
		return nscore.IOResult{State: nscore.IOReady}, nil
	}
	dst[0] = 1
	return nscore.IOResult{Bytes: len(dst), State: nscore.IOReady}, nil
}
func (*benchmarkStream) TryWrite(src []byte) (nscore.IOResult, error) {
	if len(src) == 0 {
		return nscore.IOResult{State: nscore.IOReady}, nil
	}
	return nscore.IOResult{Bytes: len(src), State: nscore.IOReady}, nil
}
func (*benchmarkStream) TryShutdownWrite() (nscore.Progress, error) { return nscore.ProgressDone, nil }

var (
	benchmarkHandle   resource.Handle
	benchmarkProgress nscore.Progress
	benchmarkIO       nscore.IOResult
	benchmarkEndpoint nscore.Endpoint
	benchmarkErr      error
)

func newBenchmarkTCPState(b testing.TB) (*instancecore.State, resource.Handle, func()) {
	b.Helper()
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	stream := &benchmarkStream{local: local, remote: remote}
	state, manager, instance := attachState(b, &fakeNamespace{stream: stream}, 2)
	handle, _, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil {
		b.Fatal(err)
	}
	return state, handle, func() { _ = manager.Detach(instance) }
}

func BenchmarkConnectClose(b *testing.B) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	stream := &benchmarkStream{local: local, remote: remote}
	state, manager, instance := attachState(b, &fakeNamespace{stream: stream}, 2)
	defer manager.Detach(instance)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHandle, benchmarkProgress, benchmarkErr = Connect(state, state.NamespaceHandle(), remote)
		if benchmarkErr != nil || benchmarkProgress != nscore.ProgressInProgress {
			b.Fatalf("connect = %v, %v, %v", benchmarkHandle, benchmarkProgress, benchmarkErr)
		}
		if err := state.CloseHandle(benchmarkHandle, resource.KindTCPStream); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEndpoints(b *testing.B) {
	state, handle, cleanup := newBenchmarkTCPState(b)
	defer cleanup()
	b.ReportAllocs()
	for b.Loop() {
		var local nscore.Endpoint
		local, benchmarkEndpoint, benchmarkErr = Endpoints(state, handle)
		if benchmarkErr != nil || !local.Valid() || !benchmarkEndpoint.Valid() {
			b.Fatalf("endpoints = %+v, %+v, %v", local, benchmarkEndpoint, benchmarkErr)
		}
	}
}

func BenchmarkFinishConnect(b *testing.B) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	stream := &benchmarkStream{local: local, remote: remote}
	state, manager, instance := attachState(b, &fakeNamespace{stream: stream}, 2)
	defer manager.Detach(instance)
	handle, _, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkProgress, benchmarkErr = FinishConnect(state, handle)
	}
}

func BenchmarkRead(b *testing.B) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	stream := &benchmarkStream{local: local, remote: remote}
	state, manager, instance := attachState(b, &fakeNamespace{stream: stream}, 2)
	defer manager.Detach(instance)
	handle, _, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkIO, benchmarkErr = Read(state, handle, dst)
		if benchmarkErr != nil || benchmarkIO.Bytes != len(dst) {
			b.Fatalf("read = %+v, %v", benchmarkIO, benchmarkErr)
		}
	}
}

func BenchmarkWrite(b *testing.B) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	stream := &benchmarkStream{local: local, remote: remote}
	state, manager, instance := attachState(b, &fakeNamespace{stream: stream}, 2)
	defer manager.Detach(instance)
	handle, _, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil {
		b.Fatal(err)
	}
	src := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkIO, benchmarkErr = Write(state, handle, src)
		if benchmarkErr != nil || benchmarkIO.Bytes != len(src) {
			b.Fatalf("write = %+v, %v", benchmarkIO, benchmarkErr)
		}
	}
}

func BenchmarkShutdownWrite(b *testing.B) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	stream := &benchmarkStream{local: local, remote: remote}
	state, manager, instance := attachState(b, &fakeNamespace{stream: stream}, 2)
	defer manager.Detach(instance)
	handle, _, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkProgress, benchmarkErr = ShutdownWrite(state, handle)
	}
}

var _ tcpns.Stream = (*benchmarkStream)(nil)
