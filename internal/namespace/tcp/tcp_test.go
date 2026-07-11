package tcp

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

var (
	_ Namespace = (*fakeNamespace)(nil)
	_ Listener  = (*fakeListener)(nil)
	_ Stream    = (*fakeStream)(nil)
)

type fakeNamespace struct {
	listener nscore.Resource
	stream   nscore.Resource
}

func (n *fakeNamespace) TryListenTCP(nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.listener, nscore.ProgressDone, nil
}
func (n *fakeNamespace) TryConnectTCP(nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.stream, nscore.ProgressInProgress, nil
}

type fakeListener struct{ stream nscore.Resource }

func (*fakeListener) Close() error                   { return nil }
func (*fakeListener) Readiness() nscore.Readiness    { return nscore.ReadyAccept }
func (*fakeListener) LocalEndpoint() nscore.Endpoint { return endpoint(80) }
func (l *fakeListener) TryAccept() (nscore.Resource, nscore.Progress, error) {
	if l.stream == nil {
		return nil, nscore.ProgressWouldBlock, nil
	}
	return l.stream, nscore.ProgressDone, nil
}

type fakeStream struct{}

func (*fakeStream) Close() error                               { return nil }
func (*fakeStream) Readiness() nscore.Readiness                { return nscore.ReadyConnected }
func (*fakeStream) LocalEndpoint() nscore.Endpoint             { return endpoint(1000) }
func (*fakeStream) RemoteEndpoint() nscore.Endpoint            { return endpoint(443) }
func (*fakeStream) TryFinishConnect() (nscore.Progress, error) { return nscore.ProgressDone, nil }
func (*fakeStream) TryRead(dst []byte) (nscore.IOResult, error) {
	return nscore.IOResult{Bytes: len(dst), State: nscore.IOReady}, nil
}
func (*fakeStream) TryWrite(src []byte) (nscore.IOResult, error) {
	return nscore.IOResult{Bytes: len(src), State: nscore.IOReady}, nil
}
func (*fakeStream) TryShutdownWrite() (nscore.Progress, error) { return nscore.ProgressDone, nil }

func TestNarrowTCPFacetUsesSharedResourceContract(t *testing.T) {
	stream := &fakeStream{}
	listener := &fakeListener{stream: stream}
	backend := &fakeNamespace{listener: listener, stream: stream}
	resource, progress, err := backend.TryListenTCP(endpoint(8080))
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("TryListenTCP = %v, %v", progress, err)
	}
	typed, ok := resource.(Listener)
	if !ok {
		t.Fatalf("listener resource type = %T", resource)
	}
	accepted, progress, err := typed.TryAccept()
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("TryAccept = %v, %v", progress, err)
	}
	if _, ok := accepted.(Stream); !ok {
		t.Fatalf("stream resource type = %T", accepted)
	}
}

func endpoint(port uint16) nscore.Endpoint {
	return nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: port}
}
