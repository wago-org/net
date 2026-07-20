package tls

import (
	"errors"
	"net/netip"
	"testing"

	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct {
	stream  nscore.Resource
	profile uint32
	name    string
}

func (*fakeNamespace) Close() error                { return nil }
func (*fakeNamespace) Readiness() nscore.Readiness { return 0 }
func (*fakeNamespace) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}
func (namespace *fakeNamespace) TryConnectTLS(_ nscore.Endpoint, profile uint32, name string) (nscore.Resource, nscore.Progress, error) {
	namespace.profile, namespace.name = profile, name
	return namespace.stream, nscore.ProgressInProgress, nil
}

type fakeStream struct {
	local, remote nscore.Endpoint
	input         []byte
	written       []byte
	closed        int
	info          tlsns.ConnectionInfo
}

func (stream *fakeStream) Close() error { stream.closed++; return nil }
func (*fakeStream) Readiness() nscore.Readiness {
	return nscore.ReadyConnected | nscore.ReadyReadable | nscore.ReadyWritable
}
func (stream *fakeStream) LocalEndpoint() nscore.Endpoint      { return stream.local }
func (stream *fakeStream) RemoteEndpoint() nscore.Endpoint     { return stream.remote }
func (*fakeStream) TryFinishConnect() (nscore.Progress, error) { return nscore.ProgressDone, nil }
func (stream *fakeStream) TryRead(dst []byte) (nscore.IOResult, error) {
	if len(stream.input) == 0 {
		return nscore.IOResult{State: nscore.IOWouldBlock}, nil
	}
	count := copy(dst, stream.input)
	stream.input = stream.input[count:]
	return nscore.IOResult{Bytes: count, State: nscore.IOReady}, nil
}
func (stream *fakeStream) TryWrite(src []byte) (nscore.IOResult, error) {
	count := min(3, len(src))
	stream.written = append(stream.written, src[:count]...)
	return nscore.IOResult{Bytes: count, State: nscore.IOReady}, nil
}
func (*fakeStream) TryShutdownWrite() (nscore.Progress, error)          { return nscore.ProgressDone, nil }
func (stream *fakeStream) ConnectionInfo() (tlsns.ConnectionInfo, bool) { return stream.info, true }

func TestTLSOperationsKeepHandlesKindSpecificAndPartial(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 49152}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	info := tlsns.ConnectionInfo{LocalEndpoint: local, RemoteEndpoint: remote, TLSVersion: 0x304, CipherSuite: 0x1301, NegotiatedALPN: "h2", Role: tlsns.RoleClient, PeerAuthenticated: true, PeerLeafSPKI256: [32]byte{1}, VerifiedIdentity: tlsns.IdentityDNS}
	stream := &fakeStream{local: local, remote: remote, input: []byte("reply"), info: info}
	namespace := &fakeNamespace{stream: stream}
	state, manager, instance := attachState(t, namespace)
	defer manager.Detach(instance)
	handle, progress, err := Connect(state, state.NamespaceHandle(), remote, 7, "api.example.com")
	if err != nil || progress != nscore.ProgressInProgress || handle == 0 {
		t.Fatalf("Connect = %v, %v, %v", handle, progress, err)
	}
	if namespace.profile != 7 || namespace.name != "api.example.com" {
		t.Fatalf("selection = %d %q", namespace.profile, namespace.name)
	}
	if progress, err := FinishConnect(state, handle); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("Finish = %v, %v", progress, err)
	}
	buffer := make([]byte, 3)
	if result, err := Read(state, handle, buffer); err != nil || result.Bytes != 3 || string(buffer) != "rep" {
		t.Fatalf("Read = %+v %q %v", result, buffer, err)
	}
	if result, err := Write(state, handle, []byte("abcdef")); err != nil || result.Bytes != 3 || string(stream.written) != "abc" {
		t.Fatalf("Write = %+v %q %v", result, stream.written, err)
	}
	if got, progress, err := ConnectionInfo(state, handle); err != nil || progress != nscore.ProgressDone || got.NegotiatedALPN != "h2" {
		t.Fatalf("Info = %+v %v %v", got, progress, err)
	}
	if err := state.CloseHandle(handle, resource.KindTLSStream); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(state, handle, buffer); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale read = %v", err)
	}
	if stream.closed != 1 {
		t.Fatalf("close count = %d", stream.closed)
	}
}

func TestTLSHandleIsCrossInstanceAndWrongKindSafe(t *testing.T) {
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	firstStream := &fakeStream{local: endpoint, remote: endpoint, info: tlsns.ConnectionInfo{LocalEndpoint: endpoint, RemoteEndpoint: endpoint, TLSVersion: 0x304, CipherSuite: 0x1301, Role: tlsns.RoleClient, PeerAuthenticated: true, PeerLeafSPKI256: [32]byte{1}, VerifiedIdentity: tlsns.IdentityIP}}
	first, firstManager, firstInstance := attachState(t, &fakeNamespace{stream: firstStream})
	defer firstManager.Detach(firstInstance)
	handle, _, err := Connect(first, first.NamespaceHandle(), endpoint, 1, "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	second, secondManager, secondInstance := attachState(t, &fakeNamespace{stream: &fakeStream{local: endpoint, remote: endpoint}})
	defer secondManager.Detach(secondInstance)
	if _, err := Read(second, handle, make([]byte, 1)); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("cross-instance = %v", err)
	}
	wrong, err := first.Resources().Add(resource.KindTCPStream, firstStream)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(first, wrong, make([]byte, 1)); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind = %v", err)
	}
}

func attachState(t testing.TB, backend nscore.Namespace) (*core.State, *core.Manager, *wago.Instance) {
	t.Helper()
	config := core.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: 8}
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return backend, nil }
	manager, err := core.NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("state not attached")
	}
	return state, manager, instance
}
