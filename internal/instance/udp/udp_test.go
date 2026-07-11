package udp

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	core "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct{ socket namespace.UDPSocket }

func (*fakeNamespace) Close() error                   { return nil }
func (*fakeNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (n *fakeNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return n.socket, namespace.ProgressDone, nil
}
func (*fakeNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*fakeNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*fakeNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*fakeNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type fakeSocket struct {
	closed atomic.Int32
	local  namespace.Endpoint
	result namespace.DatagramResult
}

func (s *fakeSocket) Close() error { s.closed.Add(1); return nil }
func (*fakeSocket) Readiness() namespace.Readiness {
	return namespace.ReadyReadable | namespace.ReadyWritable
}
func (s *fakeSocket) LocalEndpoint() namespace.Endpoint                   { return s.local }
func (s *fakeSocket) TryReceive([]byte) (namespace.DatagramResult, error) { return s.result, nil }
func (*fakeSocket) TrySend([]byte, namespace.Endpoint) (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}

func TestOperationsAndRegistrationRollback(t *testing.T) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4200}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 53}
	socket := &fakeSocket{local: local, result: namespace.DatagramResult{Ready: true, Copied: 2, DatagramBytes: 2, Source: remote}}
	state, manager, instance := attachState(t, &fakeNamespace{socket: socket}, 2)
	defer manager.Detach(instance)

	handle, progress, err := Bind(state, state.NamespaceHandle(), local)
	if err != nil || progress != namespace.ProgressDone || handle == 0 {
		t.Fatalf("Bind = %v, %v, %v", handle, progress, err)
	}
	if progress, err := Send(state, handle, []byte("ok"), remote); err != nil || progress != namespace.ProgressDone {
		t.Fatalf("Send = %v, %v", progress, err)
	}
	if result, err := Receive(state, handle, make([]byte, 2)); err != nil || !result.Ready || result.Copied != 2 || result.DatagramBytes != 2 {
		t.Fatalf("Receive = %+v, %v", result, err)
	}
	if _, err := Send(state, state.NamespaceHandle(), nil, remote); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind send = %v", err)
	}
	if err := state.CloseHandle(handle, resource.KindUDPSocket); err != nil || socket.closed.Load() != 1 {
		t.Fatalf("close = %v, count=%d", err, socket.closed.Load())
	}

	rollbackSocket := &fakeSocket{local: local}
	rollbackState, rollbackManager, rollbackInstance := attachState(t, &fakeNamespace{socket: rollbackSocket}, 1)
	defer rollbackManager.Detach(rollbackInstance)
	if handle, progress, err := Bind(rollbackState, rollbackState.NamespaceHandle(), local); handle != 0 || progress != 0 || !errors.Is(err, readiness.ErrLimit) {
		t.Fatalf("Bind rollback = %v, %v, %v", handle, progress, err)
	}
	if rollbackSocket.closed.Load() != 1 || rollbackState.Resources().Len() != 1 || rollbackState.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("rollback retained state: closes=%d resources=%d readiness=%+v", rollbackSocket.closed.Load(), rollbackState.Resources().Len(), rollbackState.Readiness().Snapshot())
	}
}

func attachState(t testing.TB, backend namespace.Namespace, maxRegistrations int) (*core.State, *core.Manager, *wago.Instance) {
	t.Helper()
	config := core.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: maxRegistrations}
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
