package tcp

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	core "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct {
	listener namespace.TCPListener
	stream   namespace.TCPStream
}

func (*fakeNamespace) Close() error                   { return nil }
func (*fakeNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (*fakeNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (n *fakeNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	return n.listener, namespace.ProgressDone, nil
}
func (n *fakeNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	return n.stream, namespace.ProgressInProgress, nil
}
func (*fakeNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, nil)
}
func (*fakeNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type fakeListener struct {
	closed   atomic.Int32
	local    namespace.Endpoint
	accepted namespace.TCPStream
}

func (l *fakeListener) Close() error                      { l.closed.Add(1); return nil }
func (*fakeListener) Readiness() namespace.Readiness      { return namespace.ReadyAccept }
func (l *fakeListener) LocalEndpoint() namespace.Endpoint { return l.local }
func (l *fakeListener) TryAccept() (namespace.TCPStream, namespace.Progress, error) {
	if l.accepted == nil {
		return nil, namespace.ProgressWouldBlock, nil
	}
	stream := l.accepted
	l.accepted = nil
	return stream, namespace.ProgressDone, nil
}

type fakeStream struct {
	closed  atomic.Int32
	local   namespace.Endpoint
	remote  namespace.Endpoint
	input   []byte
	written []byte
}

func (s *fakeStream) Close() error { s.closed.Add(1); return nil }
func (*fakeStream) Readiness() namespace.Readiness {
	return namespace.ReadyConnected | namespace.ReadyReadable | namespace.ReadyWritable
}
func (s *fakeStream) LocalEndpoint() namespace.Endpoint           { return s.local }
func (s *fakeStream) RemoteEndpoint() namespace.Endpoint          { return s.remote }
func (*fakeStream) TryFinishConnect() (namespace.Progress, error) { return namespace.ProgressDone, nil }
func (s *fakeStream) TryRead(dst []byte) (namespace.IOResult, error) {
	if len(s.input) == 0 {
		return namespace.IOResult{State: namespace.IOWouldBlock}, nil
	}
	n := copy(dst, s.input)
	s.input = s.input[n:]
	return namespace.IOResult{Bytes: n, State: namespace.IOReady}, nil
}
func (s *fakeStream) TryWrite(src []byte) (namespace.IOResult, error) {
	n := min(3, len(src))
	s.written = append(s.written, src[:n]...)
	return namespace.IOResult{Bytes: n, State: namespace.IOReady}, nil
}
func (*fakeStream) TryShutdownWrite() (namespace.Progress, error) { return namespace.ProgressDone, nil }

func TestOperationsPreserveReadinessPartialIOAndKindSafety(t *testing.T) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 4301}
	outbound := &fakeStream{local: local, remote: remote, input: []byte("reply")}
	accepted := &fakeStream{local: local, remote: remote, input: []byte("hello")}
	listener := &fakeListener{local: local, accepted: accepted}
	state, manager, instance := attachState(t, &fakeNamespace{listener: listener, stream: outbound}, 4)
	defer manager.Detach(instance)

	listenerHandle, progress, err := Listen(state, state.NamespaceHandle(), local)
	if err != nil || progress != namespace.ProgressDone || listenerHandle == 0 {
		t.Fatalf("Listen = %v, %v, %v", listenerHandle, progress, err)
	}
	streamHandle, progress, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil || progress != namespace.ProgressInProgress || streamHandle == 0 {
		t.Fatalf("Connect = %v, %v, %v", streamHandle, progress, err)
	}
	if progress, err := FinishConnect(state, streamHandle); err != nil || progress != namespace.ProgressDone {
		t.Fatalf("FinishConnect = %v, %v", progress, err)
	}
	acceptedHandle, progress, err := Accept(state, listenerHandle)
	if err != nil || progress != namespace.ProgressDone || acceptedHandle == 0 {
		t.Fatalf("Accept = %v, %v, %v", acceptedHandle, progress, err)
	}
	buffer := make([]byte, 3)
	if result, err := Read(state, acceptedHandle, buffer); err != nil || result.Bytes != 3 || string(buffer) != "hel" {
		t.Fatalf("Read = %+v %q, %v", result, buffer, err)
	}
	if result, err := Write(state, streamHandle, []byte("abcdef")); err != nil || result.Bytes != 3 || string(outbound.written) != "abc" {
		t.Fatalf("Write = %+v %q, %v", result, outbound.written, err)
	}
	if progress, err := ShutdownWrite(state, streamHandle); err != nil || progress != namespace.ProgressDone {
		t.Fatalf("ShutdownWrite = %v, %v", progress, err)
	}
	if _, _, err := Accept(state, streamHandle); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind accept = %v", err)
	}
	if _, err := Read(state, listenerHandle, buffer); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind read = %v", err)
	}
	if snapshot := state.Readiness().Snapshot(); snapshot.Registrations != 4 {
		t.Fatalf("readiness registrations = %+v", snapshot)
	}
}

func TestRegistrationRollbackAndCloseRace(t *testing.T) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4302}
	listener := &fakeListener{local: local}
	state, manager, instance := attachState(t, &fakeNamespace{listener: listener}, 1)
	if handle, progress, err := Listen(state, state.NamespaceHandle(), local); handle != 0 || progress != 0 || !errors.Is(err, readiness.ErrLimit) {
		t.Fatalf("Listen rollback = %v, %v, %v", handle, progress, err)
	}
	if listener.closed.Load() != 1 || state.Resources().Len() != 1 || state.Readiness().Snapshot().Registrations != 1 {
		t.Fatalf("rollback retained state: closes=%d resources=%d readiness=%+v", listener.closed.Load(), state.Resources().Len(), state.Readiness().Snapshot())
	}

	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				_, _, _ = Listen(state, state.NamespaceHandle(), local)
			}
		}()
	}
	if err := manager.Detach(instance); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
}

func attachState(t testing.TB, backend namespace.Namespace, maxRegistrations int) (*core.State, *core.Manager, *wago.Instance) {
	t.Helper()
	config := core.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.Readiness = readiness.Config{MaxRegistrations: maxRegistrations}
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (namespace.Namespace, error) { return backend, nil }
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
