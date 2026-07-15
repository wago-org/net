package udp

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	core "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct {
	socket   nscore.Resource
	progress namespace.Progress
	failure  error
}

func (*fakeNamespace) Close() error                   { return nil }
func (*fakeNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (n *fakeNamespace) TryBindUDP(namespace.Endpoint) (nscore.Resource, namespace.Progress, error) {
	if n.progress != 0 || n.failure != nil {
		return n.socket, n.progress, n.failure
	}
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
	closed       atomic.Int32
	local        namespace.Endpoint
	result       namespace.DatagramResult
	payload      []byte
	failure      error
	receiveSize  int
	sendProgress namespace.Progress
	sendFailure  error
}

func (s *fakeSocket) Close() error { s.closed.Add(1); return nil }
func (*fakeSocket) Readiness() namespace.Readiness {
	return namespace.ReadyReadable | namespace.ReadyWritable
}
func (s *fakeSocket) LocalEndpoint() namespace.Endpoint { return s.local }
func (s *fakeSocket) TryReceive(dst []byte) (namespace.DatagramResult, error) {
	s.receiveSize = len(dst)
	copy(dst, s.payload)
	return s.result, s.failure
}
func (s *fakeSocket) TrySend([]byte, namespace.Endpoint) (namespace.Progress, error) {
	if s.sendProgress != 0 || s.sendFailure != nil {
		return s.sendProgress, s.sendFailure
	}
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

func TestBindRejectsMalformedSuccessfulResources(t *testing.T) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4200}
	var typedNil *fakeSocket
	for _, test := range []struct {
		name     string
		resource nscore.Resource
		progress namespace.Progress
	}{
		{name: "wrong type", resource: new(fakeResource), progress: namespace.ProgressDone},
		{name: "invalid progress", resource: new(fakeSocket), progress: 99},
		{name: "dirty would block", resource: new(fakeSocket), progress: namespace.ProgressWouldBlock},
		{name: "typed nil", resource: typedNil, progress: namespace.ProgressDone},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &fakeNamespace{socket: test.resource, progress: test.progress}
			state, manager, instance := attachState(t, backend, 4)
			defer manager.Detach(instance)
			resourcesBefore := state.Resources().Len()
			readinessBefore := state.Readiness().Snapshot()
			if handle, progress, err := Bind(state, state.NamespaceHandle(), local); handle != 0 || progress != 0 || failureOf(t, err) != namespace.FailureIO {
				t.Fatalf("Bind = %v, %v, %v", handle, progress, err)
			}
			if state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
				t.Fatalf("malformed bind published state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
			}
			switch value := test.resource.(type) {
			case *fakeResource:
				if value.closed.Load() != 1 {
					t.Fatalf("wrong resource closes = %d", value.closed.Load())
				}
			case *fakeSocket:
				if value != nil && value.closed.Load() != 1 {
					t.Fatalf("socket closes = %d", value.closed.Load())
				}
			}
		})
	}
}

type fakeResource struct{ closed atomic.Int32 }

func (r *fakeResource) Close() error { r.closed.Add(1); return nil }
func (*fakeResource) Readiness() namespace.Readiness {
	return namespace.ReadyWritable
}

func TestBindAndSendErrorsCloseResourcesAndCanonicalizeProgress(t *testing.T) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4200}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 53}
	backend := &fakeNamespace{}
	state, manager, instance := attachState(t, backend, 4)
	defer manager.Detach(instance)
	resourcesBefore := state.Resources().Len()
	readinessBefore := state.Readiness().Snapshot()
	failure := namespace.Fail(namespace.FailureTemporary, errors.New("backend failed"))

	socket := &fakeSocket{}
	backend.socket, backend.progress, backend.failure = socket, namespace.ProgressDone, failure
	if handle, progress, err := Bind(state, state.NamespaceHandle(), local); handle != 0 || progress != 0 || failureOf(t, err) != namespace.FailureTemporary {
		t.Fatalf("failed bind = %v, %v, %v", handle, progress, err)
	}
	if socket.closed.Load() != 1 || state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("failed bind published state: closes=%d resources=%d readiness=%+v", socket.closed.Load(), state.Resources().Len(), state.Readiness().Snapshot())
	}

	var typedNil *fakeSocket
	backend.socket = typedNil
	if handle, progress, err := Bind(state, state.NamespaceHandle(), local); handle != 0 || progress != 0 || failureOf(t, err) != namespace.FailureTemporary {
		t.Fatalf("typed-nil failed bind = %v, %v, %v", handle, progress, err)
	}
	if state.Resources().Len() != resourcesBefore || state.Readiness().Snapshot() != readinessBefore {
		t.Fatalf("typed-nil failed bind published state: resources=%d readiness=%+v", state.Resources().Len(), state.Readiness().Snapshot())
	}

	backend.socket, backend.progress, backend.failure = nil, namespace.ProgressWouldBlock, nil
	if handle, progress, err := Bind(state, state.NamespaceHandle(), local); err != nil || handle != 0 || progress != namespace.ProgressWouldBlock {
		t.Fatalf("would-block bind = %v, %v, %v", handle, progress, err)
	}

	socket = &fakeSocket{sendProgress: namespace.ProgressDone, sendFailure: failure}
	handle, err := state.Resources().Add(resource.KindUDPSocket, socket)
	if err != nil {
		t.Fatal(err)
	}
	if progress, err := Send(state, handle, nil, remote); progress != 0 || failureOf(t, err) != namespace.FailureTemporary {
		t.Fatalf("failed send = %v, %v", progress, err)
	}
	socket.sendProgress, socket.sendFailure = namespace.ProgressWouldBlock, nil
	if progress, err := Send(state, handle, nil, remote); err != nil || progress != namespace.ProgressWouldBlock {
		t.Fatalf("would-block send = %v, %v", progress, err)
	}
	socket.sendProgress = 99
	if progress, err := Send(state, handle, nil, remote); progress != 0 || failureOf(t, err) != namespace.FailureIO {
		t.Fatalf("malformed send = %v, %v", progress, err)
	}
}

func TestReceiveCommitsOnlyValidReadyPayloads(t *testing.T) {
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4200}
	remote := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 53}
	socket := &fakeSocket{local: local, payload: []byte("reply")}
	state, manager, instance := attachState(t, &fakeNamespace{socket: socket}, 2)
	defer manager.Detach(instance)
	handle, _, err := Bind(state, state.NamespaceHandle(), local)
	if err != nil {
		t.Fatal(err)
	}

	dst := []byte{0xa5, 0xa5, 0xa5, 0xa5, 0xa5}
	wantUnchanged := append([]byte(nil), dst...)
	socket.result = namespace.DatagramResult{Ready: true, Copied: 5, DatagramBytes: 5, Source: remote}
	socket.failure = namespace.Fail(namespace.FailureTemporary, errors.New("receive"))
	if result, err := Receive(state, handle, dst); failureOf(t, err) != namespace.FailureTemporary || result != (namespace.DatagramResult{}) || string(dst) != string(wantUnchanged) {
		t.Fatalf("failed receive = %+v, %v, dst=%x", result, err, dst)
	}

	socket.failure = nil
	socket.result = namespace.DatagramResult{}
	if result, err := Receive(state, handle, dst); err != nil || result != (namespace.DatagramResult{}) || string(dst) != string(wantUnchanged) {
		t.Fatalf("would-block receive = %+v, %v, dst=%x", result, err, dst)
	}

	for name, malformed := range map[string]namespace.DatagramResult{
		"copied beyond buffer":   {Ready: true, Copied: len(dst) + 1, DatagramBytes: len(dst) + 1, Source: remote},
		"copied beyond datagram": {Ready: true, Copied: 4, DatagramBytes: 3, Source: remote},
		"negative copied":        {Ready: true, Copied: -1, DatagramBytes: 1, Source: remote},
		"negative datagram":      {Ready: true, DatagramBytes: -1, Source: remote},
		"oversize datagram":      {Ready: true, DatagramBytes: udpns.MaxDatagramPayloadBytes + 1, Source: remote, Truncated: true},
		"missing truncation":     {Ready: true, Copied: 3, DatagramBytes: 4, Source: remote},
		"spurious truncation":    {Ready: true, Copied: 3, DatagramBytes: 3, Source: remote, Truncated: true},
		"ready without source":   {Ready: true},
		"blocked with copied":    {Copied: 1},
		"blocked with size":      {DatagramBytes: 1},
		"blocked with source":    {Source: remote},
		"blocked truncated":      {Truncated: true},
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			before := append([]byte(nil), dst...)
			socket.result = malformed
			if result, err := Receive(state, handle, dst); failureOf(t, err) != namespace.FailureIO || result != (namespace.DatagramResult{}) || string(dst) != string(before) {
				t.Fatalf("receive = %+v, %v, dst=%x", result, err, dst)
			}
		})
	}

	socket.result = namespace.DatagramResult{Ready: true, Copied: 3, DatagramBytes: 3, Source: remote}
	if result, err := Receive(state, handle, dst); err != nil || !result.Ready || string(dst) != "rep\xa5\xa5" {
		t.Fatalf("ready receive = %+v, %v, dst=%x", result, err, dst)
	}

	largeDst := make([]byte, udpns.MaxDatagramPayloadBytes+32)
	for i := range largeDst[:5] {
		largeDst[i] = 0xa5
	}
	socket.result = namespace.DatagramResult{}
	if result, err := Receive(state, handle, largeDst); err != nil || result.Ready || socket.receiveSize != udpns.MaxDatagramPayloadBytes || string(largeDst[:5]) != "\xa5\xa5\xa5\xa5\xa5" {
		t.Fatalf("bounded receive = %+v, %v, size=%d dst=%x", result, err, socket.receiveSize, largeDst[:5])
	}
}

func failureOf(t testing.TB, err error) namespace.Failure {
	t.Helper()
	failure, ok := namespace.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
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
