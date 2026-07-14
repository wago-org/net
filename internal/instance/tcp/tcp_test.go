package tcp

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fakeNamespace struct {
	listener tcpns.Listener
	stream   tcpns.Stream
}

func (*fakeNamespace) Close() error                { return nil }
func (*fakeNamespace) Readiness() nscore.Readiness { return nscore.ReadyWritable }
func (n *fakeNamespace) TryListenTCP(nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.listener, nscore.ProgressDone, nil
}
func (n *fakeNamespace) TryConnectTCP(nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.stream, nscore.ProgressInProgress, nil
}
func (*fakeNamespace) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeListener struct {
	closed   atomic.Int32
	local    nscore.Endpoint
	accepted tcpns.Stream
}

func (l *fakeListener) Close() error                   { l.closed.Add(1); return nil }
func (*fakeListener) Readiness() nscore.Readiness      { return nscore.ReadyAccept }
func (l *fakeListener) LocalEndpoint() nscore.Endpoint { return l.local }
func (l *fakeListener) TryAccept() (nscore.Resource, nscore.Progress, error) {
	if l.accepted == nil {
		return nil, nscore.ProgressWouldBlock, nil
	}
	stream := l.accepted
	l.accepted = nil
	return stream, nscore.ProgressDone, nil
}

type fakeStream struct {
	closed      atomic.Int32
	local       nscore.Endpoint
	remote      nscore.Endpoint
	input       []byte
	written     []byte
	scriptRead  bool
	readPayload []byte
	readResult  nscore.IOResult
	readFailure error
	readDstLen  int
}

func (s *fakeStream) Close() error { s.closed.Add(1); return nil }
func (*fakeStream) Readiness() nscore.Readiness {
	return nscore.ReadyConnected | nscore.ReadyReadable | nscore.ReadyWritable
}
func (s *fakeStream) LocalEndpoint() nscore.Endpoint           { return s.local }
func (s *fakeStream) RemoteEndpoint() nscore.Endpoint          { return s.remote }
func (*fakeStream) TryFinishConnect() (nscore.Progress, error) { return nscore.ProgressDone, nil }
func (s *fakeStream) TryRead(dst []byte) (nscore.IOResult, error) {
	if s.scriptRead {
		s.readDstLen = len(dst)
		copy(dst, s.readPayload)
		return s.readResult, s.readFailure
	}
	if len(s.input) == 0 {
		return nscore.IOResult{State: nscore.IOWouldBlock}, nil
	}
	n := copy(dst, s.input)
	s.input = s.input[n:]
	return nscore.IOResult{Bytes: n, State: nscore.IOReady}, nil
}
func (s *fakeStream) TryWrite(src []byte) (nscore.IOResult, error) {
	n := min(3, len(src))
	s.written = append(s.written, src[:n]...)
	return nscore.IOResult{Bytes: n, State: nscore.IOReady}, nil
}
func (*fakeStream) TryShutdownWrite() (nscore.Progress, error) { return nscore.ProgressDone, nil }

func TestOperationsPreserveReadinessPartialIOAndKindSafety(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 4301}
	outbound := &fakeStream{local: local, remote: remote, input: []byte("reply")}
	accepted := &fakeStream{local: local, remote: remote, input: []byte("hello")}
	listener := &fakeListener{local: local, accepted: accepted}
	state, manager, instance := attachState(t, &fakeNamespace{listener: listener, stream: outbound}, 4)
	defer manager.Detach(instance)

	listenerHandle, progress, err := Listen(state, state.NamespaceHandle(), local)
	if err != nil || progress != nscore.ProgressDone || listenerHandle == 0 {
		t.Fatalf("Listen = %v, %v, %v", listenerHandle, progress, err)
	}
	streamHandle, progress, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil || progress != nscore.ProgressInProgress || streamHandle == 0 {
		t.Fatalf("Connect = %v, %v, %v", streamHandle, progress, err)
	}
	if progress, err := FinishConnect(state, streamHandle); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("FinishConnect = %v, %v", progress, err)
	}
	acceptedHandle, progress, err := Accept(state, listenerHandle)
	if err != nil || progress != nscore.ProgressDone || acceptedHandle == 0 {
		t.Fatalf("Accept = %v, %v, %v", acceptedHandle, progress, err)
	}
	buffer := make([]byte, 3)
	if result, err := Read(state, acceptedHandle, buffer); err != nil || result.Bytes != 3 || string(buffer) != "hel" {
		t.Fatalf("Read = %+v %q, %v", result, buffer, err)
	}
	if result, err := Write(state, streamHandle, []byte("abcdef")); err != nil || result.Bytes != 3 || string(outbound.written) != "abc" {
		t.Fatalf("Write = %+v %q, %v", result, outbound.written, err)
	}
	if progress, err := ShutdownWrite(state, streamHandle); err != nil || progress != nscore.ProgressDone {
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

func TestReadCommitsOnlyValidatedReadyBytes(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4300}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 4301}
	stream := &fakeStream{local: local, remote: remote, scriptRead: true, readPayload: []byte("backend-write")}
	state, manager, instance := attachState(t, &fakeNamespace{stream: stream}, 2)
	defer manager.Detach(instance)
	handle, _, err := Connect(state, state.NamespaceHandle(), remote)
	if err != nil {
		t.Fatal(err)
	}

	backendFailure := nscore.Fail(nscore.FailureConnectionReset, errors.New("reset"))
	for _, test := range []struct {
		name   string
		result nscore.IOResult
		err    error
	}{
		{name: "error", result: nscore.IOResult{Bytes: 7, State: nscore.IOReady}, err: backendFailure},
		{name: "would block", result: nscore.IOResult{State: nscore.IOWouldBlock}},
		{name: "EOF", result: nscore.IOResult{State: nscore.IOEOF}},
		{name: "malformed", result: nscore.IOResult{Bytes: 33, State: nscore.IOReady}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dst := make([]byte, 32)
			for i := range dst {
				dst[i] = 0xa5
			}
			before := append([]byte(nil), dst...)
			stream.readResult, stream.readFailure = test.result, test.err
			result, err := Read(state, handle, dst)
			if test.err != nil {
				if result != (nscore.IOResult{}) || failureOf(t, err) != nscore.FailureConnectionReset || string(dst) != string(before) {
					t.Fatalf("Read = %+v, %v, dst=%x", result, err, dst)
				}
				return
			}
			if test.name == "malformed" {
				if result != (nscore.IOResult{}) || failureOf(t, err) != nscore.FailureIO || string(dst) != string(before) {
					t.Fatalf("Read = %+v, %v, dst=%x", result, err, dst)
				}
				return
			}
			if err != nil || result != test.result || string(dst) != string(before) {
				t.Fatalf("Read = %+v, %v, dst=%x", result, err, dst)
			}
		})
	}

	dst := make([]byte, 32)
	for i := range dst {
		dst[i] = 0xa5
	}
	stream.readPayload = []byte("validated-extra")
	stream.readResult, stream.readFailure = nscore.IOResult{Bytes: 9, State: nscore.IOReady}, nil
	result, err := Read(state, handle, dst)
	if err != nil || result != stream.readResult || string(dst[:9]) != "validated" {
		t.Fatalf("ready Read = %+v, %v, dst=%q", result, err, dst)
	}
	for i, value := range dst[9:] {
		if value != 0xa5 {
			t.Fatalf("ready tail[%d] = %x", i, value)
		}
	}

	const maxReadBytes = tcpns.MaxReadBytes
	large := make([]byte, maxReadBytes+17)
	for i := range large {
		large[i] = 0xa5
	}
	stream.readPayload = make([]byte, maxReadBytes+17)
	for i := range stream.readPayload {
		stream.readPayload[i] = 0x5a
	}
	stream.readResult = nscore.IOResult{Bytes: maxReadBytes, State: nscore.IOReady}
	result, err = Read(state, handle, large)
	if err != nil || result != stream.readResult || stream.readDstLen != maxReadBytes {
		t.Fatalf("bounded Read = %+v, %v, backend dst=%d", result, err, stream.readDstLen)
	}
	for i, value := range large[:maxReadBytes] {
		if value != 0x5a {
			t.Fatalf("bounded payload[%d] = %x", i, value)
		}
	}
	for i, value := range large[maxReadBytes:] {
		if value != 0xa5 {
			t.Fatalf("bounded tail[%d] = %x", i, value)
		}
	}
}

func TestTypedNilBackendResourcesFailClosed(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4302}
	var nilListener *fakeListener
	var nilStream *fakeStream
	backend := &fakeNamespace{listener: nilListener, stream: nilStream}
	state, manager, instance := attachState(t, backend, 4)
	defer manager.Detach(instance)

	if handle, progress, err := Listen(state, state.NamespaceHandle(), local); handle != 0 || progress != 0 || !errors.Is(err, core.ErrInvalidBackendResult) {
		t.Fatalf("typed nil Listen = %v, %v, %v", handle, progress, err)
	}
	if handle, progress, err := Connect(state, state.NamespaceHandle(), local); handle != 0 || progress != 0 || !errors.Is(err, core.ErrInvalidBackendResult) {
		t.Fatalf("typed nil Connect = %v, %v, %v", handle, progress, err)
	}

	listener := &fakeListener{local: local, accepted: nilStream}
	backend.listener = listener
	listenerHandle, progress, err := Listen(state, state.NamespaceHandle(), local)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("setup Listen = %v, %v", progress, err)
	}
	if handle, progress, err := Accept(state, listenerHandle); handle != 0 || progress != 0 || !errors.Is(err, core.ErrInvalidBackendResult) {
		t.Fatalf("typed nil Accept = %v, %v, %v", handle, progress, err)
	}
}

func TestRegistrationRollbackAndCloseRace(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4302}
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

func failureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}

func attachState(t testing.TB, backend nscore.Namespace, maxRegistrations int) (*core.State, *core.Manager, *wago.Instance) {
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
