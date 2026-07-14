package tcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	tcpabi "github.com/wago-org/net/internal/abi/tcp"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type testHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h testHost) Memory() []byte           { return h.memory }
func (h testHost) Instance() *wago.Instance { return h.instance }

type fakeBase struct{}

func (*fakeBase) Close() error                { return nil }
func (*fakeBase) Readiness() nscore.Readiness { return 0 }
func (*fakeBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeNamespace struct {
	listener        nscore.Resource
	listenProgress  nscore.Progress
	listenFailure   error
	listenLocal     nscore.Endpoint
	listenCalls     int
	stream          nscore.Resource
	connectProgress nscore.Progress
	connectFailure  error
	connectRemote   nscore.Endpoint
	connectCalls    int
}

func (n *fakeNamespace) TryListenTCP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	n.listenCalls++
	n.listenLocal = local
	return n.listener, n.listenProgress, n.listenFailure
}
func (n *fakeNamespace) TryConnectTCP(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	n.connectCalls++
	n.connectRemote = remote
	return n.stream, n.connectProgress, n.connectFailure
}

type fakeListener struct {
	local      nscore.Endpoint
	stream     nscore.Resource
	progress   nscore.Progress
	failure    error
	accepts    int
	closeCalls int
}

func (l *fakeListener) Close() error                   { l.closeCalls++; return nil }
func (*fakeListener) Readiness() nscore.Readiness      { return nscore.ReadyAccept }
func (l *fakeListener) LocalEndpoint() nscore.Endpoint { return l.local }
func (l *fakeListener) TryAccept() (nscore.Resource, nscore.Progress, error) {
	l.accepts++
	return l.stream, l.progress, l.failure
}

type fakeStream struct {
	local            nscore.Endpoint
	remote           nscore.Endpoint
	finishProgress   nscore.Progress
	finishFailure    error
	finishCalls      int
	readResult       nscore.IOResult
	readFailure      error
	readData         []byte
	readCalls        int
	writeResult      nscore.IOResult
	writeFailure     error
	written          []byte
	writeCalls       int
	shutdownProgress nscore.Progress
	shutdownFailure  error
	shutdownCalls    int
	closeCalls       int
}

func (s *fakeStream) Close() error { s.closeCalls++; return nil }
func (*fakeStream) Readiness() nscore.Readiness {
	return nscore.ReadyConnected | nscore.ReadyReadable | nscore.ReadyWritable
}
func (s *fakeStream) LocalEndpoint() nscore.Endpoint  { return s.local }
func (s *fakeStream) RemoteEndpoint() nscore.Endpoint { return s.remote }
func (s *fakeStream) TryFinishConnect() (nscore.Progress, error) {
	s.finishCalls++
	return s.finishProgress, s.finishFailure
}
func (s *fakeStream) TryRead(dst []byte) (nscore.IOResult, error) {
	s.readCalls++
	copy(dst, s.readData)
	return s.readResult, s.readFailure
}
func (s *fakeStream) TryWrite(src []byte) (nscore.IOResult, error) {
	s.writeCalls++
	s.written = append(s.written[:0], src...)
	return s.writeResult, s.writeFailure
}
func (s *fakeStream) TryShutdownWrite() (nscore.Progress, error) {
	s.shutdownCalls++
	return s.shutdownProgress, s.shutdownFailure
}

func TestBindingsConnectStreamIOAtomicStatusesAndLifecycle(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 41000}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("2001:db8::20"), Port: 443}
	stream := &fakeStream{
		local: local, remote: remote,
		finishProgress:   nscore.ProgressDone,
		readResult:       nscore.IOResult{State: nscore.IOWouldBlock},
		writeResult:      nscore.IOResult{State: nscore.IOWouldBlock},
		shutdownProgress: nscore.ProgressDone,
	}
	backend := &fakeNamespace{stream: stream, connectProgress: nscore.ProgressInProgress}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 480); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[480:488]))
	if !abicore.EncodeEndpointV1(host.memory, 0, remote) {
		t.Fatal("encode remote endpoint")
	}

	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "connect"), host, uint64(namespaceHandle), 0, 16); status != guest.StatusInvalidArgument || backend.connectCalls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap connect = %v, calls=%d", status, backend.connectCalls)
	}
	host.memory[28] = 1
	streamBefore := append([]byte(nil), host.memory[64:64+tcpabi.StreamV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "connect"), host, uint64(namespaceHandle), 0, 64); status != guest.StatusInvalidArgument || backend.connectCalls != 0 || !bytes.Equal(host.memory[64:64+tcpabi.StreamV1Size], streamBefore) {
		t.Fatalf("reserved connect = %v, calls=%d", status, backend.connectCalls)
	}
	host.memory[28] = 0

	backend.connectFailure = nscore.Fail(nscore.FailureConnectionRefused, errors.New("refused"))
	if status := callBinding(t, bindingByName(t, bindings, "connect"), host, uint64(namespaceHandle), 0, 64); status != guest.StatusConnectionRefused || backend.connectCalls != 1 || !bytes.Equal(host.memory[64:64+tcpabi.StreamV1Size], streamBefore) {
		t.Fatalf("failed connect = %v, calls=%d", status, backend.connectCalls)
	}
	backend.connectFailure = nil
	var typedNil *fakeStream
	backend.stream = typedNil
	if status := callBinding(t, bindingByName(t, bindings, "connect"), host, uint64(namespaceHandle), 0, 64); status != guest.StatusIO || backend.connectCalls != 2 || !bytes.Equal(host.memory[64:64+tcpabi.StreamV1Size], streamBefore) {
		t.Fatalf("typed-nil connect = %v, calls=%d", status, backend.connectCalls)
	}
	backend.stream = stream
	if status := callBinding(t, bindingByName(t, bindings, "connect"), host, uint64(namespaceHandle), 0, 64); status != guest.StatusInProgress || backend.connectCalls != 3 || backend.connectRemote != remote {
		t.Fatalf("connect = %v, calls=%d remote=%+v", status, backend.connectCalls, backend.connectRemote)
	}
	streamHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[64:72]))
	gotLocal, localOK := abicore.DecodeEndpointV1(host.memory, 72)
	gotRemote, remoteOK := abicore.DecodeEndpointV1(host.memory, 104)
	if streamHandle == 0 || !localOK || !remoteOK || gotLocal != local || gotRemote != remote {
		t.Fatalf("stream = %v local=%+v/%v remote=%+v/%v", streamHandle, gotLocal, localOK, gotRemote, remoteOK)
	}

	if status := callBinding(t, bindingByName(t, bindings, "finish_connect"), host, uint64(streamHandle)); status != guest.StatusOK {
		t.Fatalf("finish_connect = %v", status)
	}
	stream.finishProgress = 99
	if status := callBinding(t, bindingByName(t, bindings, "finish_connect"), host, uint64(streamHandle)); status != guest.StatusIO {
		t.Fatalf("malformed finish_connect = %v", status)
	}
	stream.finishProgress = nscore.ProgressDone

	payloadPtr, payloadLen, resultPtr := uint64(160), uint64(16), uint64(192)
	readPayloadBefore := append([]byte(nil), host.memory[payloadPtr:payloadPtr+payloadLen]...)
	readResultBefore := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(tcpabi.IOResultV1Size)]...)
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(streamHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusAgain || stream.readCalls != 1 || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], readPayloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(tcpabi.IOResultV1Size)], readResultBefore) {
		t.Fatalf("would-block read = %v, calls=%d", status, stream.readCalls)
	}
	stream.readResult = nscore.IOResult{State: nscore.IOEOF}
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(streamHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusEOF || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(tcpabi.IOResultV1Size)], readResultBefore) {
		t.Fatalf("EOF read = %v", status)
	}
	stream.readData = []byte("poison")
	stream.readFailure = nscore.Fail(nscore.FailureConnectionReset, errors.New("reset"))
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(streamHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusConnectionReset || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], readPayloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(tcpabi.IOResultV1Size)], readResultBefore) {
		t.Fatalf("failed read = %v", status)
	}
	stream.readFailure = nil
	stream.readResult = nscore.IOResult{Bytes: int(payloadLen) + 1, State: nscore.IOReady}
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(streamHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusIO || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], readPayloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(tcpabi.IOResultV1Size)], readResultBefore) {
		t.Fatalf("malformed read = %v", status)
	}
	stream.readData = []byte("reply")
	stream.readResult = nscore.IOResult{Bytes: len(stream.readData), State: nscore.IOReady}
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(streamHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusOK {
		t.Fatalf("ready read = %v", status)
	}
	if got := string(host.memory[payloadPtr : payloadPtr+uint64(len(stream.readData))]); got != "reply" {
		t.Fatalf("read payload = %q", got)
	}
	if got := binary.LittleEndian.Uint32(host.memory[resultPtr : resultPtr+4]); got != uint32(len(stream.readData)) || !bytes.Equal(host.memory[resultPtr+4:resultPtr+8], make([]byte, 4)) {
		t.Fatalf("read result = %x", host.memory[resultPtr:resultPtr+8])
	}

	copy(host.memory[224:230], "abcdef")
	writeResultBefore := append([]byte(nil), host.memory[240:248]...)
	if status := callBinding(t, bindingByName(t, bindings, "write"), host, uint64(streamHandle), 224, 16, 232); status != guest.StatusInvalidArgument || stream.writeCalls != 0 || !bytes.Equal(host.memory[240:248], writeResultBefore) {
		t.Fatalf("overlap write = %v, calls=%d", status, stream.writeCalls)
	}
	stream.writeResult = nscore.IOResult{Bytes: 3, State: nscore.IOReady}
	if status := callBinding(t, bindingByName(t, bindings, "write"), host, uint64(streamHandle), 224, 6, 240); status != guest.StatusOK || string(stream.written) != "abcdef" {
		t.Fatalf("ready write = %v, payload=%q", status, stream.written)
	}
	if got := binary.LittleEndian.Uint32(host.memory[240:244]); got != 3 || !bytes.Equal(host.memory[244:248], make([]byte, 4)) {
		t.Fatalf("write result = %x", host.memory[240:248])
	}
	stream.writeResult = nscore.IOResult{State: nscore.IOWouldBlock}
	writeAgainBefore := append([]byte(nil), host.memory[240:248]...)
	if status := callBinding(t, bindingByName(t, bindings, "write"), host, uint64(streamHandle), 224, 6, 240); status != guest.StatusAgain || !bytes.Equal(host.memory[240:248], writeAgainBefore) {
		t.Fatalf("would-block write = %v", status)
	}

	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(namespaceHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind read = %v", status)
	}
	stream.shutdownProgress = 99
	if status := callBinding(t, bindingByName(t, bindings, "shutdown_write"), host, uint64(streamHandle)); status != guest.StatusIO {
		t.Fatalf("malformed shutdown_write = %v", status)
	}
	stream.shutdownProgress = nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "shutdown_write"), host, uint64(streamHandle)); status != guest.StatusOK {
		t.Fatalf("shutdown_write = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_stream"), host, uint64(streamHandle)); status != guest.StatusOK || stream.closeCalls != 1 {
		t.Fatalf("close_stream = %v, calls=%d", status, stream.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(streamHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle {
		t.Fatalf("stale read = %v", status)
	}

	fresh := &fakeStream{
		local: local, remote: remote,
		finishProgress:   nscore.ProgressDone,
		readResult:       nscore.IOResult{State: nscore.IOWouldBlock},
		writeResult:      nscore.IOResult{Bytes: 6, State: nscore.IOReady},
		shutdownProgress: nscore.ProgressDone,
	}
	backend.stream = fresh
	if status := callBinding(t, bindingByName(t, bindings, "connect"), host, uint64(namespaceHandle), 0, 320); status != guest.StatusInProgress {
		t.Fatalf("fresh connect = %v", status)
	}
	freshHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[320:328]))
	if freshHandle == streamHandle || uint16(freshHandle) != uint16(streamHandle) {
		t.Fatalf("generation-safe stream slot reuse = old %v, fresh %v", streamHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "finish_connect"), host, uint64(streamHandle)); status != guest.StatusBadHandle || fresh.finishCalls != 0 {
		t.Fatalf("stale finish_connect after reuse = %v, fresh calls=%d", status, fresh.finishCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, uint64(streamHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle || fresh.readCalls != 0 {
		t.Fatalf("stale read after reuse = %v, fresh calls=%d", status, fresh.readCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "write"), host, uint64(streamHandle), 224, 6, 240); status != guest.StatusBadHandle || fresh.writeCalls != 0 {
		t.Fatalf("stale write after reuse = %v, fresh calls=%d", status, fresh.writeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "shutdown_write"), host, uint64(streamHandle)); status != guest.StatusBadHandle || fresh.shutdownCalls != 0 {
		t.Fatalf("stale shutdown_write after reuse = %v, fresh calls=%d", status, fresh.shutdownCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_stream"), host, uint64(streamHandle)); status != guest.StatusBadHandle || fresh.closeCalls != 0 {
		t.Fatalf("stale close after reuse = %v, fresh calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "finish_connect"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.finishCalls != 1 {
		t.Fatalf("fresh finish_connect = %v, calls=%d", status, fresh.finishCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "write"), host, uint64(freshHandle), 224, 6, 240); status != guest.StatusOK || fresh.writeCalls != 1 {
		t.Fatalf("fresh write = %v, calls=%d", status, fresh.writeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "shutdown_write"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.shutdownCalls != 1 {
		t.Fatalf("fresh shutdown_write = %v, calls=%d", status, fresh.shutdownCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_stream"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("fresh close = %v, calls=%d", status, fresh.closeCalls)
	}
}

func TestBindingsRejectHighBitI32AliasesBeforeBackendCalls(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("0.0.0.0"), Port: 8080}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.44"), Port: 443}
	stream := &fakeStream{local: local, remote: remote, readResult: nscore.IOResult{State: nscore.IOWouldBlock}, writeResult: nscore.IOResult{State: nscore.IOWouldBlock}}
	listener := &fakeListener{local: local, progress: nscore.ProgressWouldBlock}
	backend := &fakeNamespace{listener: listener, listenProgress: nscore.ProgressDone, stream: stream, connectProgress: nscore.ProgressDone}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	bindings := Bindings(plugin.NewHost(manager))
	state, _ := manager.ForInstance(instance)
	if !abicore.EncodeEndpointV1(host.memory, 0, local) {
		t.Fatal("encode endpoint")
	}
	listenerHandle, err := state.Resources().Add(resource.KindTCPListener, listener)
	if err != nil {
		t.Fatal(err)
	}
	streamHandle, err := state.Resources().Add(resource.KindTCPStream, stream)
	if err != nil {
		t.Fatal(err)
	}

	const high = uint64(1) << 32
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, high+480); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("high namespace output = %v", status)
	}
	for name, params := range map[string][]uint64{
		"listen endpoint": {uint64(state.NamespaceHandle()), high, 64},
		"listen output":   {uint64(state.NamespaceHandle()), 0, high + 64},
	} {
		if status := callBinding(t, bindingByName(t, bindings, "listen"), host, params...); status != guest.StatusInvalidArgument || backend.listenCalls != 0 || !bytes.Equal(host.memory, before) {
			t.Fatalf("high %s = %v calls=%d", name, status, backend.listenCalls)
		}
	}
	for name, params := range map[string][]uint64{
		"connect endpoint": {uint64(state.NamespaceHandle()), high, 64},
		"connect output":   {uint64(state.NamespaceHandle()), 0, high + 64},
	} {
		if status := callBinding(t, bindingByName(t, bindings, "connect"), host, params...); status != guest.StatusInvalidArgument || backend.connectCalls != 0 || !bytes.Equal(host.memory, before) {
			t.Fatalf("high %s = %v calls=%d", name, status, backend.connectCalls)
		}
	}
	if status := callBinding(t, bindingByName(t, bindings, "accept"), host, uint64(listenerHandle), high+64); status != guest.StatusInvalidArgument || listener.accepts != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high accept output = %v calls=%d", status, listener.accepts)
	}
	for operation, cases := range map[string]map[string][]uint64{
		"read": {
			"payload pointer": {uint64(streamHandle), high + 160, 16, 192},
			"payload length":  {uint64(streamHandle), 160, high + 16, 192},
			"result pointer":  {uint64(streamHandle), 160, 16, high + 192},
		},
		"write": {
			"payload pointer": {uint64(streamHandle), high + 160, 16, 192},
			"payload length":  {uint64(streamHandle), 160, high + 16, 192},
			"result pointer":  {uint64(streamHandle), 160, 16, high + 192},
		},
	} {
		for name, params := range cases {
			if status := callBinding(t, bindingByName(t, bindings, operation), host, params...); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
				t.Fatalf("high %s %s = %v", operation, name, status)
			}
		}
	}
	if stream.readCalls != 0 || stream.writeCalls != 0 {
		t.Fatalf("high I/O invoked backend: reads=%d writes=%d", stream.readCalls, stream.writeCalls)
	}
}

func TestBindingsListenAcceptAtomicStatusesAndLifecycle(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("0.0.0.0"), Port: 8080}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.44"), Port: 52000}
	accepted := &fakeStream{local: local, remote: remote}
	listener := &fakeListener{local: local, progress: nscore.ProgressWouldBlock}
	backend := &fakeNamespace{listener: listener, listenProgress: nscore.ProgressDone}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 256)}
	bindings := Bindings(plugin.NewHost(manager))
	state, _ := manager.ForInstance(instance)
	if !abicore.EncodeEndpointV1(host.memory, 0, local) {
		t.Fatal("encode local endpoint")
	}
	listenerBefore := append([]byte(nil), host.memory[32:40]...)
	if status := callBinding(t, bindingByName(t, bindings, "listen"), host, uint64(state.NamespaceHandle()), 0, 16); status != guest.StatusInvalidArgument || backend.listenCalls != 0 {
		t.Fatalf("overlap listen = %v, calls=%d", status, backend.listenCalls)
	}
	var typedNilListener *fakeListener
	backend.listener = typedNilListener
	if status := callBinding(t, bindingByName(t, bindings, "listen"), host, uint64(state.NamespaceHandle()), 0, 32); status != guest.StatusIO || backend.listenCalls != 1 || !bytes.Equal(host.memory[32:40], listenerBefore) {
		t.Fatalf("typed-nil listen = %v, calls=%d", status, backend.listenCalls)
	}
	backend.listener = listener
	if status := callBinding(t, bindingByName(t, bindings, "listen"), host, uint64(state.NamespaceHandle()), 0, 32); status != guest.StatusOK || backend.listenCalls != 2 || backend.listenLocal != local || bytes.Equal(host.memory[32:40], listenerBefore) {
		t.Fatalf("listen = %v, calls=%d local=%+v", status, backend.listenCalls, backend.listenLocal)
	}
	listenerHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[32:40]))
	streamBefore := append([]byte(nil), host.memory[64:64+tcpabi.StreamV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "accept"), host, uint64(listenerHandle), 64); status != guest.StatusAgain || listener.accepts != 1 || !bytes.Equal(host.memory[64:64+tcpabi.StreamV1Size], streamBefore) {
		t.Fatalf("would-block accept = %v, calls=%d", status, listener.accepts)
	}
	var typedNilStream *fakeStream
	listener.stream, listener.progress = typedNilStream, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "accept"), host, uint64(listenerHandle), 64); status != guest.StatusIO || listener.accepts != 2 || !bytes.Equal(host.memory[64:64+tcpabi.StreamV1Size], streamBefore) {
		t.Fatalf("typed-nil accept = %v, calls=%d", status, listener.accepts)
	}
	listener.stream = accepted
	if status := callBinding(t, bindingByName(t, bindings, "accept"), host, uint64(listenerHandle), 64); status != guest.StatusOK {
		t.Fatalf("accept = %v", status)
	}
	acceptedHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[64:72]))
	if acceptedHandle == 0 {
		t.Fatal("zero accepted handle")
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_listener"), host, uint64(listenerHandle)); status != guest.StatusOK || listener.closeCalls != 1 {
		t.Fatalf("close_listener = %v, calls=%d", status, listener.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "accept"), host, uint64(listenerHandle), 64); status != guest.StatusBadHandle {
		t.Fatalf("stale accept = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close_stream"), host, uint64(acceptedHandle)); status != guest.StatusOK || accepted.closeCalls != 1 {
		t.Fatalf("close accepted = %v, calls=%d", status, accepted.closeCalls)
	}
}

func TestBindingsPrevalidateOutputsBeforeInstanceAndHandleLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x3c}, 64)}
	bindings := Bindings(plugin.NewHost(manager))
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 57); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("namespace range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "connect"), host, 1, 0, 0); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("connect range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "accept"), host, 1, 1); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("accept range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "read"), host, 1, 0, 64, 0); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("read range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func attachManager(t testing.TB, backend tcpns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: tcpns.ServiceKey, Value: backend})
	}
	manager, err := instancecore.NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	return manager, instance
}

func bindingByName(t testing.TB, bindings []plugin.Binding, name string) wago.HostFunc {
	t.Helper()
	for _, binding := range bindings {
		if binding.Name == name {
			return binding.Func
		}
	}
	t.Fatalf("binding %q missing", name)
	return nil
}

func callBinding(t testing.TB, function wago.HostFunc, host testHost, params ...uint64) guest.Status {
	t.Helper()
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}

func BenchmarkReadBindingReady(b *testing.B) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 41000}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.20"), Port: 443}
	stream := &fakeStream{local: local, remote: remote, readData: bytes.Repeat([]byte{0x5a}, 256), readResult: nscore.IOResult{Bytes: 256, State: nscore.IOReady}}
	manager, instance := attachManager(b, &fakeNamespace{stream: stream, connectProgress: nscore.ProgressDone})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindTCPStream, stream)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, 512)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "read")
	params := []uint64{uint64(handle), 0, 256, 256}
	var results [1]uint64
	function(host, params, results[:])
	if status := guest.Status(int32(results[0])); status != guest.StatusOK {
		b.Fatalf("warmup status = %v", status)
	}
	b.ReportAllocs()
	b.SetBytes(256)
	b.ResetTimer()
	for b.Loop() {
		function(host, params, results[:])
	}
}
