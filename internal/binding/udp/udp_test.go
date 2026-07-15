package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	udpabi "github.com/wago-org/net/internal/abi/udp"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
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
	socket   nscore.Resource
	progress nscore.Progress
	failure  error
	local    nscore.Endpoint
	calls    int
}

func (n *fakeNamespace) TryBindUDP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	n.calls++
	n.local = local
	return n.socket, n.progress, n.failure
}

type fakeSocket struct {
	local          nscore.Endpoint
	sendProgress   nscore.Progress
	sendFailure    error
	sent           []byte
	remote         nscore.Endpoint
	sendCalls      int
	receiveResult  udpns.DatagramResult
	receiveFailure error
	receivePayload []byte
	receiveCalls   int
	closeCalls     int
}

func (s *fakeSocket) Close() error { s.closeCalls++; return nil }
func (*fakeSocket) Readiness() nscore.Readiness {
	return nscore.ReadyReadable | nscore.ReadyWritable
}
func (s *fakeSocket) LocalEndpoint() nscore.Endpoint { return s.local }
func (s *fakeSocket) TrySend(payload []byte, remote nscore.Endpoint) (nscore.Progress, error) {
	s.sendCalls++
	s.sent = append(s.sent[:0], payload...)
	s.remote = remote
	return s.sendProgress, s.sendFailure
}
func (s *fakeSocket) TryReceive(dst []byte) (udpns.DatagramResult, error) {
	s.receiveCalls++
	if s.receiveFailure == nil && s.receiveResult.Ready {
		copy(dst, s.receivePayload)
	}
	return s.receiveResult, s.receiveFailure
}

func TestBindingsBindSendReceiveAtomicStatusesAndLifecycle(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("0.0.0.0"), Port: 53000}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("2001:db8::53"), Port: 53}
	socket := &fakeSocket{local: local, sendProgress: nscore.ProgressDone}
	backend := &fakeNamespace{socket: socket, progress: nscore.ProgressDone}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 480); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[480:488]))
	if !abicore.EncodeEndpointV1(host.memory, 0, local) {
		t.Fatal("encode local endpoint")
	}

	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 16); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap bind = %v, calls=%d", status, backend.calls)
	}
	host.memory[28] = 1
	handleBefore := append([]byte(nil), host.memory[48:56]...)
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 48); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory[48:56], handleBefore) {
		t.Fatalf("reserved bind = %v, calls=%d", status, backend.calls)
	}
	host.memory[28] = 0

	failedSocket := &fakeSocket{local: local}
	backend.socket = failedSocket
	backend.failure = nscore.Fail(nscore.FailureAddressInUse, errors.New("in use"))
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 48); status != guest.StatusAddressInUse || backend.calls != 1 || failedSocket.closeCalls != 1 || !bytes.Equal(host.memory[48:56], handleBefore) {
		t.Fatalf("failed bind = %v, calls=%d closes=%d", status, backend.calls, failedSocket.closeCalls)
	}
	backend.socket, backend.progress, backend.failure = nil, nscore.ProgressWouldBlock, nil
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 48); status != guest.StatusAgain || backend.calls != 2 || !bytes.Equal(host.memory[48:56], handleBefore) {
		t.Fatalf("would-block bind = %v, calls=%d", status, backend.calls)
	}
	var typedNil *fakeSocket
	backend.socket, backend.progress = typedNil, nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 48); status != guest.StatusIO || backend.calls != 3 || !bytes.Equal(host.memory[48:56], handleBefore) {
		t.Fatalf("typed-nil bind = %v, calls=%d", status, backend.calls)
	}
	backend.socket = socket
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 48); status != guest.StatusOK || backend.calls != 4 || backend.local != local {
		t.Fatalf("bind = %v, calls=%d local=%+v", status, backend.calls, backend.local)
	}
	socketHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[48:56]))
	if socketHandle == 0 {
		t.Fatal("zero socket handle")
	}

	copy(host.memory[64:70], "packet")
	if !abicore.EncodeEndpointV1(host.memory, 96, remote) {
		t.Fatal("encode remote endpoint")
	}
	sendCalls := socket.sendCalls
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 500, 16, 96); status != guest.StatusInvalidArgument || socket.sendCalls != sendCalls {
		t.Fatalf("send payload range = %v, calls=%d", status, socket.sendCalls)
	}
	host.memory[124] = 1
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 64, 6, 96); status != guest.StatusInvalidArgument || socket.sendCalls != sendCalls {
		t.Fatalf("send endpoint reserved = %v, calls=%d", status, socket.sendCalls)
	}
	host.memory[124] = 0
	socket.sendFailure = nscore.Fail(nscore.FailureMessageTooLarge, errors.New("large"))
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 64, 6, 96); status != guest.StatusMessageTooLarge {
		t.Fatalf("failed send = %v", status)
	}
	socket.sendFailure = nil
	socket.sendProgress = 99
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 64, 6, 96); status != guest.StatusIO {
		t.Fatalf("malformed send = %v", status)
	}
	socket.sendProgress = nscore.ProgressWouldBlock
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 64, 6, 96); status != guest.StatusAgain {
		t.Fatalf("would-block send = %v", status)
	}
	socket.sendProgress = nscore.ProgressDone
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 64, 6, 96); status != guest.StatusOK || string(socket.sent) != "packet" || socket.remote != remote {
		t.Fatalf("send = %v payload=%q remote=%+v", status, socket.sent, socket.remote)
	}

	payloadPtr, payloadLen, resultPtr := uint64(160), uint64(8), uint64(192)
	payloadBefore := append([]byte(nil), host.memory[payloadPtr:payloadPtr+payloadLen]...)
	resultBefore := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(udpabi.ReceiveResultV1Size)]...)
	receiveCalls := socket.receiveCalls
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, 48, resultPtr); status != guest.StatusInvalidArgument || socket.receiveCalls != receiveCalls {
		t.Fatalf("overlap receive = %v, calls=%d", status, socket.receiveCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, payloadLen, 480); status != guest.StatusInvalidArgument || socket.receiveCalls != receiveCalls {
		t.Fatalf("receive result range = %v, calls=%d", status, socket.receiveCalls)
	}
	socket.receiveResult = udpns.DatagramResult{}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusAgain || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], payloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(udpabi.ReceiveResultV1Size)], resultBefore) {
		t.Fatalf("would-block receive = %v", status)
	}
	socket.receiveFailure = nscore.Fail(nscore.FailureTemporary, errors.New("temporary"))
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusTemporaryFailure || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], payloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(udpabi.ReceiveResultV1Size)], resultBefore) {
		t.Fatalf("failed receive = %v", status)
	}
	socket.receiveFailure = nil
	socket.receivePayload = []byte("mutation")
	socket.receiveResult = udpns.DatagramResult{Ready: true, Copied: 9, DatagramBytes: 9, Source: remote}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusIO || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], payloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(udpabi.ReceiveResultV1Size)], resultBefore) {
		t.Fatalf("malformed receive = %v", status)
	}
	socket.receivePayload = []byte("response-data")
	socket.receiveResult = udpns.DatagramResult{Ready: true, Copied: 8, DatagramBytes: len(socket.receivePayload), Source: remote, Truncated: true}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusOK {
		t.Fatalf("ready receive = %v", status)
	}
	if got := string(host.memory[payloadPtr : payloadPtr+payloadLen]); got != "response" {
		t.Fatalf("receive payload = %q", got)
	}
	encoded := host.memory[resultPtr : resultPtr+uint64(udpabi.ReceiveResultV1Size)]
	gotSource, ok := abicore.DecodeEndpointV1(encoded, 0)
	if !ok || gotSource != remote || binary.LittleEndian.Uint32(encoded[32:36]) != 8 || binary.LittleEndian.Uint32(encoded[36:40]) != uint32(len(socket.receivePayload)) || binary.LittleEndian.Uint32(encoded[40:44]) != udpabi.ReceiveFlagTruncated || binary.LittleEndian.Uint32(encoded[44:48]) != 0 {
		t.Fatalf("receive result = %x source=%+v/%v", encoded, gotSource, ok)
	}

	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(namespaceHandle), 64, 6, 96); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind send = %v", status)
	}
	payloadBefore = append(payloadBefore[:0], host.memory[payloadPtr:payloadPtr+payloadLen]...)
	resultBefore = append(resultBefore[:0], host.memory[resultPtr:resultPtr+uint64(udpabi.ReceiveResultV1Size)]...)
	receiveCalls = socket.receiveCalls
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(namespaceHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle || socket.receiveCalls != receiveCalls || !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], payloadBefore) || !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(udpabi.ReceiveResultV1Size)], resultBefore) {
		t.Fatalf("wrong-kind receive = %v, calls=%d", status, socket.receiveCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(socketHandle)); status != guest.StatusOK || socket.closeCalls != 1 {
		t.Fatalf("close = %v, calls=%d", status, socket.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle {
		t.Fatalf("stale receive = %v", status)
	}

	fresh := &fakeSocket{local: local, sendProgress: nscore.ProgressDone}
	backend.socket = fresh
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 56); status != guest.StatusOK {
		t.Fatalf("fresh bind = %v", status)
	}
	freshHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[56:64]))
	if freshHandle == socketHandle || uint16(freshHandle) != uint16(socketHandle) {
		t.Fatalf("generation-safe slot reuse = old %v, fresh %v", socketHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 64, 6, 96); status != guest.StatusBadHandle || fresh.sendCalls != 0 {
		t.Fatalf("stale send after reuse = %v, fresh calls=%d", status, fresh.sendCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), payloadPtr, payloadLen, resultPtr); status != guest.StatusBadHandle || fresh.receiveCalls != 0 {
		t.Fatalf("stale receive after reuse = %v, fresh calls=%d", status, fresh.receiveCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(socketHandle)); status != guest.StatusBadHandle || fresh.closeCalls != 0 {
		t.Fatalf("stale close after reuse = %v, fresh calls=%d", status, fresh.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(freshHandle), 64, 6, 96); status != guest.StatusOK || fresh.sendCalls != 1 {
		t.Fatalf("fresh send = %v, calls=%d", status, fresh.sendCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(freshHandle)); status != guest.StatusOK || fresh.closeCalls != 1 {
		t.Fatalf("fresh close = %v, calls=%d", status, fresh.closeCalls)
	}
}

func TestBindingsRejectHighBitI32AliasesBeforeBackendCalls(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("0.0.0.0"), Port: 53000}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.53"), Port: 53}
	socket := &fakeSocket{local: local, sendProgress: nscore.ProgressDone}
	backend := &fakeNamespace{socket: socket, progress: nscore.ProgressDone}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	bindings := Bindings(plugin.NewHost(manager))
	state, _ := manager.ForInstance(instance)
	namespaceHandle := state.NamespaceHandle()
	if !abicore.EncodeEndpointV1(host.memory, 0, local) || !abicore.EncodeEndpointV1(host.memory, 96, remote) {
		t.Fatal("encode endpoints")
	}

	const high = uint64(1) << 32
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, high+480); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("high namespace output = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), high, 48); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high bind endpoint = %v calls=%d", status, backend.calls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, high+48); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("high bind output = %v calls=%d", status, backend.calls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 48); status != guest.StatusOK {
		t.Fatalf("valid bind = %v", status)
	}
	socketHandle := binary.LittleEndian.Uint64(host.memory[48:56])
	copy(host.memory[64:70], "packet")

	for name, params := range map[string][]uint64{
		"payload pointer": {socketHandle, high + 64, 6, 96},
		"payload length":  {socketHandle, 64, high + 6, 96},
		"remote pointer":  {socketHandle, 64, 6, high + 96},
	} {
		if status := callBinding(t, bindingByName(t, bindings, "send"), host, params...); status != guest.StatusInvalidArgument || socket.sendCalls != 0 {
			t.Fatalf("high send %s = %v calls=%d", name, status, socket.sendCalls)
		}
	}

	before = append(before[:0], host.memory...)
	for name, params := range map[string][]uint64{
		"payload pointer": {socketHandle, high + 160, 8, 192},
		"payload length":  {socketHandle, 160, high + 8, 192},
		"result pointer":  {socketHandle, 160, 8, high + 192},
	} {
		if status := callBinding(t, bindingByName(t, bindings, "receive"), host, params...); status != guest.StatusInvalidArgument || socket.receiveCalls != 0 || !bytes.Equal(host.memory, before) {
			t.Fatalf("high receive %s = %v calls=%d", name, status, socket.receiveCalls)
		}
	}
}

func TestBindingsPreserveFullWidthNamespaceAndSocketHandles(t *testing.T) {
	local := nscore.Endpoint{Address: netip.MustParseAddr("0.0.0.0"), Port: 53000}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.53"), Port: 53}
	socket := &fakeSocket{
		local: local, sendProgress: nscore.ProgressDone,
		receiveResult: udpns.DatagramResult{},
	}
	created := &fakeSocket{local: local, sendProgress: nscore.ProgressDone}
	backend := &fakeNamespace{socket: created, progress: nscore.ProgressDone}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x71}, 512)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	namespaceHandle := state.NamespaceHandle()
	socketHandle, err := state.Resources().Add(resource.KindUDPSocket, socket)
	if err != nil {
		t.Fatal(err)
	}
	if !abicore.EncodeEndpointV1(host.memory, 0, local) || !abicore.EncodeEndpointV1(host.memory, 96, remote) {
		t.Fatal("encode endpoints")
	}
	copy(host.memory[64:70], "packet")

	const high = uint64(1) << 63
	handleBefore := append([]byte(nil), host.memory[48:56]...)
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle)|high, 0, 48); status != guest.StatusBadHandle || backend.calls != 0 || !bytes.Equal(host.memory[48:56], handleBefore) {
		t.Fatalf("high namespace bind = %v calls=%d", status, backend.calls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle)|high, 64, 6, 96); status != guest.StatusBadHandle || socket.sendCalls != 0 {
		t.Fatalf("high socket send = %v calls=%d", status, socket.sendCalls)
	}
	payloadBefore := append([]byte(nil), host.memory[160:176]...)
	resultBefore := append([]byte(nil), host.memory[192:192+udpabi.ReceiveResultV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle)|high, 160, 16, 192); status != guest.StatusBadHandle || socket.receiveCalls != 0 || !bytes.Equal(host.memory[160:176], payloadBefore) || !bytes.Equal(host.memory[192:192+udpabi.ReceiveResultV1Size], resultBefore) {
		t.Fatalf("high socket receive = %v calls=%d", status, socket.receiveCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(socketHandle)|high); status != guest.StatusBadHandle || socket.closeCalls != 0 {
		t.Fatalf("high socket close = %v calls=%d", status, socket.closeCalls)
	}

	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, uint64(namespaceHandle), 0, 48); status != guest.StatusOK || backend.calls != 1 {
		t.Fatalf("exact namespace bind = %v calls=%d", status, backend.calls)
	}
	createdHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[48:56]))
	if status := callBinding(t, bindingByName(t, bindings, "send"), host, uint64(socketHandle), 64, 6, 96); status != guest.StatusOK || socket.sendCalls != 1 || string(socket.sent) != "packet" || socket.remote != remote {
		t.Fatalf("exact socket send = %v calls=%d payload=%q remote=%+v", status, socket.sendCalls, socket.sent, socket.remote)
	}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, uint64(socketHandle), 160, 16, 192); status != guest.StatusAgain || socket.receiveCalls != 1 || !bytes.Equal(host.memory[160:176], payloadBefore) || !bytes.Equal(host.memory[192:192+udpabi.ReceiveResultV1Size], resultBefore) {
		t.Fatalf("exact socket receive = %v calls=%d", status, socket.receiveCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(socketHandle)); status != guest.StatusOK || socket.closeCalls != 1 {
		t.Fatalf("exact socket close = %v calls=%d", status, socket.closeCalls)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, uint64(createdHandle)); status != guest.StatusOK || created.closeCalls != 1 {
		t.Fatalf("created socket close = %v calls=%d", status, created.closeCalls)
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
	if status := callBinding(t, bindingByName(t, bindings, "bind"), host, 1, 0, 0); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("bind range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "receive"), host, 1, 0, 64, 0); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("receive range = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func attachManager(t testing.TB, backend udpns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: udpns.ServiceKey, Value: backend})
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

func BenchmarkReceiveBindingReady(b *testing.B) {
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.53"), Port: 53}
	socket := &fakeSocket{
		receivePayload: bytes.Repeat([]byte{0x5a}, 256),
		receiveResult:  udpns.DatagramResult{Ready: true, Copied: 256, DatagramBytes: 256, Source: remote},
	}
	manager, instance := attachManager(b, &fakeNamespace{socket: socket, progress: nscore.ProgressDone})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindUDPSocket, socket)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, 512)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "receive")
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
