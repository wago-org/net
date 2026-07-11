package net

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	abi "github.com/wago-org/net/internal/abi/core"
	instance "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

type udpHostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m udpHostModule) Memory() []byte           { return m.memory }
func (m udpHostModule) Instance() *wago.Instance { return m.instance }

func TestGuestUDPUnavailableNamespaceIsTruthful(t *testing.T) {
	extension := Init(Config{})
	runtime := runtimeForExtension(t, extension)
	instance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime))
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := udpHostModule{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 16)}
	before := append([]byte(nil), host.memory...)
	if got := callUDP(t, extension, "namespace_default", host, 0); got != StatusNotSupported {
		t.Fatalf("namespace without configuration = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("unavailable namespace mutated output")
	}
}

func TestGuestUDPImportCapabilityGate(t *testing.T) {
	extension := Init(Config{})
	runtime := runtimeForExtension(t, extension)
	importEntry := append(append(wasmtest.Name(UDPModule), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	wasm := wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(importEntry)),
	)
	module, err := runtime.Compile(wasm)
	if err != nil {
		t.Fatalf("Compile UDP capability module: %v", err)
	}
	if _, err := runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{DeniedCapabilities: []wago.Capability{CapUDP}})); !errors.Is(err, wago.ErrPermissionDenied) {
		t.Fatalf("denied UDP capability instantiate = %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{CapUDP}}))
	if err != nil {
		t.Fatalf("allowed UDP capability instantiate: %v", err)
	}
	_ = instance.Close()
}

func TestGuestUDPImportsIsolationPolicyQuotaAndClose(t *testing.T) {
	firstExt, firstRuntime, firstInstance, firstHost := newGuestUDPInstance(t, 1, 2)
	secondExt, _, secondInstance, secondHost := newGuestUDPInstance(t, 2, 1)
	defer firstInstance.Close()
	defer secondInstance.Close()

	firstNamespace := guestNamespace(t, firstRuntime, firstHost)
	secondNamespace := guestNamespaceFromExtension(t, secondExt, secondHost)
	firstSocket := guestBind(t, firstExt, firstHost, firstNamespace, endpointFor(1, 4101), 64)
	secondSocket := guestBind(t, secondExt, secondHost, secondNamespace, endpointFor(2, 4102), 64)

	copy(firstHost.memory[128:], []byte("hello"))
	encodeGuestEndpoint(t, firstHost.memory, 32, endpointFor(2, 4102))
	if got := callUDP(t, firstExt, "send", firstHost, uint64(firstSocket), 128, 5, 32); got != StatusOK {
		t.Fatalf("send status = %v", got)
	}
	if got := callUDP(t, firstExt, "send", firstHost, uint64(firstSocket), 128, 5, 32); got != StatusOK {
		t.Fatalf("second send status = %v", got)
	}
	if got := callUDP(t, firstExt, "send", firstHost, uint64(firstSocket), 128, 5, 32); got != StatusAgain {
		t.Fatalf("full queue send status = %v", got)
	}

	encodeGuestEndpoint(t, firstHost.memory, 32, namespace.Endpoint{Address: netip.MustParseAddr("198.51.100.1"), Port: 53})
	if got := callUDP(t, firstExt, "send", firstHost, uint64(firstSocket), 128, 5, 32); got != StatusAccessDenied {
		t.Fatalf("policy-denied send status = %v", got)
	}
	encodeGuestEndpoint(t, secondHost.memory, 32, endpointFor(1, 4101))
	if got := callUDP(t, secondExt, "send", secondHost, uint64(firstSocket), 0, 0, 32); got != StatusBadHandle {
		t.Fatalf("cross-instance send status = %v", got)
	}

	encodeGuestEndpoint(t, firstHost.memory, 0, endpointFor(1, 4103))
	if got := callUDP(t, firstExt, "bind", firstHost, uint64(firstNamespace), 0, 96); got != StatusResourceLimit {
		t.Fatalf("exact socket quota status = %v", got)
	}
	if got := callUDP(t, firstExt, "close", firstHost, uint64(firstSocket)); got != StatusOK {
		t.Fatalf("close status = %v", got)
	}
	if got := callUDP(t, firstExt, "close", firstHost, uint64(firstSocket)); got != StatusBadHandle {
		t.Fatalf("stale close status = %v", got)
	}
	rebound := guestBind(t, firstExt, firstHost, firstNamespace, endpointFor(1, 4101), 64)
	if rebound == firstSocket {
		t.Fatal("rebind reused stale generation")
	}
	if got := callUDP(t, firstExt, "close", firstHost, uint64(rebound)); got != StatusOK {
		t.Fatalf("rebound close status = %v", got)
	}
	if got := callUDP(t, secondExt, "close", secondHost, uint64(secondSocket)); got != StatusOK {
		t.Fatalf("second close status = %v", got)
	}
}

func TestGuestUDPEmptyTruncationAndFailedMemoryWrites(t *testing.T) {
	senderExt, _, senderInstance, senderHost := newGuestUDPInstance(t, 11, 12)
	receiverExt, _, receiverInstance, receiverHost := newGuestUDPInstance(t, 12, 11)
	defer senderInstance.Close()
	defer receiverInstance.Close()
	senderState, _ := senderExt.instanceManager().ForInstance(senderInstance)
	receiverState, _ := receiverExt.instanceManager().ForInstance(receiverInstance)

	senderNamespace := guestNamespaceFromExtension(t, senderExt, senderHost)
	receiverNamespace := guestNamespaceFromExtension(t, receiverExt, receiverHost)
	sender := guestBind(t, senderExt, senderHost, senderNamespace, endpointFor(11, 4211), 64)
	receiver := guestBind(t, receiverExt, receiverHost, receiverNamespace, endpointFor(12, 4212), 64)

	encodeGuestEndpoint(t, senderHost.memory, 32, endpointFor(12, 4212))
	if got := callUDP(t, senderExt, "send", senderHost, uint64(sender), 128, 0, 32); got != StatusOK {
		t.Fatalf("empty send = %v", got)
	}
	copy(senderHost.memory[128:], []byte("abcdef"))
	if got := callUDP(t, senderExt, "send", senderHost, uint64(sender), 128, 6, 32); got != StatusOK {
		t.Fatalf("payload send = %v", got)
	}
	transferGuestUDP(t, senderState, receiverState)
	transferGuestUDP(t, senderState, receiverState)

	before := append([]byte(nil), receiverHost.memory...)
	if got := callUDP(t, receiverExt, "receive", receiverHost, uint64(receiver), 200, 3, 201); got != StatusInvalidArgument {
		t.Fatalf("overlapping receive outputs = %v", got)
	}
	if !bytes.Equal(receiverHost.memory, before) {
		t.Fatal("rejected receive mutated guest memory")
	}

	if got := callUDP(t, receiverExt, "receive", receiverHost, uint64(receiver), 200, 0, 224); got != StatusOK {
		t.Fatalf("empty receive = %v", got)
	}
	if copied := binary.LittleEndian.Uint32(receiverHost.memory[224+32:]); copied != 0 {
		t.Fatalf("empty copied = %d", copied)
	}
	if datagramBytes := binary.LittleEndian.Uint32(receiverHost.memory[224+36:]); datagramBytes != 0 {
		t.Fatalf("empty datagram bytes = %d", datagramBytes)
	}
	if source, ok := abi.DecodeEndpointV1(receiverHost.memory, 224); !ok || source != endpointFor(11, 4211) {
		t.Fatalf("empty source = %+v, %v", source, ok)
	}

	if got := callUDP(t, receiverExt, "receive", receiverHost, uint64(receiver), 200, 3, 224); got != StatusOK {
		t.Fatalf("truncated receive = %v", got)
	}
	if got := string(receiverHost.memory[200:203]); got != "abc" {
		t.Fatalf("truncated payload = %q", got)
	}
	if copied := binary.LittleEndian.Uint32(receiverHost.memory[224+32:]); copied != 3 {
		t.Fatalf("truncated copied = %d", copied)
	}
	if datagramBytes := binary.LittleEndian.Uint32(receiverHost.memory[224+36:]); datagramBytes != 6 {
		t.Fatalf("truncated datagram bytes = %d", datagramBytes)
	}
	if flags := binary.LittleEndian.Uint32(receiverHost.memory[224+40:]); flags != UDPReceiveFlagTruncated {
		t.Fatalf("truncated flags = %#x", flags)
	}
	unchanged := append([]byte(nil), receiverHost.memory...)
	if got := callUDP(t, receiverExt, "receive", receiverHost, uint64(receiver), 200, 3, 224); got != StatusAgain {
		t.Fatalf("empty queue receive = %v", got)
	}
	if !bytes.Equal(receiverHost.memory, unchanged) {
		t.Fatal("AGAIN receive mutated outputs")
	}
}

func TestGuestUDPBindValidatesOutputBeforeAllocation(t *testing.T) {
	extension, _, instance, host := newGuestUDPInstance(t, 21, 22)
	defer instance.Close()
	state, _ := extension.instanceManager().ForInstance(instance)
	namespaceHandle := guestNamespaceFromExtension(t, extension, host)
	encodeGuestEndpoint(t, host.memory, 0, endpointFor(21, 4321))
	if got := callUDP(t, extension, "bind", host, uint64(namespaceHandle), 0, uint64(len(host.memory)-4)); got != StatusInvalidArgument {
		t.Fatalf("bad output bind = %v", got)
	}
	if usage, _ := state.Quotas().Snapshot(); usage.Resources != 1 || usage.UDPResources != 0 || usage.QueuedBytes != 0 {
		t.Fatalf("failed output bind leaked quota = %+v", usage)
	}
	socket := guestBind(t, extension, host, namespaceHandle, endpointFor(21, 4321), 64)
	if socket == 0 {
		t.Fatal("valid bind after rejected output failed")
	}
}

func newGuestUDPInstance(t testing.TB, localLast, gatewayLast byte) (*Extension, *wago.Runtime, *wago.Instance, udpHostModule) {
	t.Helper()
	limits := QuotaLimits{Resources: 2, UDPResources: 1, QueuedBytes: 128, ServiceUnits: 32}
	ready := ReadinessConfig{MaxRegistrations: 2}
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	extension := Init(Config{
		Policy: PolicyConfig{Rules: []PolicyRule{{
			Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportUDP},
			Directions: []PolicyDirection{PolicyInbound, PolicyOutbound}, Prefixes: []netip.Prefix{prefix},
		}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &StaticIPv4Config{
			Hostname: "guest-udp", RandSeed: int64(localLast),
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, localLast}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, gatewayLast},
			IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, localLast}), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4},
			UDP:  UDPConfig{MaxSockets: 1, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32},
		},
	})
	runtime := runtimeForExtension(t, extension)
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Compile empty UDP guest: %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate UDP guest: %v", err)
	}
	return extension, runtime, instance, udpHostModule{instance: instance, memory: make([]byte, 512)}
}

func runtimeForExtension(t testing.TB, extension *Extension) *wago.Runtime {
	t.Helper()
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use UDP extension: %v", err)
	}
	return runtime
}

func guestNamespace(t testing.TB, runtime *wago.Runtime, host udpHostModule) resource.Handle {
	t.Helper()
	fn, ok := runtime.HostImports()[UDPModule+".namespace_default"].(wago.HostFunc)
	if !ok {
		t.Fatal("namespace_default binding missing")
	}
	results := []uint64{0}
	fn(host, []uint64{0}, results)
	if got := Status(wago.AsI32(results[0])); got != StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	return resource.Handle(binary.LittleEndian.Uint64(host.memory[:8]))
}

func guestNamespaceFromExtension(t testing.TB, extension *Extension, host udpHostModule) resource.Handle {
	t.Helper()
	if got := callUDP(t, extension, "namespace_default", host, 0); got != StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	return resource.Handle(binary.LittleEndian.Uint64(host.memory[:8]))
}

func guestBind(t testing.TB, extension *Extension, host udpHostModule, namespaceHandle resource.Handle, local namespace.Endpoint, out uint32) resource.Handle {
	t.Helper()
	encodeGuestEndpoint(t, host.memory, 0, local)
	if got := callUDP(t, extension, "bind", host, uint64(namespaceHandle), 0, uint64(out)); got != StatusOK {
		t.Fatalf("bind %v = %v", local, got)
	}
	return resource.Handle(binary.LittleEndian.Uint64(host.memory[out : out+8]))
}

func callUDP(t testing.TB, extension *Extension, name string, host udpHostModule, params ...uint64) Status {
	t.Helper()
	var binding wago.HostFunc
	for _, candidate := range extension.udpBindings() {
		if candidate.name == name {
			binding = candidate.fn
			break
		}
	}
	if binding == nil {
		t.Fatalf("UDP binding %q missing", name)
	}
	results := []uint64{0}
	binding(host, params, results)
	return Status(wago.AsI32(results[0]))
}

func encodeGuestEndpoint(t testing.TB, memory []byte, ptr uint32, endpoint namespace.Endpoint) {
	t.Helper()
	if !abi.EncodeEndpointV1(memory, ptr, endpoint) {
		t.Fatalf("encode endpoint %+v", endpoint)
	}
}

func endpointFor(last byte, port uint16) namespace.Endpoint {
	return namespace.Endpoint{Address: netip.AddrFrom4([4]byte{192, 0, 2, last}), Port: port}
}

func transferGuestUDP(t testing.TB, fromState, toState *instance.State) {
	t.Helper()
	from := concreteNamespace(t, fromState)
	to := concreteNamespace(t, toState)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 2}
	report, progress, err := from.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 {
		t.Fatalf("egress service = %+v, %v, %v", report, progress, err)
	}
	frame := make([]byte, 1514)
	result, err := from.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready || result.Truncated {
		t.Fatalf("dequeue egress = %+v, %v", result, err)
	}
	if err := to.Link().TryEnqueue(packetlink.Ingress, frame[:result.FrameBytes]); err != nil {
		t.Fatalf("enqueue ingress: %v", err)
	}
	report, progress, err = to.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 {
		t.Fatalf("ingress service = %+v, %v, %v", report, progress, err)
	}
}

type linkedNamespace interface {
	namespace.Namespace
	Link() *packetlink.Link
}

func concreteNamespace(t testing.TB, state *instance.State) linkedNamespace {
	t.Helper()
	value, err := state.LookupNamespace(state.NamespaceHandle())
	if err != nil {
		t.Fatalf("namespace lookup: %v", err)
	}
	backend, ok := nscore.ResolveNamespaceBase(value).(linkedNamespace)
	if !ok {
		t.Fatalf("namespace resource type = %T", value)
	}
	return backend
}

var _ wago.InstanceHostModule = udpHostModule{}
