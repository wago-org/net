package net

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	abi "github.com/wago-org/net/internal/abi/core"
	instance "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestTCPBindingsAreRegisteredOnlyAsCompleteTable(t *testing.T) {
	extension := Init(guestTCPConfig(1, 2))
	runtime := runtimeForExtension(t, extension)
	if got := len(extension.tcpBindings()); got != 11 {
		t.Fatalf("complete checked TCP bindings = %d, want 11", got)
	}
	for _, binding := range extension.tcpBindings() {
		if _, ok := runtime.HostImports()[TCPModule+"."+binding.name].(wago.HostFunc); !ok {
			t.Fatalf("registered TCP binding %q missing", binding.name)
		}
	}
	foundCapability := false
	for _, capability := range runtime.Capabilities() {
		foundCapability = foundCapability || capability == CapTCP
	}
	if !foundCapability {
		t.Fatal("complete TCP capability was not advertised")
	}
	for name := range Imports(guestTCPConfig(1, 2)) {
		if len(name) >= len(TCPModule)+1 && name[:len(TCPModule)+1] == TCPModule+"." {
			t.Fatalf("low-level stateless imports exposed TCP resource function %q", name)
		}
	}
}

func TestGuestTCPUnavailableNamespaceIsTruthful(t *testing.T) {
	extension := Init(Config{})
	runtime := runtimeForExtension(t, extension)
	instance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime))
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := udpHostModule{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 16)}
	before := append([]byte(nil), host.memory...)
	if got := callRegisteredTCP(t, runtime, "namespace_default", host, 0); got != StatusNotSupported {
		t.Fatalf("TCP namespace without configuration = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("unavailable TCP namespace mutated output")
	}
}

func TestGuestTCPImportCapabilityGate(t *testing.T) {
	extension := Init(Config{})
	runtime := runtimeForExtension(t, extension)
	importEntry := append(append(wasmtest.Name(TCPModule), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	wasmBytes := wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(importEntry)),
	)
	module, err := runtime.Compile(wasmBytes)
	if err != nil {
		t.Fatalf("Compile TCP capability module: %v", err)
	}
	if _, err := runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{DeniedCapabilities: []wago.Capability{CapTCP}})); !errors.Is(err, wago.ErrPermissionDenied) {
		t.Fatalf("denied TCP capability instantiate = %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{CapTCP}}))
	if err != nil {
		t.Fatalf("allowed TCP capability instantiate: %v", err)
	}
	_ = instance.Close()
}

func TestRegisteredGuestTCPTwoNamespaceExchange(t *testing.T) {
	clientExt, clientRuntime, clientInstance, clientHost := newGuestTCPInstance(t, 3, 4)
	serverExt, serverRuntime, serverInstance, serverHost := newGuestTCPInstance(t, 4, 3)
	defer clientInstance.Close()
	defer serverInstance.Close()
	clientState, _ := clientExt.instanceManager().ForInstance(clientInstance)
	serverState, _ := serverExt.instanceManager().ForInstance(serverInstance)

	if got := callRegisteredTCP(t, clientRuntime, "namespace_default", clientHost, 0); got != StatusOK {
		t.Fatalf("client namespace = %v", got)
	}
	clientNamespace := resource.Handle(binary.LittleEndian.Uint64(clientHost.memory[:8]))
	if got := callRegisteredTCP(t, serverRuntime, "namespace_default", serverHost, 0); got != StatusOK {
		t.Fatalf("server namespace = %v", got)
	}
	serverNamespace := resource.Handle(binary.LittleEndian.Uint64(serverHost.memory[:8]))
	serverEndpoint := endpointFor(4, 4604)
	encodeGuestEndpoint(t, serverHost.memory, 0, serverEndpoint)
	if got := callRegisteredTCP(t, serverRuntime, "listen", serverHost, uint64(serverNamespace), 0, 64); got != StatusOK {
		t.Fatalf("registered listen = %v", got)
	}
	listener := resource.Handle(binary.LittleEndian.Uint64(serverHost.memory[64:72]))

	encodeGuestEndpoint(t, clientHost.memory, 0, serverEndpoint)
	if got := callRegisteredTCP(t, clientRuntime, "connect", clientHost, uint64(clientNamespace), 0, 64); got != StatusInProgress {
		t.Fatalf("registered connect = %v", got)
	}
	clientStream, _, _ := decodeGuestTCPStream(t, clientHost.memory, 64)
	transferGuestUDP(t, clientState, serverState)
	transferGuestUDP(t, serverState, clientState)
	transferGuestUDP(t, clientState, serverState)
	if got := callRegisteredTCP(t, clientRuntime, "finish_connect", clientHost, uint64(clientStream)); got != StatusOK {
		t.Fatalf("registered finish_connect = %v", got)
	}
	if got := callRegisteredTCP(t, serverRuntime, "accept", serverHost, uint64(listener), 128); got != StatusOK {
		t.Fatalf("registered accept = %v", got)
	}
	serverStream, _, _ := decodeGuestTCPStream(t, serverHost.memory, 128)

	copy(clientHost.memory[256:], []byte("request"))
	if got := callRegisteredTCP(t, clientRuntime, "write", clientHost, uint64(clientStream), 256, 7, 320); got != StatusOK {
		t.Fatalf("registered client write = %v", got)
	}
	transferGuestUDP(t, clientState, serverState)
	if got := callRegisteredTCP(t, serverRuntime, "read", serverHost, uint64(serverStream), 256, 16, 320); got != StatusOK {
		t.Fatalf("registered server read = %v", got)
	}
	if count := binary.LittleEndian.Uint32(serverHost.memory[320:324]); count != 7 || string(serverHost.memory[256:263]) != "request" {
		t.Fatalf("registered server payload = %d/%q", count, serverHost.memory[256:263])
	}

	copy(serverHost.memory[384:], []byte("reply"))
	if got := callRegisteredTCP(t, serverRuntime, "write", serverHost, uint64(serverStream), 384, 5, 448); got != StatusOK {
		t.Fatalf("registered server write = %v", got)
	}
	transferGuestUDP(t, serverState, clientState)
	if got := callRegisteredTCP(t, clientRuntime, "read", clientHost, uint64(clientStream), 384, 16, 448); got != StatusOK {
		t.Fatalf("registered client read = %v", got)
	}
	if count := binary.LittleEndian.Uint32(clientHost.memory[448:452]); count != 5 || string(clientHost.memory[384:389]) != "reply" {
		t.Fatalf("registered client payload = %d/%q", count, clientHost.memory[384:389])
	}
	if got := callRegisteredTCP(t, clientRuntime, "shutdown_write", clientHost, uint64(clientStream)); got != StatusOK {
		t.Fatalf("registered shutdown = %v", got)
	}
	transferGuestUDP(t, clientState, serverState)
	if got := callRegisteredTCP(t, serverRuntime, "read", serverHost, uint64(serverStream), 512, 16, 544); got != StatusEOF {
		t.Fatalf("registered EOF = %v", got)
	}
	if got := callRegisteredTCP(t, clientRuntime, "close_stream", clientHost, uint64(clientStream)); got != StatusOK {
		t.Fatalf("registered client close = %v", got)
	}
	if got := callRegisteredTCP(t, serverRuntime, "close_stream", serverHost, uint64(serverStream)); got != StatusOK {
		t.Fatalf("registered server close = %v", got)
	}
	if got := callRegisteredTCP(t, serverRuntime, "close_listener", serverHost, uint64(listener)); got != StatusOK {
		t.Fatalf("registered listener close = %v", got)
	}
}

func TestGuestTCPCreationValidatesMemoryPolicyQuotaAndKinds(t *testing.T) {
	config := guestTCPConfig(11, 12)
	config.StaticIPv4.TCP.MaxListeners = 2
	limits := *config.Limits
	limits.TCPResources = 1
	config.Limits = &limits
	extension, _, instance, host := instantiateGuestTCP(t, config)
	defer instance.Close()
	state, _ := extension.instanceManager().ForInstance(instance)

	before := append([]byte(nil), host.memory...)
	if got := callTCP(t, extension, "namespace_default", host, uint64(len(host.memory)-4)); got != StatusInvalidArgument {
		t.Fatalf("short namespace output = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("rejected namespace output mutated memory")
	}
	namespaceHandle := guestTCPNamespace(t, extension, host)

	local := endpointFor(11, 4611)
	encodeGuestEndpoint(t, host.memory, 0, local)
	before = append([]byte(nil), host.memory...)
	if got := callTCP(t, extension, "listen", host, uint64(namespaceHandle), 0, 24); got != StatusInvalidArgument {
		t.Fatalf("overlapping listen output = %v", got)
	}
	if !bytes.Equal(host.memory, before) || state.Resources().Len() != 1 {
		t.Fatal("rejected listen changed memory or resources")
	}
	listener := guestTCPListen(t, extension, host, namespaceHandle, local, 64)
	if got := callTCP(t, extension, "finish_connect", host, uint64(listener)); got != StatusBadHandle {
		t.Fatalf("listener used as stream = %v", got)
	}

	encodeGuestEndpoint(t, host.memory, 0, endpointFor(11, 4612))
	if got := callTCP(t, extension, "listen", host, uint64(namespaceHandle), 0, 80); got != StatusResourceLimit {
		t.Fatalf("exact TCP resource quota = %v", got)
	}
	usage, _ := state.Quotas().Snapshot()
	if usage.TCPResources != 1 || usage.Resources != 2 {
		t.Fatalf("listener quota usage = %+v", usage)
	}

	encodeGuestEndpoint(t, host.memory, 0, namespace.Endpoint{Address: netip.MustParseAddr("198.51.100.11"), Port: 443})
	if got := callTCP(t, extension, "connect", host, uint64(namespaceHandle), 0, 128); got != StatusAccessDenied {
		t.Fatalf("policy-denied connect = %v", got)
	}
	if state.Resources().Len() != 2 {
		t.Fatalf("denied connect leaked resource count = %d", state.Resources().Len())
	}

	encodeGuestEndpoint(t, host.memory, 0, endpointFor(12, 4612))
	before = append([]byte(nil), host.memory...)
	if got := callTCP(t, extension, "connect", host, uint64(namespaceHandle), 0, uint64(len(host.memory)-32)); got != StatusInvalidArgument {
		t.Fatalf("short stream output = %v", got)
	}
	if !bytes.Equal(host.memory, before) || state.Resources().Len() != 2 {
		t.Fatal("rejected connect changed memory or resources")
	}
}

func TestGuestTCPConnectProgressEndpointsAndInstanceIsolation(t *testing.T) {
	clientExt, _, clientInstance, clientHost := newGuestTCPInstance(t, 21, 22)
	serverExt, _, serverInstance, serverHost := newGuestTCPInstance(t, 22, 21)
	defer clientInstance.Close()
	defer serverInstance.Close()
	clientState, _ := clientExt.instanceManager().ForInstance(clientInstance)
	serverState, _ := serverExt.instanceManager().ForInstance(serverInstance)

	clientNamespace := guestTCPNamespace(t, clientExt, clientHost)
	serverNamespace := guestTCPNamespace(t, serverExt, serverHost)
	serverEndpoint := endpointFor(22, 4622)
	listener := guestTCPListen(t, serverExt, serverHost, serverNamespace, serverEndpoint, 64)

	encodeGuestEndpoint(t, clientHost.memory, 0, serverEndpoint)
	if got := callTCP(t, clientExt, "connect", clientHost, uint64(clientNamespace), 0, 64); got != StatusInProgress {
		t.Fatalf("connect = %v", got)
	}
	stream, local, remote := decodeGuestTCPStream(t, clientHost.memory, 64)
	if local.Address != endpointFor(21, 0).Address || local.Port < 49152 || remote != serverEndpoint {
		t.Fatalf("connect descriptor local=%+v remote=%+v", local, remote)
	}
	if got := callTCP(t, clientExt, "finish_connect", clientHost, uint64(stream)); got != StatusInProgress {
		t.Fatalf("initial finish_connect = %v", got)
	}
	if got := callTCP(t, serverExt, "finish_connect", serverHost, uint64(stream)); got != StatusBadHandle {
		t.Fatalf("cross-instance stream = %v", got)
	}
	encodeGuestEndpoint(t, serverHost.memory, 0, endpointFor(22, 4623))
	if got := callTCP(t, serverExt, "listen", serverHost, uint64(clientNamespace), 0, 160); got != StatusBadHandle {
		t.Fatalf("cross-instance namespace = %v", got)
	}

	transferGuestUDP(t, clientState, serverState)
	transferGuestUDP(t, serverState, clientState)
	transferGuestUDP(t, clientState, serverState)
	if got := callTCP(t, clientExt, "finish_connect", clientHost, uint64(stream)); got != StatusOK {
		t.Fatalf("completed finish_connect = %v", got)
	}
	if snapshot := serverState.Readiness().Snapshot(); snapshot.Registrations != 2 {
		t.Fatalf("server readiness before accept = %+v", snapshot)
	}
	if err := clientState.CloseHandle(stream, resource.KindTCPStream); err != nil {
		t.Fatalf("close stream for stale check: %v", err)
	}
	if got := callTCP(t, clientExt, "finish_connect", clientHost, uint64(stream)); got != StatusBadHandle {
		t.Fatalf("stale finish_connect = %v", got)
	}
	if err := serverState.CloseHandle(listener, resource.KindTCPListener); err != nil {
		t.Fatalf("close listener: %v", err)
	}
}

func TestGuestTCPConnectRollsBackInvalidBackendDescriptor(t *testing.T) {
	stream := &invalidDescriptorStream{}
	backend := &invalidDescriptorNamespace{stream: stream}
	manager, err := instance.NewManagerConfigured(instance.Config{
		Limits:    quota.Limits{Resources: 3, TCPResources: 2},
		Readiness: readiness.Config{MaxRegistrations: 3},
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return backend, nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	extension := &Extension{instances: manager}
	if err := extension.registerTCPModule(); err != nil {
		t.Fatalf("register TCP module: %v", err)
	}
	runtime := runtimeForExtension(t, extension)
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	inst, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	defer inst.Close()
	host := udpHostModule{instance: inst, memory: make([]byte, 256)}
	namespaceHandle := guestTCPNamespace(t, extension, host)
	encodeGuestEndpoint(t, host.memory, 0, endpointFor(31, 4631))
	before := append([]byte(nil), host.memory...)
	if got := callTCP(t, extension, "connect", host, uint64(namespaceHandle), 0, 64); got != StatusIO {
		t.Fatalf("invalid backend descriptor = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("invalid backend descriptor mutated output")
	}
	state, _ := manager.ForInstance(inst)
	if state.Resources().Len() != 1 || stream.closed.Load() != 1 {
		t.Fatalf("failed descriptor rollback resources=%d closes=%d", state.Resources().Len(), stream.closed.Load())
	}
}

func TestGuestTCPAcceptPartialIOShutdownCloseAndPoll(t *testing.T) {
	clientExt, _, clientInstance, clientHost := newGuestTCPInstance(t, 41, 42)
	serverExt, _, serverInstance, serverHost := newGuestTCPInstance(t, 42, 41)
	defer clientInstance.Close()
	defer serverInstance.Close()
	clientState, _ := clientExt.instanceManager().ForInstance(clientInstance)
	serverState, _ := serverExt.instanceManager().ForInstance(serverInstance)
	clientNamespace := guestTCPNamespace(t, clientExt, clientHost)
	serverNamespace := guestTCPNamespace(t, serverExt, serverHost)
	serverEndpoint := endpointFor(42, 4642)
	listener := guestTCPListen(t, serverExt, serverHost, serverNamespace, serverEndpoint, 64)

	before := append([]byte(nil), serverHost.memory...)
	if got := callTCP(t, serverExt, "accept", serverHost, uint64(listener), 128); got != StatusAgain {
		t.Fatalf("accept before connection = %v", got)
	}
	if !bytes.Equal(serverHost.memory, before) {
		t.Fatal("AGAIN accept mutated output")
	}

	encodeGuestEndpoint(t, clientHost.memory, 0, serverEndpoint)
	if got := callTCP(t, clientExt, "connect", clientHost, uint64(clientNamespace), 0, 64); got != StatusInProgress {
		t.Fatalf("connect = %v", got)
	}
	clientStream, clientLocal, _ := decodeGuestTCPStream(t, clientHost.memory, 64)
	transferGuestUDP(t, clientState, serverState)
	transferGuestUDP(t, serverState, clientState)
	transferGuestUDP(t, clientState, serverState)
	if got := callTCP(t, clientExt, "finish_connect", clientHost, uint64(clientStream)); got != StatusOK {
		t.Fatalf("finish_connect = %v", got)
	}

	writePollBudget(serverHost.memory, 256, 2, 2, 0, 0, 0, 0)
	if got := callTCP(t, serverExt, "poll", serverHost, 320, 2, 256, 400); got != StatusOK {
		t.Fatalf("TCP poll = %v", got)
	}
	report := decodePollResult(serverHost.memory, 400)
	events := decodePollEvents(serverHost.memory, 320, report[0])
	if report[1] > 2 || report[0] > 2 || !hasPollEvent(events, listener, namespace.ReadyAccept) {
		t.Fatalf("TCP poll report/events = %v %+v", report, events)
	}
	before = append([]byte(nil), serverHost.memory...)
	if got := callTCP(t, serverExt, "accept", serverHost, uint64(listener), uint64(len(serverHost.memory)-32)); got != StatusInvalidArgument {
		t.Fatalf("short accept output = %v", got)
	}
	if !bytes.Equal(serverHost.memory, before) {
		t.Fatal("rejected accept mutated output or consumed stream")
	}

	if got := callTCP(t, serverExt, "accept", serverHost, uint64(listener), 128); got != StatusOK {
		t.Fatalf("accept = %v", got)
	}
	serverStream, serverLocal, serverRemote := decodeGuestTCPStream(t, serverHost.memory, 128)
	if serverLocal != serverEndpoint || serverRemote != clientLocal {
		t.Fatalf("accepted descriptor local=%+v remote=%+v", serverLocal, serverRemote)
	}
	before = append([]byte(nil), serverHost.memory...)
	if got := callTCP(t, serverExt, "read", serverHost, uint64(serverStream), 512, 16, 600); got != StatusAgain {
		t.Fatalf("empty read = %v", got)
	}
	if !bytes.Equal(serverHost.memory, before) {
		t.Fatal("AGAIN read mutated payload or result")
	}

	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}
	copy(clientHost.memory[200:], payload)
	if got := callTCP(t, clientExt, "write", clientHost, uint64(clientStream), 200, uint64(len(payload)), 600); got != StatusOK {
		t.Fatalf("partial write = %v", got)
	}
	if written := binary.LittleEndian.Uint32(clientHost.memory[600:604]); written != 256 || binary.LittleEndian.Uint32(clientHost.memory[604:608]) != 0 {
		t.Fatalf("partial write metadata = %d/%#x", written, binary.LittleEndian.Uint32(clientHost.memory[604:608]))
	}
	unchangedResult := append([]byte(nil), clientHost.memory[600:608]...)
	if got := callTCP(t, clientExt, "write", clientHost, uint64(clientStream), 456, 44, 600); got != StatusAgain {
		t.Fatalf("full-buffer write = %v", got)
	}
	if !bytes.Equal(clientHost.memory[600:608], unchangedResult) {
		t.Fatal("AGAIN write mutated result")
	}
	transferGuestUDP(t, clientState, serverState)

	before = append([]byte(nil), serverHost.memory...)
	if got := callTCP(t, serverExt, "read", serverHost, uint64(serverStream), 700, 32, 716); got != StatusInvalidArgument {
		t.Fatalf("overlapping read outputs = %v", got)
	}
	if !bytes.Equal(serverHost.memory, before) {
		t.Fatal("rejected read mutated memory or consumed bytes")
	}
	if got := callTCP(t, serverExt, "read", serverHost, uint64(serverStream), 700, 31, 800); got != StatusOK {
		t.Fatalf("partial read = %v", got)
	}
	if read := binary.LittleEndian.Uint32(serverHost.memory[800:804]); read != 31 || !bytes.Equal(serverHost.memory[700:731], payload[:31]) {
		t.Fatalf("partial read metadata/payload = %d/%v", read, serverHost.memory[700:731])
	}
	if got := callTCP(t, serverExt, "read", serverHost, uint64(serverStream), 700, 256, 960); got != StatusOK {
		t.Fatalf("remaining read = %v", got)
	}
	if read := binary.LittleEndian.Uint32(serverHost.memory[960:964]); read != 225 || !bytes.Equal(serverHost.memory[700:925], payload[31:256]) {
		t.Fatalf("remaining read metadata/payload = %d", read)
	}
	transferGuestUDP(t, serverState, clientState)
	if got := callTCP(t, clientExt, "shutdown_write", clientHost, uint64(clientStream)); got != StatusOK {
		t.Fatalf("shutdown_write = %v", got)
	}
	transferGuestUDP(t, clientState, serverState)
	before = append([]byte(nil), serverHost.memory...)
	if got := callTCP(t, serverExt, "read", serverHost, uint64(serverStream), 700, 16, 960); got != StatusEOF {
		t.Fatalf("read after FIN = %v", got)
	}
	if !bytes.Equal(serverHost.memory, before) {
		t.Fatal("EOF read mutated payload or result")
	}

	if got := callTCP(t, serverExt, "close_listener", serverHost, uint64(serverStream)); got != StatusBadHandle {
		t.Fatalf("stream closed as listener = %v", got)
	}
	if got := callTCP(t, serverExt, "close_stream", serverHost, uint64(listener)); got != StatusBadHandle {
		t.Fatalf("listener closed as stream = %v", got)
	}
	if got := callTCP(t, serverExt, "close_stream", serverHost, uint64(serverStream)); got != StatusOK {
		t.Fatalf("close stream = %v", got)
	}
	if got := callTCP(t, serverExt, "close_stream", serverHost, uint64(serverStream)); got != StatusBadHandle {
		t.Fatalf("stale close stream = %v", got)
	}
	if got := callTCP(t, serverExt, "close_listener", serverHost, uint64(listener)); got != StatusOK {
		t.Fatalf("close listener = %v", got)
	}
	if got := callTCP(t, clientExt, "close_stream", clientHost, uint64(clientStream)); got != StatusOK {
		t.Fatalf("close client stream = %v", got)
	}
}

func TestGuestTCPAcceptRollsBackInvalidDescriptor(t *testing.T) {
	stream := &invalidDescriptorStream{}
	listener := &fixedTCPListener{stream: stream}
	backend := &invalidDescriptorNamespace{}
	manager, err := instance.NewManagerConfigured(instance.Config{
		Limits:           quota.Limits{Resources: 4, TCPResources: 2},
		Readiness:        readiness.Config{MaxRegistrations: 4},
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return backend, nil },
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	extension := &Extension{instances: manager}
	if err := extension.registerTCPModule(); err != nil {
		t.Fatalf("register TCP module: %v", err)
	}
	runtime := runtimeForExtension(t, extension)
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	inst, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	defer inst.Close()
	host := udpHostModule{instance: inst, memory: bytes.Repeat([]byte{0x5a}, 256)}
	state, _ := manager.ForInstance(inst)
	listenerHandle, err := state.Resources().Add(resource.KindTCPListener, listener)
	if err != nil {
		t.Fatalf("add listener: %v", err)
	}
	before := append([]byte(nil), host.memory...)
	if got := callTCP(t, extension, "accept", host, uint64(listenerHandle), 64); got != StatusIO {
		t.Fatalf("invalid accepted descriptor = %v", got)
	}
	if !bytes.Equal(host.memory, before) || stream.closed.Load() != 1 || state.Resources().Len() != 2 {
		t.Fatalf("accept rollback memory=%v closes=%d resources=%d", bytes.Equal(host.memory, before), stream.closed.Load(), state.Resources().Len())
	}
}

func TestGuestTCPStreamOperationsRaceClose(t *testing.T) {
	extension, _, instance, host := newGuestTCPInstance(t, 51, 52)
	namespaceHandle := guestTCPNamespace(t, extension, host)
	encodeGuestEndpoint(t, host.memory, 0, endpointFor(52, 4652))
	if got := callTCP(t, extension, "connect", host, uint64(namespaceHandle), 0, 64); got != StatusInProgress {
		t.Fatalf("connect = %v", got)
	}
	stream, _, _ := decodeGuestTCPStream(t, host.memory, 64)
	readFn := findTCPBinding(extension, "read")
	writeFn := findTCPBinding(extension, "write")
	finishFn := findTCPBinding(extension, "finish_connect")
	shutdownFn := findTCPBinding(extension, "shutdown_write")
	closeFn := findTCPBinding(extension, "close_stream")
	if readFn == nil || writeFn == nil || finishFn == nil || shutdownFn == nil || closeFn == nil {
		t.Fatal("missing TCP race binding")
	}
	var wait sync.WaitGroup
	var bad atomic.Int32
	for worker := range 8 {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			local := udpHostModule{instance: instance, memory: make([]byte, 128)}
			for iteration := range 100 {
				results := []uint64{0}
				switch (worker + iteration) % 4 {
				case 0:
					readFn(local, []uint64{uint64(stream), 0, 8, 32}, results)
				case 1:
					writeFn(local, []uint64{uint64(stream), 0, 8, 32}, results)
				case 2:
					finishFn(local, []uint64{uint64(stream)}, results)
				case 3:
					shutdownFn(local, []uint64{uint64(stream)}, results)
				}
				status := Status(wago.AsI32(results[0]))
				if status != StatusOK && status != StatusAgain && status != StatusInProgress && status != StatusEOF && status != StatusBadHandle && status != StatusInvalidState && status != StatusConnectionRefused && status != StatusConnectionAborted && status != StatusConnectionBroken {
					bad.Add(1)
					return
				}
			}
		}(worker)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		results := []uint64{0}
		closeFn(udpHostModule{instance: instance, memory: make([]byte, 8)}, []uint64{uint64(stream)}, results)
		status := Status(wago.AsI32(results[0]))
		if status != StatusOK && status != StatusBadHandle {
			bad.Add(1)
		}
	}()
	wait.Wait()
	if bad.Load() != 0 {
		t.Fatalf("unexpected concurrent TCP statuses = %d", bad.Load())
	}
	if got := callTCP(t, extension, "close_stream", host, uint64(stream)); got != StatusBadHandle {
		t.Fatalf("stream remained live after close race = %v", got)
	}
	_ = instance.Close()
}

func FuzzGuestTCPStreamMemory(f *testing.F) {
	extension, _, instance, host := newGuestTCPInstance(f, 61, 62)
	f.Cleanup(func() { _ = instance.Close() })
	namespaceHandle := guestTCPNamespace(f, extension, host)
	encodeGuestEndpoint(f, host.memory, 0, endpointFor(62, 4662))
	if got := callTCP(f, extension, "connect", host, uint64(namespaceHandle), 0, 64); got != StatusInProgress {
		f.Fatalf("connect = %v", got)
	}
	stream, _, _ := decodeGuestTCPStream(f, host.memory, 64)
	f.Add(make([]byte, 128), uint32(0), uint32(8), uint32(32), false)
	f.Add([]byte{1, 2, 3}, ^uint32(0), ^uint32(0), ^uint32(0), true)
	f.Fuzz(func(t *testing.T, memory []byte, payloadPtr, payloadLength, resultPtr uint32, write bool) {
		local := udpHostModule{instance: instance, memory: append([]byte(nil), memory...)}
		name := "read"
		if write {
			name = "write"
		}
		status := callTCP(t, extension, name, local, uint64(stream), uint64(payloadPtr), uint64(payloadLength), uint64(resultPtr))
		if status < StatusOK || status > StatusOther {
			t.Fatalf("invalid TCP stream status = %d", status)
		}
	})
}

func BenchmarkGuestTCPPoll(b *testing.B) {
	extension, _, instance, host := newGuestTCPInstance(b, 71, 72)
	defer instance.Close()
	writePollBudget(host.memory, 0, 1, 1, 0, 0, 0, 0)
	poll := findTCPBinding(extension, "poll")
	if poll == nil {
		b.Fatal("TCP poll binding missing")
	}
	params := []uint64{64, 1, 0, 128}
	results := []uint64{0}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		poll(&host, params, results)
		status := Status(wago.AsI32(results[0]))
		if status != StatusOK {
			b.Fatalf("TCP poll status = %v", status)
		}
	}
}

func newGuestTCPInstance(t testing.TB, localLast, gatewayLast byte) (*Extension, *wago.Runtime, *wago.Instance, udpHostModule) {
	t.Helper()
	return instantiateGuestTCP(t, guestTCPConfig(localLast, gatewayLast))
}

func instantiateGuestTCP(t testing.TB, config Config) (*Extension, *wago.Runtime, *wago.Instance, udpHostModule) {
	t.Helper()
	extension := Init(config)
	runtime := runtimeForExtension(t, extension)
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Compile empty TCP guest: %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate TCP guest: %v", err)
	}
	return extension, runtime, instance, udpHostModule{instance: instance, memory: make([]byte, 1024)}
}

func guestTCPConfig(localLast, gatewayLast byte) Config {
	limits := QuotaLimits{Resources: 4, TCPResources: 3, QueuedBytes: 1024, ServiceUnits: 64}
	ready := ReadinessConfig{MaxRegistrations: 4}
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	return Config{
		Policy: PolicyConfig{Rules: []PolicyRule{{
			Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportTCP},
			Directions: []PolicyDirection{PolicyInbound, PolicyOutbound}, Prefixes: []netip.Prefix{prefix},
		}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &StaticIPv4Config{
			Hostname: "guest-tcp", RandSeed: int64(localLast),
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, localLast}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, gatewayLast},
			IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, localLast}), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8},
			TCP:  TCPConfig{MaxListeners: 1, MaxOutboundStreams: 1, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4},
		},
	}
}

func guestTCPNamespace(t testing.TB, extension *Extension, host udpHostModule) resource.Handle {
	t.Helper()
	if got := callTCP(t, extension, "namespace_default", host, 0); got != StatusOK {
		t.Fatalf("TCP namespace_default = %v", got)
	}
	return resource.Handle(binary.LittleEndian.Uint64(host.memory[:8]))
}

func guestTCPListen(t testing.TB, extension *Extension, host udpHostModule, namespaceHandle resource.Handle, local namespace.Endpoint, out uint32) resource.Handle {
	t.Helper()
	encodeGuestEndpoint(t, host.memory, 0, local)
	if got := callTCP(t, extension, "listen", host, uint64(namespaceHandle), 0, uint64(out)); got != StatusOK {
		t.Fatalf("TCP listen %v = %v", local, got)
	}
	return resource.Handle(binary.LittleEndian.Uint64(host.memory[out : out+abi.HandleV1Size]))
}

func callRegisteredTCP(t testing.TB, runtime *wago.Runtime, name string, host udpHostModule, params ...uint64) Status {
	t.Helper()
	fn, ok := runtime.HostImports()[TCPModule+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("registered TCP binding %q missing", name)
	}
	results := []uint64{0}
	fn(host, params, results)
	return Status(wago.AsI32(results[0]))
}

func callTCP(t testing.TB, extension *Extension, name string, host udpHostModule, params ...uint64) Status {
	t.Helper()
	fn := findTCPBinding(extension, name)
	if fn == nil {
		t.Fatalf("TCP binding %q missing", name)
	}
	results := []uint64{0}
	fn(host, params, results)
	return Status(wago.AsI32(results[0]))
}

func findTCPBinding(extension *Extension, name string) wago.HostFunc {
	for _, candidate := range extension.tcpBindings() {
		if candidate.name == name {
			return candidate.fn
		}
	}
	return nil
}

func decodeGuestTCPStream(t testing.TB, memory []byte, ptr uint32) (resource.Handle, namespace.Endpoint, namespace.Endpoint) {
	t.Helper()
	handle := resource.Handle(binary.LittleEndian.Uint64(memory[ptr : ptr+8]))
	local, localOK := abi.DecodeEndpointV1(memory, ptr+8)
	remote, remoteOK := abi.DecodeEndpointV1(memory, ptr+40)
	if handle == 0 || !localOK || !remoteOK {
		t.Fatalf("invalid guest TCP descriptor handle=%v local=%+v/%v remote=%+v/%v", handle, local, localOK, remote, remoteOK)
	}
	return handle, local, remote
}

type invalidDescriptorNamespace struct {
	stream *invalidDescriptorStream
}

func (n *invalidDescriptorNamespace) Close() error                   { return nil }
func (n *invalidDescriptorNamespace) Readiness() namespace.Readiness { return namespace.ReadyWritable }
func (n *invalidDescriptorNamespace) TryBindUDP(namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, errors.ErrUnsupported)
}
func (n *invalidDescriptorNamespace) TryListenTCP(namespace.Endpoint) (nscore.Resource, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, errors.ErrUnsupported)
}
func (n *invalidDescriptorNamespace) TryConnectTCP(namespace.Endpoint) (nscore.Resource, namespace.Progress, error) {
	return n.stream, namespace.ProgressInProgress, nil
}
func (n *invalidDescriptorNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, errors.ErrUnsupported)
}
func (n *invalidDescriptorNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
}

type fixedTCPListener struct {
	stream namespace.TCPStream
}

func (l *fixedTCPListener) Close() error                      { return nil }
func (l *fixedTCPListener) Readiness() namespace.Readiness    { return namespace.ReadyAccept }
func (l *fixedTCPListener) LocalEndpoint() namespace.Endpoint { return endpointFor(41, 4641) }
func (l *fixedTCPListener) TryAccept() (nscore.Resource, namespace.Progress, error) {
	stream := l.stream
	l.stream = nil
	if stream == nil {
		return nil, namespace.ProgressWouldBlock, nil
	}
	return stream, namespace.ProgressDone, nil
}

type invalidDescriptorStream struct {
	closed atomic.Int32
}

func (s *invalidDescriptorStream) Close() error                       { s.closed.Add(1); return nil }
func (s *invalidDescriptorStream) Readiness() namespace.Readiness     { return 0 }
func (s *invalidDescriptorStream) LocalEndpoint() namespace.Endpoint  { return namespace.Endpoint{} }
func (s *invalidDescriptorStream) RemoteEndpoint() namespace.Endpoint { return endpointFor(31, 4631) }
func (s *invalidDescriptorStream) TryFinishConnect() (namespace.Progress, error) {
	return namespace.ProgressInProgress, nil
}
func (s *invalidDescriptorStream) TryRead([]byte) (namespace.IOResult, error) {
	return namespace.IOResult{State: namespace.IOWouldBlock}, nil
}
func (s *invalidDescriptorStream) TryWrite([]byte) (namespace.IOResult, error) {
	return namespace.IOResult{State: namespace.IOWouldBlock}, nil
}
func (s *invalidDescriptorStream) TryShutdownWrite() (namespace.Progress, error) {
	return namespace.ProgressDone, nil
}

var _ namespace.Namespace = (*invalidDescriptorNamespace)(nil)
var _ namespace.TCPListener = (*fixedTCPListener)(nil)
var _ namespace.TCPStream = (*invalidDescriptorStream)(nil)
