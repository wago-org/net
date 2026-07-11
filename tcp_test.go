package net

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/wago-org/net/internal/abi"
	"github.com/wago-org/net/internal/instance"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

func TestTCPCreationBindingsStayUnregistered(t *testing.T) {
	extension := Init(guestTCPConfig(1, 2))
	runtime := runtimeForExtension(t, extension)
	if got := len(extension.tcpBindings()); got != 4 {
		t.Fatalf("checked TCP creation bindings = %d, want 4", got)
	}
	if _, ok := runtime.HostImports()[TCPModule+".namespace_default"]; ok {
		t.Fatal("incomplete TCP table was registered")
	}
	for _, capability := range runtime.Capabilities() {
		if capability == CapTCP {
			t.Fatal("incomplete TCP capability was advertised")
		}
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
		NamespaceFactory: func(*policy.Policy, *quota.Account) (namespace.Namespace, error) {
			return backend, nil
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	extension := &Extension{instances: manager}
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

func callTCP(t testing.TB, extension *Extension, name string, host udpHostModule, params ...uint64) Status {
	t.Helper()
	var fn wago.HostFunc
	for _, candidate := range extension.tcpBindings() {
		if candidate.name == name {
			fn = candidate.fn
			break
		}
	}
	if fn == nil {
		t.Fatalf("TCP binding %q missing", name)
	}
	results := []uint64{0}
	fn(host, params, results)
	return Status(wago.AsI32(results[0]))
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
func (n *invalidDescriptorNamespace) TryListenTCP(namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, errors.ErrUnsupported)
}
func (n *invalidDescriptorNamespace) TryConnectTCP(namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	return n.stream, namespace.ProgressInProgress, nil
}
func (n *invalidDescriptorNamespace) TryResolve(namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return nil, 0, namespace.Fail(namespace.FailureNotSupported, errors.ErrUnsupported)
}
func (n *invalidDescriptorNamespace) TryService(namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return namespace.ServiceReport{}, namespace.ProgressWouldBlock, nil
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
var _ namespace.TCPStream = (*invalidDescriptorStream)(nil)
