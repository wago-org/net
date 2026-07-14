package tcp_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	abicore "github.com/wago-org/net/internal/abi/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/tcp"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestRegisterExposesOnlyTCPAndSharedCore(t *testing.T) {
	network := wagonet.New()
	if err := tcp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}

	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	wantCapabilities := []wago.Capability{wagonet.CapInfo, wagonet.CapTCP}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("Capabilities = %v, want %v", got, wantCapabilities)
	}
	imports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	wantImports := map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11}
	if !reflect.DeepEqual(imports, wantImports) {
		t.Fatalf("import modules = %v, want %v", imports, wantImports)
	}
}

func TestRegisterRejectsDuplicateInvalidOptionFrozenAndNilNetwork(t *testing.T) {
	if err := tcp.Register(nil); err == nil {
		t.Fatal("nil network registration unexpectedly succeeded")
	}

	network := wagonet.New()
	if err := tcp.Register(network, nil); !errors.Is(err, tcp.ErrInvalidOption) {
		t.Fatalf("nil option = %v", err)
	}
	if err := tcp.Register(network, tcp.AllowListeners()); !errors.Is(err, tcp.ErrInvalidOption) {
		t.Fatalf("empty listener helper = %v", err)
	}
	if err := tcp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := tcp.Register(network); !errors.Is(err, wagonet.ErrProtocolAlreadyRegistered) {
		t.Fatalf("duplicate registration = %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if err := tcp.Register(network); !errors.Is(err, wagonet.ErrProtocolRegistrationFrozen) {
		t.Fatalf("registration after freeze = %v", err)
	}
}

func TestSelectiveTCPBindingUsesExactSharedInstanceState(t *testing.T) {
	network := wagonet.New()
	if err := tcp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Compile empty module: %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()

	fn, ok := runtime.HostImports()[wagonet.TCPModule+".namespace_default"].(wago.HostFunc)
	if !ok {
		t.Fatal("selective TCP namespace binding missing")
	}
	host := exactHost{instance: instance, memory: make([]byte, wagonet.HandleV1Size)}
	results := []uint64{0}
	fn(host, []uint64{0}, results)
	if got := wagonet.Status(wago.AsI32(results[0])); got != wagonet.StatusNotSupported {
		t.Fatalf("namespace_default without configured namespace = %v", got)
	}
}

func TestDefaultTCPAllowsFiniteOutboundAndDeniesListenerSpecialAndCallerDeniedAuthority(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.77/32")
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportTCP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{denied},
		}}},
		StaticIPv4: selectiveStaticIPv4(),
	}))
	if err := tcp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := exactHost{instance: instance, memory: make([]byte, 256)}
	namespace := callTCP(t, runtime, host, "namespace_default", 0)
	if namespace != wagonet.StatusOK {
		t.Fatalf("namespace_default = %v", namespace)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[:8])

	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.20"), Port: 443}) {
		t.Fatal("encode allowed remote")
	}
	if got := callTCP(t, runtime, host, "connect", namespaceHandle, 16, 64); got != wagonet.StatusInProgress {
		t.Fatalf("default outbound connect = %v", got)
	}
	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.77"), Port: 443}) {
		t.Fatal("encode denied remote")
	}
	if got := callTCP(t, runtime, host, "connect", namespaceHandle, 16, 64); got != wagonet.StatusAccessDenied {
		t.Fatalf("caller-denied connect = %v", got)
	}
	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 443}) {
		t.Fatal("encode loopback remote")
	}
	if got := callTCP(t, runtime, host, "connect", namespaceHandle, 16, 64); got != wagonet.StatusInvalidArgument {
		t.Fatalf("default loopback connect = %v", got)
	}
	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Port: 8080}) {
		t.Fatal("encode listener")
	}
	if got := callTCP(t, runtime, host, "listen", namespaceHandle, 16, 64); got != wagonet.StatusNotSupported {
		t.Fatalf("default listener = %v", got)
	}
}

func TestDefaultTCPStorageFitsSharedDefaultsAndStopsAtEightStreams(t *testing.T) {
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{StaticIPv4: selectiveStaticIPv4()}))
	if err := tcp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := exactHost{instance: instance, memory: make([]byte, 256)}
	if got := callTCP(t, runtime, host, "namespace_default", 0); got != wagonet.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[:8])
	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.20"), Port: 443}) {
		t.Fatal("encode remote")
	}
	for stream := 0; stream < 8; stream++ {
		if got := callTCP(t, runtime, host, "connect", namespaceHandle, 16, 64); got != wagonet.StatusInProgress {
			t.Fatalf("connect %d = %v", stream, got)
		}
	}
	if got := callTCP(t, runtime, host, "connect", namespaceHandle, 16, 64); got != wagonet.StatusResourceLimit {
		t.Fatalf("ninth connect = %v", got)
	}
}

func TestTCPRegistrationLeavesUDPImportUnresolved(t *testing.T) {
	network := wagonet.New()
	if err := tcp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}

	module, err := runtime.Compile(namespaceImportModule(wagonet.UDPModule))
	if err == nil {
		var instance *wago.Instance
		instance, err = runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{wagonet.CapUDP}}))
		if instance != nil {
			_ = instance.Close()
		}
	}
	if err == nil {
		t.Fatal("unregistered UDP import unexpectedly resolved")
	}
}

type exactHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h exactHost) Memory() []byte           { return h.memory }
func (h exactHost) Instance() *wago.Instance { return h.instance }

func callTCP(t testing.TB, runtime *wago.Runtime, host exactHost, name string, params ...uint64) wagonet.Status {
	t.Helper()
	fn, ok := runtime.HostImports()[wagonet.TCPModule+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("TCP import %q missing", name)
	}
	results := []uint64{0}
	fn(host, params, results)
	return wagonet.Status(wago.AsI32(results[0]))
}

func selectiveStaticIPv4() *wagonet.StaticIPv4Config {
	return &wagonet.StaticIPv4Config{
		Hostname: "tcp-default", RandSeed: 11,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 10}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.10"), MTU: 1500,
		Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4},
	}
}

func namespaceImportModule(module string) []byte {
	entry := append(append(wasmtest.Name(module), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	return wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(entry)),
	)
}
