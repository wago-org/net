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
	module := selectiveTCPModule(t, runtime)
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()

	host := newExactHost(instance)
	if got := callTCP(t, runtime, host, "namespace_default", 0); got != wagonet.StatusNotSupported {
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
	module := selectiveTCPModule(t, runtime)
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := newExactHost(instance)
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
	if got := callTCP(t, runtime, host, "connect", namespaceHandle, 16, 64); got != wagonet.StatusAccessDenied {
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
	module := selectiveTCPModule(t, runtime)
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := newExactHost(instance)
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

func newExactHost(instance *wago.Instance) exactHost {
	return exactHost{instance: instance, memory: instance.Memory().Bytes()}
}

func callTCP(t testing.TB, _ *wago.Runtime, host exactHost, name string, params ...uint64) wagonet.Status {
	t.Helper()
	var values []wago.Value
	switch name {
	case "namespace_default":
		values = []wago.Value{wago.ValueI32(int32(params[0]))}
	case "connect", "listen":
		values = []wago.Value{wago.ValueI64(int64(params[0])), wago.ValueI32(int32(params[1])), wago.ValueI32(int32(params[2]))}
	default:
		t.Fatalf("unsupported TCP wrapper %q", name)
	}
	results, err := host.instance.Call(context.Background(), "tcp_"+name, values...)
	if err != nil || len(results) != 1 {
		t.Fatalf("TCP %s call = %v, %v", name, results, err)
	}
	return wagonet.Status(results[0].I32())
}

func selectiveTCPModule(t testing.TB, runtime *wago.Runtime) *wago.Module {
	t.Helper()
	importEntry := func(name string, typeIndex byte) []byte {
		return append(append(append(wasmtest.Name(wagonet.TCPModule), wasmtest.Name(name)...), 0x00), typeIndex)
	}
	module, err := runtime.Compile(wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(
			wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}),
			wasmtest.FuncType([]wasm.ValType{wasm.I64, wasm.I32, wasm.I32}, []wasm.ValType{wasm.I32}),
		)),
		wasmtest.Section(2, wasmtest.Vec(importEntry("namespace_default", 0), importEntry("connect", 1), importEntry("listen", 1))),
		wasmtest.Section(3, wasmtest.Vec(wasmtest.ULEB(0), wasmtest.ULEB(1), wasmtest.ULEB(1))),
		wasmtest.Section(5, wasmtest.Vec([]byte{0x00, 0x01})),
		wasmtest.Section(7, wasmtest.Vec(
			wasmtest.ExportEntry("tcp_namespace_default", 0, 3),
			wasmtest.ExportEntry("tcp_connect", 0, 4),
			wasmtest.ExportEntry("tcp_listen", 0, 5),
			wasmtest.ExportEntry("memory", 2, 0),
		)),
		wasmtest.Section(10, wasmtest.Vec(
			wasmtest.Code([]byte{0x20, 0x00, 0x10, 0x00, 0x0b}),
			wasmtest.Code([]byte{0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x10, 0x01, 0x0b}),
			wasmtest.Code([]byte{0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x10, 0x02, 0x0b}),
		)),
	))
	if err != nil {
		t.Fatalf("Compile selective TCP module: %v", err)
	}
	return module
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
