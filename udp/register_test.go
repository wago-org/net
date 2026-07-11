package udp_test

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
	"github.com/wago-org/net/udp"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestRegisterExposesOnlyUDPAndSharedCore(t *testing.T) {
	network := wagonet.New()
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}

	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	wantCapabilities := []wago.Capability{wagonet.CapInfo, wagonet.CapUDP}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("Capabilities = %v, want %v", got, wantCapabilities)
	}
	imports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	wantImports := map[string]int{wagonet.Module: 1, wagonet.UDPModule: 6}
	if !reflect.DeepEqual(imports, wantImports) {
		t.Fatalf("import modules = %v, want %v", imports, wantImports)
	}
	if _, ok := runtime.HostImports()[wagonet.TCPModule+".namespace_default"]; ok {
		t.Fatal("TCP import exposed by UDP-only registration")
	}
	if _, ok := runtime.HostImports()[wagonet.DNSModule+".namespace_default"]; ok {
		t.Fatal("DNS import exposed by UDP-only registration")
	}
}

func TestRegisterRejectsDuplicateInvalidOptionFrozenAndNilNetwork(t *testing.T) {
	if err := udp.Register(nil); err == nil {
		t.Fatal("nil network registration unexpectedly succeeded")
	}

	network := wagonet.New()
	if err := udp.Register(network, nil); !errors.Is(err, udp.ErrInvalidOption) {
		t.Fatalf("nil option = %v", err)
	}
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := udp.Register(network); !errors.Is(err, wagonet.ErrProtocolAlreadyRegistered) {
		t.Fatalf("duplicate registration = %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if err := udp.Register(network); !errors.Is(err, wagonet.ErrProtocolRegistrationFrozen) {
		t.Fatalf("registration after freeze = %v", err)
	}
}

func TestSelectiveUDPBindingUsesExactSharedInstanceState(t *testing.T) {
	network := wagonet.New()
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module := selectiveUDPModule(t, runtime)
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()

	host := newExactHost(instance)
	if got := callUDP(t, runtime, host, "namespace_default", 0); got != wagonet.StatusNotSupported {
		t.Fatalf("namespace_default without configured namespace = %v", got)
	}
}

func TestDefaultUDPAllowsEphemeralUnicastAndDeniesServerSpecialAndCallerDeniedAuthority(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.77/32")
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportUDP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{denied},
		}}},
		StaticIPv4: selectiveStaticIPv4(),
	}))
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module := selectiveUDPModule(t, runtime)
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := newExactHost(instance)
	if got := callUDP(t, runtime, host, "namespace_default", 0); got != wagonet.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[:8])

	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.IPv4Unspecified(), Port: 8080}) {
		t.Fatal("encode server bind")
	}
	if got := callUDP(t, runtime, host, "bind", namespaceHandle, 16, 64); got != wagonet.StatusAccessDenied {
		t.Fatalf("default server bind = %v", got)
	}
	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.IPv4Unspecified()}) {
		t.Fatal("encode ephemeral bind")
	}
	if got := callUDP(t, runtime, host, "bind", namespaceHandle, 16, 64); got != wagonet.StatusOK {
		t.Fatalf("default ephemeral bind = %v", got)
	}
	socket := binary.LittleEndian.Uint64(host.memory[64:72])
	copy(host.memory[128:131], "udp")
	for _, test := range []struct {
		address string
		want    wagonet.Status
	}{
		{address: "192.0.2.20", want: wagonet.StatusOK},
		{address: "192.0.2.77", want: wagonet.StatusAccessDenied},
		{address: "224.0.0.1", want: wagonet.StatusAccessDenied},
		{address: "255.255.255.255", want: wagonet.StatusAccessDenied},
	} {
		if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.MustParseAddr(test.address), Port: 53}) {
			t.Fatalf("encode remote %s", test.address)
		}
		if got := callUDP(t, runtime, host, "send", socket, 128, 3, 16); got != test.want {
			t.Fatalf("send %s = %v, want %v", test.address, got, test.want)
		}
	}
}

func TestDefaultUDPStorageFitsSharedDefaultsAndStopsAtEightSockets(t *testing.T) {
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{StaticIPv4: selectiveStaticIPv4()}))
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module := selectiveUDPModule(t, runtime)
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := newExactHost(instance)
	if got := callUDP(t, runtime, host, "namespace_default", 0); got != wagonet.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[:8])
	if !abicore.EncodeEndpointV1(host.memory, 16, nscore.Endpoint{Address: netip.IPv4Unspecified()}) {
		t.Fatal("encode ephemeral bind")
	}
	for socket := 0; socket < 8; socket++ {
		if got := callUDP(t, runtime, host, "bind", namespaceHandle, 16, 64); got != wagonet.StatusOK {
			t.Fatalf("bind %d = %v", socket, got)
		}
	}
	if got := callUDP(t, runtime, host, "bind", namespaceHandle, 16, 64); got != wagonet.StatusResourceLimit {
		t.Fatalf("ninth bind = %v", got)
	}
}

func TestUDPRegistrationLeavesTCPAndDNSImportsUnresolved(t *testing.T) {
	network := wagonet.New()
	if err := udp.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}

	for _, test := range []struct {
		module     string
		capability wago.Capability
	}{
		{module: wagonet.TCPModule, capability: wagonet.CapTCP},
		{module: wagonet.DNSModule, capability: wagonet.CapDNS},
	} {
		module, err := runtime.Compile(namespaceImportModule(test.module))
		if err == nil {
			var instance *wago.Instance
			instance, err = runtime.Instantiate(context.Background(), module, wago.WithPolicy(wago.Policy{AllowedCapabilities: []wago.Capability{test.capability}}))
			if instance != nil {
				_ = instance.Close()
			}
		}
		if err == nil {
			t.Fatalf("unregistered %s import unexpectedly resolved", test.module)
		}
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

func callUDP(t testing.TB, _ *wago.Runtime, host exactHost, name string, params ...uint64) wagonet.Status {
	t.Helper()
	var values []wago.Value
	switch name {
	case "namespace_default":
		values = []wago.Value{wago.ValueI32(int32(params[0]))}
	case "bind":
		values = []wago.Value{wago.ValueI64(int64(params[0])), wago.ValueI32(int32(params[1])), wago.ValueI32(int32(params[2]))}
	case "send":
		values = []wago.Value{wago.ValueI64(int64(params[0])), wago.ValueI32(int32(params[1])), wago.ValueI32(int32(params[2])), wago.ValueI32(int32(params[3]))}
	default:
		t.Fatalf("unsupported UDP wrapper %q", name)
	}
	results, err := host.instance.Call(context.Background(), "udp_"+name, values...)
	if err != nil || len(results) != 1 {
		t.Fatalf("UDP %s call = %v, %v", name, results, err)
	}
	return wagonet.Status(results[0].I32())
}

func selectiveUDPModule(t testing.TB, runtime *wago.Runtime) *wago.Module {
	t.Helper()
	importEntry := func(name string, typeIndex byte) []byte {
		return append(append(append(wasmtest.Name(wagonet.UDPModule), wasmtest.Name(name)...), 0x00), typeIndex)
	}
	module, err := runtime.Compile(wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(
			wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}),
			wasmtest.FuncType([]wasm.ValType{wasm.I64, wasm.I32, wasm.I32}, []wasm.ValType{wasm.I32}),
			wasmtest.FuncType([]wasm.ValType{wasm.I64, wasm.I32, wasm.I32, wasm.I32}, []wasm.ValType{wasm.I32}),
		)),
		wasmtest.Section(2, wasmtest.Vec(importEntry("namespace_default", 0), importEntry("bind", 1), importEntry("send", 2))),
		wasmtest.Section(3, wasmtest.Vec(wasmtest.ULEB(0), wasmtest.ULEB(1), wasmtest.ULEB(2))),
		wasmtest.Section(5, wasmtest.Vec([]byte{0x00, 0x01})),
		wasmtest.Section(7, wasmtest.Vec(
			wasmtest.ExportEntry("udp_namespace_default", 0, 3),
			wasmtest.ExportEntry("udp_bind", 0, 4),
			wasmtest.ExportEntry("udp_send", 0, 5),
			wasmtest.ExportEntry("memory", 2, 0),
		)),
		wasmtest.Section(10, wasmtest.Vec(
			wasmtest.Code([]byte{0x20, 0x00, 0x10, 0x00, 0x0b}),
			wasmtest.Code([]byte{0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x10, 0x01, 0x0b}),
			wasmtest.Code([]byte{0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0x20, 0x03, 0x10, 0x02, 0x0b}),
		)),
	))
	if err != nil {
		t.Fatalf("Compile selective UDP module: %v", err)
	}
	return module
}

func selectiveStaticIPv4() *wagonet.StaticIPv4Config {
	return &wagonet.StaticIPv4Config{
		Hostname: "udp-default", RandSeed: 12,
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
