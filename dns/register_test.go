package dns_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	dnsabi "github.com/wago-org/net/internal/abi/dns"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

func TestRegisterExposesOnlyDNSAndSharedCore(t *testing.T) {
	network := wagonet.New()
	if err := dns.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}

	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	wantCapabilities := []wago.Capability{wagonet.CapDNS, wagonet.CapInfo}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("Capabilities = %v, want %v", got, wantCapabilities)
	}
	imports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	wantImports := map[string]int{wagonet.Module: 1, wagonet.DNSModule: 6}
	if !reflect.DeepEqual(imports, wantImports) {
		t.Fatalf("import modules = %v, want %v", imports, wantImports)
	}
	if _, ok := runtime.HostImports()[wagonet.TCPModule+".namespace_default"]; ok {
		t.Fatal("TCP import exposed by DNS-only registration")
	}
	if _, ok := runtime.HostImports()[wagonet.UDPModule+".namespace_default"]; ok {
		t.Fatal("UDP import exposed by DNS-only registration")
	}
}

func TestRegisterRejectsDuplicateInvalidOptionResolverFrozenAndNilNetwork(t *testing.T) {
	if err := dns.Register(nil); err == nil {
		t.Fatal("nil network registration unexpectedly succeeded")
	}

	network := wagonet.New()
	if err := dns.Register(network, nil); !errors.Is(err, dns.ErrInvalidOption) {
		t.Fatalf("nil option = %v", err)
	}
	if err := dns.Register(network, dns.Resolver("not-an-address")); !errors.Is(err, dns.ErrInvalidResolver) {
		t.Fatalf("invalid resolver = %v", err)
	}
	if err := dns.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := dns.Register(network); !errors.Is(err, wagonet.ErrProtocolAlreadyRegistered) {
		t.Fatalf("duplicate registration = %v", err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if err := dns.Register(network); !errors.Is(err, wagonet.ErrProtocolRegistrationFrozen) {
		t.Fatalf("registration after freeze = %v", err)
	}
}

func TestSelectiveDNSBindingUsesExactSharedInstanceState(t *testing.T) {
	network := wagonet.New()
	if err := dns.Register(network); err != nil {
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

	fn, ok := runtime.HostImports()[wagonet.DNSModule+".namespace_default"].(wago.HostFunc)
	if !ok {
		t.Fatal("selective DNS namespace binding missing")
	}
	host := exactHost{instance: instance, memory: make([]byte, wagonet.HandleV1Size)}
	results := []uint64{0}
	fn(host, []uint64{0}, results)
	if got := wagonet.Status(wago.AsI32(results[0])); got != wagonet.StatusNotSupported {
		t.Fatalf("namespace_default without configured namespace = %v", got)
	}
}

func TestDefaultDNSResolverAllowsFiniteQueriesAndCallerDenyWins(t *testing.T) {
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportDNS},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, DNSSuffixes: []string{"blocked.example"},
		}}},
		StaticIPv4: selectiveStaticIPv4(),
	}))
	if err := dns.Register(network, dns.Resolver("192.0.2.53")); err != nil {
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
	host := exactHost{instance: instance, memory: make([]byte, 1024)}
	if got := callDNS(t, runtime, host, "namespace_default", 900); got != wagonet.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[900:908])

	for _, test := range []struct {
		name string
		want wagonet.Status
	}{
		{name: "example.com", want: wagonet.StatusInProgress},
		{name: "blocked.example", want: wagonet.StatusAccessDenied},
	} {
		request := dnsns.Request{Name: test.name, Types: dnsns.RecordsA | dnsns.RecordsAAAA}
		if !dnsabi.EncodeDNSQueryV1(host.memory, 0, request) {
			t.Fatalf("encode query %s", test.name)
		}
		if got := callDNS(t, runtime, host, "resolve", namespaceHandle, 0, 300); got != test.want {
			t.Fatalf("resolve %s = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestDNSRegistrationLeavesTCPAndUDPImportsUnresolved(t *testing.T) {
	network := wagonet.New()
	if err := dns.Register(network); err != nil {
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
		{module: wagonet.UDPModule, capability: wagonet.CapUDP},
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

func callDNS(t testing.TB, runtime *wago.Runtime, host exactHost, name string, params ...uint64) wagonet.Status {
	t.Helper()
	fn, ok := runtime.HostImports()[wagonet.DNSModule+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("DNS import %q missing", name)
	}
	results := []uint64{0}
	fn(host, params, results)
	return wagonet.Status(wago.AsI32(results[0]))
}

func selectiveStaticIPv4() *wagonet.StaticIPv4Config {
	return &wagonet.StaticIPv4Config{
		Hostname: "dns-default", RandSeed: 13,
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
