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
	"github.com/wago-org/wago/tests/wasmtest"
)

func TestRegisterExposesOnlyDNSAndSharedCore(t *testing.T) {
	network := wagonet.New()
	if err := dns.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}

	runtime := wago.NewRuntime()
	if err := loadNetwork(runtime, network); err != nil {
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
	if hasImport(runtime, wagonet.TCPModule, "namespace_default") {
		t.Fatal("TCP import exposed by DNS-only registration")
	}
	if hasImport(runtime, wagonet.UDPModule, "namespace_default") {
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
	if err := dns.Register(network, dns.AllowSuffixes()); !errors.Is(err, dns.ErrInvalidOption) {
		t.Fatalf("empty suffix helper = %v", err)
	}
	for _, resolver := range []string{"not-an-address", "127.0.0.1"} {
		if err := dns.Register(network, dns.Resolver(resolver)); !errors.Is(err, dns.ErrInvalidResolver) {
			t.Fatalf("invalid resolver %q = %v", resolver, err)
		}
	}
	if err := dns.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := dns.Register(network); !errors.Is(err, wagonet.ErrProtocolAlreadyRegistered) {
		t.Fatalf("duplicate registration = %v", err)
	}
	runtime := wago.NewRuntime()
	if err := loadNetwork(runtime, network); err != nil {
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
	if err := loadNetwork(runtime, network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if !hasImport(runtime, wagonet.DNSModule, "namespace_default") {
		t.Fatal("selective DNS namespace binding missing")
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
	if err := loadNetwork(runtime, network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module, err := compileImportHarness(runtime)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := exactHost{instance: instance, memory: instance.Memory().Bytes()}
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

func TestDefaultDNSStorageFitsSharedDefaultsAndStopsAtEightQueries(t *testing.T) {
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{StaticIPv4: selectiveStaticIPv4()}))
	if err := dns.Register(network, dns.Resolver("192.0.2.53")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := loadNetwork(runtime, network); err != nil {
		t.Fatalf("Use: %v", err)
	}
	module, err := compileImportHarness(runtime)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer instance.Close()
	host := exactHost{instance: instance, memory: instance.Memory().Bytes()}
	if got := callDNS(t, runtime, host, "namespace_default", 900); got != wagonet.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[900:908])
	for query := 0; query < 8; query++ {
		request := dnsns.Request{Name: "query" + string(rune('a'+query)) + ".example", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
		if !dnsabi.EncodeDNSQueryV1(host.memory, 0, request) {
			t.Fatalf("encode query %d", query)
		}
		if got := callDNS(t, runtime, host, "resolve", namespaceHandle, 0, 300); got != wagonet.StatusInProgress {
			t.Fatalf("resolve %d = %v", query, got)
		}
	}
	request := dnsns.Request{Name: "ninth.example", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	if !dnsabi.EncodeDNSQueryV1(host.memory, 0, request) {
		t.Fatal("encode ninth query")
	}
	if got := callDNS(t, runtime, host, "resolve", namespaceHandle, 0, 300); got != wagonet.StatusResourceLimit {
		t.Fatalf("ninth resolve = %v", got)
	}
}

func TestDNSRegistrationLeavesTCPAndUDPImportsUnresolved(t *testing.T) {
	network := wagonet.New()
	if err := dns.Register(network); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runtime := wago.NewRuntime()
	if err := loadNetwork(runtime, network); err != nil {
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

func callDNS(t testing.TB, _ *wago.Runtime, host exactHost, name string, params ...uint64) wagonet.Status {
	t.Helper()
	results, err := host.instance.Invoke(name, params...)
	if err != nil || len(results) != 1 {
		t.Fatalf("DNS import %q = %v, %v", name, results, err)
	}
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
