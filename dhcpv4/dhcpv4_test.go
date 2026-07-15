package dhcpv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	dhcpabi "github.com/wago-org/net/internal/abi/dhcpv4"
	dhcpbinding "github.com/wago-org/net/internal/binding/dhcpv4"
	"github.com/wago-org/net/internal/guest"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

func TestSelectiveRegistrationAndFiniteConfiguration(t *testing.T) {
	network := wagonet.New()
	if err := Register(network); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{wagonet.CapDHCPv4, wagonet.CapInfo}) {
		t.Fatalf("capabilities = %v", got)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.DHCPv4Module {
			imports++
		}
	}
	if imports != 7 {
		t.Fatalf("DHCPv4 imports = %d", imports)
	}
}

func TestServerRequiresExplicitFinitePoolAndCopiesConfig(t *testing.T) {
	server := Server{Address: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 2}
	network := wagonet.New()
	if err := Register(network, WithServer(server)); err != nil {
		t.Fatal(err)
	}
	server.MaxClients = 0
	if err := Register(wagonet.New(), WithServer(server)); err != ErrInvalidServer {
		t.Fatalf("zero pool error = %v", err)
	}

	base := Server{
		Address: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 2,
	}
	for _, test := range []struct {
		name   string
		mutate func(*Server)
	}{
		{name: "server network", mutate: func(server *Server) { server.Address = netip.MustParseAddr("192.0.2.0") }},
		{name: "server broadcast", mutate: func(server *Server) { server.Address = netip.MustParseAddr("192.0.2.255") }},
		{name: "gateway network", mutate: func(server *Server) { server.Gateway = netip.MustParseAddr("192.0.2.0") }},
		{name: "gateway broadcast", mutate: func(server *Server) { server.Gateway = netip.MustParseAddr("192.0.2.255") }},
		{name: "DNS network", mutate: func(server *Server) { server.DNS = netip.MustParseAddr("192.0.2.0") }},
		{name: "DNS broadcast", mutate: func(server *Server) { server.DNS = netip.MustParseAddr("192.0.2.255") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := base
			test.mutate(&invalid)
			if err := Register(wagonet.New(), WithServer(invalid)); err != ErrInvalidConfig {
				t.Fatalf("non-host server configuration error = %v", err)
			}
		})
	}
}

func TestZeroConfigTruthfullyDisablesBackendOperations(t *testing.T) {
	if err := Register(wagonet.New(), WithConfig(Config{})); err != nil {
		t.Fatalf("zero config registration = %v", err)
	}
}

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m hostModule) Memory() []byte           { return m.memory }
func (m hostModule) Instance() *wago.Instance { return m.instance }

func TestActualBackendExactLeaseLifecycleAndDenyWins(t *testing.T) {
	limits := wagonet.QuotaLimits{Resources: 3, DHCPv4Resources: 2, QueuedBytes: 2048, DHCPv4Work: 2, ServiceUnits: 16}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 3}
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportDHCPv4}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("255.255.255.255/32")}}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{Hostname: "dhcp-guest", RandSeed: 51, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 51}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, IPv4Address: netip.MustParseAddr("192.0.2.51"), MTU: 1500, Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2}},
	}))
	if err := Register(network); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	module, _ := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0})
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	host := hostModule{instance: instance, memory: make([]byte, 512)}
	if got := callImport(t, runtime, host, "namespace_default", 400); got != guest.StatusOK {
		t.Fatal(got)
	}
	namespace := resource.Handle(binary.LittleEndian.Uint64(host.memory[400:408]))
	if !dhcpabi.EncodeRequestV1(host.memory, 0, dhcpns.Request{}) {
		t.Fatal("encode request")
	}
	before := append([]byte(nil), host.memory...)
	if got := callImport(t, runtime, host, "acquire", uint64(namespace), 0, 300); got != guest.StatusAccessDenied || !bytes.Equal(before, host.memory) {
		t.Fatalf("deny-wins acquire = %v mutated=%v", got, !bytes.Equal(before, host.memory))
	}

	allowed := wagonet.New(wagonet.WithConfig(wagonet.Config{Limits: &limits, Readiness: &ready, StaticIPv4: &wagonet.StaticIPv4Config{Hostname: "dhcp-allowed", RandSeed: 52, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 52}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, IPv4Address: netip.MustParseAddr("192.0.2.52"), MTU: 1500, Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2}}}))
	if err := Register(allowed); err != nil {
		t.Fatal(err)
	}
	runtime2 := wago.NewRuntime()
	if err := runtime2.Use(allowed); err != nil {
		t.Fatal(err)
	}
	module2, err := runtime2.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	instance2, err := runtime2.Instantiate(context.Background(), module2)
	if err != nil {
		t.Fatal(err)
	}
	defer instance2.Close()
	host2 := hostModule{instance: instance2, memory: make([]byte, 512)}
	if callImport(t, runtime2, host2, "namespace_default", 400) != guest.StatusOK {
		t.Fatal("namespace")
	}
	namespace = resource.Handle(binary.LittleEndian.Uint64(host2.memory[400:408]))
	dhcpabi.EncodeRequestV1(host2.memory, 0, dhcpns.Request{})
	if got := callImport(t, runtime2, host2, "acquire", uint64(namespace), 0, 300); got != guest.StatusInProgress {
		t.Fatalf("acquire = %v", got)
	}
	lease := resource.Handle(binary.LittleEndian.Uint64(host2.memory[300:308]))
	if got := callImport(t, runtime2, host2, "cancel", uint64(lease)); got != guest.StatusOK {
		t.Fatalf("cancel = %v", got)
	}
	if got := callImport(t, runtime2, host2, "result", uint64(lease), 0); got != guest.StatusCanceled {
		t.Fatalf("result = %v", got)
	}
	if got := callImport(t, runtime2, host2, "close", uint64(lease)); got != guest.StatusOK {
		t.Fatalf("close = %v", got)
	}
	if got := callImport(t, runtime2, host2, "close", uint64(lease)); got != guest.StatusBadHandle {
		t.Fatalf("stale close = %v", got)
	}
}

func callImport(t testing.TB, runtime *wago.Runtime, host hostModule, name string, params ...uint64) guest.Status {
	t.Helper()
	function, ok := runtime.HostImports()[dhcpbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("DHCPv4 import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}
