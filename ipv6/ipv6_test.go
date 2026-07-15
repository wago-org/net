package ipv6

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	ipv6abi "github.com/wago-org/net/internal/abi/ipv6"
	ipv6binding "github.com/wago-org/net/internal/binding/ipv6"
	"github.com/wago-org/net/internal/guest"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
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
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{wagonet.CapInfo, wagonet.CapIPv6}) {
		t.Fatalf("capabilities = %v", got)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.IPv6Module {
			imports++
		}
	}
	if imports != 3 {
		t.Fatalf("IPv6 imports = %d", imports)
	}
	for _, config := range []Config{
		{Address: netip.IPv6Unspecified(), PrefixBits: 64},
		{Address: netip.MustParseAddr("::ffff:192.0.2.1"), PrefixBits: 64},
		{Address: netip.MustParseAddr("2001:db8::1"), PrefixBits: 64, ScopeID: 1},
		{Address: netip.MustParseAddr("fe80::1"), PrefixBits: 64},
		{Address: netip.MustParseAddr("2001:db8::1"), PrefixBits: 0},
	} {
		if err := Register(wagonet.New(), WithConfig(config)); err != ErrInvalidConfig {
			t.Fatalf("invalid config %+v error = %v", config, err)
		}
	}
}

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m hostModule) Memory() []byte           { return m.memory }
func (m hostModule) Instance() *wago.Instance { return m.instance }

func TestActualLinkLocalConfigurationPreservesNumericScope(t *testing.T) {
	base := wagonet.Config{StaticIPv4: &wagonet.StaticIPv4Config{
		Hostname: "ipv6-link-local", RandSeed: 72, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 72},
		IPv4Address: netip.MustParseAddr("192.0.2.72"), MTU: 1500,
		Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
	}}
	network := wagonet.New(wagonet.WithConfig(base))
	address := netip.MustParseAddr("fe80::72")
	if err := Register(network, WithConfig(DefaultConfig(address, 64, 17))); err != nil {
		t.Fatal(err)
	}
	runtime, host := instantiate(t, network)
	if _, ok := runtime.HostImports()[wagonet.TCPModule+".namespace_default"]; ok {
		t.Fatal("IPv6 configuration exposed an unselected TCP import")
	}
	if got := callImport(t, runtime, host, "namespace_default", 200); got != guest.StatusOK {
		t.Fatalf("namespace = %v", got)
	}
	namespace := resource.Handle(binary.LittleEndian.Uint64(host.memory[200:208]))
	if got := callImport(t, runtime, host, "configuration", uint64(namespace), 32); got != guest.StatusOK {
		t.Fatalf("configuration = %v", got)
	}
	encoded := host.memory[32 : 32+ipv6abi.ConfigurationV1Size]
	if got := binary.LittleEndian.Uint32(encoded[4:8]); got != 17 {
		t.Fatalf("scope ID = %d", got)
	}
	if got := netip.AddrFrom16(*(*[16]byte)(encoded[8:24])); got != address {
		t.Fatalf("address = %v", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[36:40]); got != ipv6abi.ConfigurationFlagEnabled|ipv6abi.ConfigurationFlagLinkLocal {
		t.Fatalf("flags = %#x", got)
	}
}

func TestActualCheckedConfigurationAndDisabledTruth(t *testing.T) {
	base := wagonet.Config{StaticIPv4: &wagonet.StaticIPv4Config{
		Hostname: "ipv6-guest", RandSeed: 71, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 71}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.71"), MTU: 1500,
		Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
	}}
	configured := wagonet.New(wagonet.WithConfig(base))
	config := DefaultConfig(netip.MustParseAddr("2001:db8:71::1"), 64, 0)
	if err := Register(configured, WithConfig(config)); err != nil {
		t.Fatal(err)
	}
	runtime, host := instantiate(t, configured)
	if got := callImport(t, runtime, host, "namespace_default", 200); got != guest.StatusOK {
		t.Fatalf("namespace = %v", got)
	}
	namespace := resource.Handle(binary.LittleEndian.Uint64(host.memory[200:208]))
	if got := callImport(t, runtime, host, "configuration", uint64(namespace), 32); got != guest.StatusOK {
		t.Fatalf("configuration = %v", got)
	}
	encoded := host.memory[32 : 32+ipv6abi.ConfigurationV1Size]
	if got := binary.LittleEndian.Uint32(encoded[32:36]); got != 64 {
		t.Fatalf("prefix bits = %d", got)
	}
	if got := ipv6ns.Transports(binary.LittleEndian.Uint32(encoded[40:44])); got != ipv6ns.TransportTCPConnect|ipv6ns.TransportTCPListen {
		t.Fatalf("transport flags = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(encoded[44:48]); got != 1500 {
		t.Fatalf("MTU = %d", got)
	}

	disabled := wagonet.New(wagonet.WithConfig(base))
	if err := Register(disabled); err != nil {
		t.Fatal(err)
	}
	runtime2, host2 := instantiate(t, disabled)
	if callImport(t, runtime2, host2, "namespace_default", 200) != guest.StatusOK {
		t.Fatal("disabled namespace discovery")
	}
	namespace = resource.Handle(binary.LittleEndian.Uint64(host2.memory[200:208]))
	for i := 32; i < 32+int(ipv6abi.ConfigurationV1Size); i++ {
		host2.memory[i] = 0xa5
	}
	before := append([]byte(nil), host2.memory...)
	if got := callImport(t, runtime2, host2, "configuration", uint64(namespace), 32); got != guest.StatusNotSupported || !bytes.Equal(before, host2.memory) {
		t.Fatalf("disabled configuration = %v mutated=%v", got, !bytes.Equal(before, host2.memory))
	}
}

func instantiate(t testing.TB, network *wagonet.Network) (*wago.Runtime, hostModule) {
	t.Helper()
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return runtime, hostModule{instance: instance, memory: make([]byte, 256)}
}

func callImport(t testing.TB, runtime *wago.Runtime, host hostModule, name string, params ...uint64) guest.Status {
	t.Helper()
	function, ok := runtime.HostImports()[ipv6binding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("IPv6 import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}
