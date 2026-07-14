package icmpv6

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	icmpabi "github.com/wago-org/net/internal/abi/icmpv6"
	icmpbinding "github.com/wago-org/net/internal/binding/icmpv6"
	"github.com/wago-org/net/internal/guest"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/resource"
	"github.com/wago-org/net/ipv6"
	wago "github.com/wago-org/wago"
)

func TestSelectiveRegistrationSurface(t *testing.T) {
	if wagonet.ICMPv6EchoRequestV1Size != icmpabi.EchoRequestV1Size || wagonet.ICMPv6EchoResultV1Size != icmpabi.EchoResultV1Size || wagonet.ICMPv6NeighborKeyV1Size != icmpabi.NeighborKeyV1Size || wagonet.ICMPv6NeighborV1Size != icmpabi.NeighborV1Size || wagonet.ICMPv6OperationsV1Size != icmpabi.OperationsV1Size {
		t.Fatal("public ICMPv6 ABI constants drifted")
	}
	network := wagonet.New()
	if err := Register(network); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{wagonet.CapICMPv6, wagonet.CapInfo}) {
		t.Fatalf("capabilities = %v", got)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.ICMPv6Module {
			imports++
		}
	}
	if imports != 14 {
		t.Fatalf("ICMPv6 imports = %d", imports)
	}
	if err := Register(wagonet.New(), WithConfig(Config{})); err != nil {
		t.Fatalf("zero disabled config = %v", err)
	}
	invalid := DefaultConfig()
	invalid.MaxAttempts = 0
	if err := Register(wagonet.New(), WithConfig(invalid)); err != ErrInvalidOption {
		t.Fatalf("invalid config error = %v", err)
	}
}

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (module hostModule) Memory() []byte           { return module.memory }
func (module hostModule) Instance() *wago.Instance { return module.instance }

func TestCheckedSeedLookupEchoCancelAndDisabledTruth(t *testing.T) {
	base := wagonet.Config{StaticIPv4: &wagonet.StaticIPv4Config{
		Hostname: "icmpv6-guest", RandSeed: 81, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 81}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.81"), MTU: 1500,
		Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4},
	}}
	network := wagonet.New(wagonet.WithConfig(base))
	if err := ipv6.Register(network, ipv6.WithConfig(ipv6.DefaultConfig(netip.MustParseAddr("2001:db8:81::1"), 64, 0))); err != nil {
		t.Fatal(err)
	}
	if err := Register(network); err != nil {
		t.Fatal(err)
	}
	runtime, host := instantiate(t, network)
	if status := call(t, runtime, host, "namespace_default", 400); status != guest.StatusOK {
		t.Fatalf("namespace = %v", status)
	}
	namespace := resource.Handle(binary.LittleEndian.Uint64(host.memory[400:408]))
	if status := call(t, runtime, host, "operations", uint64(namespace), 360); status != guest.StatusOK || icmpns.Operations(binary.LittleEndian.Uint32(host.memory[360:364])) != icmpns.SupportedOperations {
		t.Fatalf("operations = %v %#x", status, binary.LittleEndian.Uint32(host.memory[360:364]))
	}
	neighbor := icmpns.Neighbor{Address: netip.MustParseAddr("2001:db8:81::2"), MAC: [6]byte{2, 0, 0, 0, 0, 82}}
	if !icmpabi.EncodeNeighborV1(host.memory, 32, neighbor) {
		t.Fatal("encode neighbor")
	}
	if status := call(t, runtime, host, "seed_neighbor", uint64(namespace), 32); status != guest.StatusOK {
		t.Fatalf("seed = %v", status)
	}
	if !icmpabi.EncodeNeighborKeyV1(host.memory, 96, icmpns.NeighborRequest{Address: neighbor.Address}) {
		t.Fatal("encode key")
	}
	if status := call(t, runtime, host, "lookup_neighbor", uint64(namespace), 96, 136); status != guest.StatusOK {
		t.Fatalf("lookup = %v", status)
	}
	got, ok := icmpabi.DecodeNeighborV1(host.memory, 136)
	if !ok || got != neighbor {
		t.Fatalf("neighbor = %+v %v", got, ok)
	}

	copy(host.memory[280:], "echo6")
	if !icmpabi.EncodeEchoRequestV1(host.memory, 200, nscore.Endpoint{Address: neighbor.Address}, 280, 5) {
		t.Fatal("encode echo")
	}
	if status := call(t, runtime, host, "echo", uint64(namespace), 200, 320); status != guest.StatusInProgress {
		t.Fatalf("echo = %v", status)
	}
	echo := resource.Handle(binary.LittleEndian.Uint64(host.memory[320:328]))
	if status := call(t, runtime, host, "close_neighbor", uint64(echo)); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind close = %v", status)
	}
	if status := call(t, runtime, host, "cancel_echo", uint64(echo)); status != guest.StatusOK {
		t.Fatalf("cancel = %v", status)
	}
	if status := call(t, runtime, host, "close_echo", uint64(echo)); status != guest.StatusOK {
		t.Fatalf("close = %v", status)
	}
	if status := call(t, runtime, host, "close_echo", uint64(echo)); status != guest.StatusBadHandle {
		t.Fatalf("stale close = %v", status)
	}
	if status := call(t, runtime, host, "remove_neighbor", uint64(namespace), 96); status != guest.StatusOK {
		t.Fatalf("remove = %v", status)
	}
	before := append([]byte(nil), host.memory[136:136+icmpabi.NeighborV1Size]...)
	if status := call(t, runtime, host, "lookup_neighbor", uint64(namespace), 96, 136); status != guest.StatusAgain || !bytes.Equal(before, host.memory[136:136+icmpabi.NeighborV1Size]) {
		t.Fatalf("missing lookup = %v mutated=%v", status, !bytes.Equal(before, host.memory[136:136+icmpabi.NeighborV1Size]))
	}

	disabled := wagonet.New(wagonet.WithConfig(base))
	if err := Register(disabled); err != nil {
		t.Fatal(err)
	}
	runtime2, host2 := instantiate(t, disabled)
	if call(t, runtime2, host2, "namespace_default", 400) != guest.StatusOK {
		t.Fatal("disabled namespace discovery")
	}
	namespace = resource.Handle(binary.LittleEndian.Uint64(host2.memory[400:408]))
	copy(host2.memory[360:364], []byte{0xa5, 0xa5, 0xa5, 0xa5})
	before = append([]byte(nil), host2.memory[360:364]...)
	if status := call(t, runtime2, host2, "operations", uint64(namespace), 360); status != guest.StatusNotSupported || !bytes.Equal(before, host2.memory[360:364]) {
		t.Fatalf("disabled operations = %v mutated=%v", status, !bytes.Equal(before, host2.memory[360:364]))
	}

	deniedBase := base
	deniedBase.Policy = wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv6},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(neighbor.Address, 128)},
	}}}
	denied := wagonet.New(wagonet.WithConfig(deniedBase))
	if err := ipv6.Register(denied, ipv6.WithConfig(ipv6.DefaultConfig(netip.MustParseAddr("2001:db8:81::1"), 64, 0))); err != nil {
		t.Fatal(err)
	}
	if err := Register(denied); err != nil {
		t.Fatal(err)
	}
	runtime3, host3 := instantiate(t, denied)
	if call(t, runtime3, host3, "namespace_default", 400) != guest.StatusOK {
		t.Fatal("denied namespace discovery")
	}
	namespace = resource.Handle(binary.LittleEndian.Uint64(host3.memory[400:408]))
	if !icmpabi.EncodeNeighborV1(host3.memory, 32, neighbor) {
		t.Fatal("encode denied neighbor")
	}
	if status := call(t, runtime3, host3, "seed_neighbor", uint64(namespace), 32); status != guest.StatusAccessDenied {
		t.Fatalf("caller deny lost to module default: %v", status)
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
	return runtime, hostModule{instance: instance, memory: make([]byte, 512)}
}

func call(t testing.TB, runtime *wago.Runtime, host hostModule, name string, params ...uint64) guest.Status {
	t.Helper()
	function, ok := runtime.HostImports()[icmpbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("ICMPv6 import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}
