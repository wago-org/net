package dhcpv6

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	dhcpabi "github.com/wago-org/net/internal/abi/dhcpv6"
	dhcpbinding "github.com/wago-org/net/internal/binding/dhcpv6"
	"github.com/wago-org/net/internal/guest"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/resource"
	"github.com/wago-org/net/ipv6"
	wago "github.com/wago-org/wago"
)

func TestSelectiveSurfaceAndActualLifecycle(t *testing.T) {
	if wagonet.DHCPv6OperationsV1Size != dhcpabi.OperationsV1Size || wagonet.DHCPv6ConfigurationV1Size != dhcpabi.ConfigurationV1Size {
		t.Fatal("public DHCPv6 ABI constants drifted")
	}
	limits := wagonet.QuotaLimits{Resources: 3, IPv6Resources: 1, DHCPv6Resources: 1, DHCPv6Work: 1, QueuedBytes: 1 << 16, ServiceUnits: 32}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 3}
	base := wagonet.Config{Limits: &limits, Readiness: &ready, StaticIPv4: &wagonet.StaticIPv4Config{
		Hostname: "dhcp6-guest", RandSeed: 91, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 91}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
		IPv4Address: netip.MustParseAddr("192.0.2.91"), MTU: 1500, Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4},
	}}
	network := wagonet.New(wagonet.WithConfig(base))
	if err := ipv6.Register(network, ipv6.WithConfig(ipv6.DefaultConfig(netip.MustParseAddr("fe80::91"), 64, 9))); err != nil {
		t.Fatal(err)
	}
	if err := Register(network); err != nil {
		t.Fatal(err)
	}
	runtime, host := instantiate(t, network)
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{wagonet.CapDHCPv6, wagonet.CapInfo, wagonet.CapIPv6}) {
		t.Fatalf("capabilities=%v", got)
	}
	if status := call(t, runtime, host, "namespace_default", 400); status != guest.StatusOK {
		t.Fatalf("namespace=%v", status)
	}
	namespace := resource.Handle(binary.LittleEndian.Uint64(host.memory[400:408]))
	if status := call(t, runtime, host, "operations", uint64(namespace), 360); status != guest.StatusOK || dhcpns.Operations(binary.LittleEndian.Uint32(host.memory[360:364])) != dhcpns.SupportedOperations {
		t.Fatalf("operations=%v", status)
	}
	copy(host.memory[320:328], bytes.Repeat([]byte{0xa5}, 8))
	before := append([]byte(nil), host.memory[320:328]...)
	if status := call(t, runtime, host, "start", uint64(namespace), uint64(dhcpns.OperationRenew), 320); status != guest.StatusNotSupported || !bytes.Equal(before, host.memory[320:328]) {
		t.Fatalf("unsupported=%v", status)
	}
	if status := call(t, runtime, host, "start", uint64(namespace), uint64(dhcpns.OperationAcquire), 320); status != guest.StatusInProgress {
		t.Fatalf("start=%v", status)
	}
	lease := resource.Handle(binary.LittleEndian.Uint64(host.memory[320:328]))
	if status := call(t, runtime, host, "close", uint64(namespace)); status != guest.StatusBadHandle {
		t.Fatalf("wrong-kind=%v", status)
	}
	if status := call(t, runtime, host, "cancel", uint64(lease)); status != guest.StatusOK {
		t.Fatalf("cancel=%v", status)
	}
	if status := call(t, runtime, host, "close", uint64(lease)); status != guest.StatusOK {
		t.Fatalf("close=%v", status)
	}
	if status := call(t, runtime, host, "close", uint64(lease)); status != guest.StatusBadHandle {
		t.Fatalf("stale=%v", status)
	}
}

func TestDisabledWithoutIPv6AndDenyWins(t *testing.T) {
	base := wagonet.Config{StaticIPv4: &wagonet.StaticIPv4Config{Hostname: "dhcp6-disabled", RandSeed: 92, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 92}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, IPv4Address: netip.MustParseAddr("192.0.2.92"), MTU: 1500, Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2}}}
	network := wagonet.New(wagonet.WithConfig(base))
	if err := Register(network); err != nil {
		t.Fatal(err)
	}
	runtime, host := instantiate(t, network)
	if call(t, runtime, host, "namespace_default", 400) != guest.StatusOK {
		t.Fatal("namespace")
	}
	namespace := resource.Handle(binary.LittleEndian.Uint64(host.memory[400:408]))
	copy(host.memory[360:364], []byte{0xa5, 0xa5, 0xa5, 0xa5})
	before := append([]byte(nil), host.memory[360:364]...)
	if status := call(t, runtime, host, "operations", uint64(namespace), 360); status != guest.StatusNotSupported || !bytes.Equal(before, host.memory[360:364]) {
		t.Fatalf("disabled=%v", status)
	}
	compiled, err := policy.Compile(policy.Merge(defaultAuthority(), policy.Config{Rules: []policy.Rule{{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("ff02::1:2"), 128)}}}}))
	if err != nil {
		t.Fatal(err)
	}
	if compiled.CheckEndpoint(policy.OperationDHCPv6ClientSend, netip.MustParseAddr("ff02::1:2"), 547) {
		t.Fatal("caller deny lost")
	}
}

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (h hostModule) Memory() []byte           { return h.memory }
func (h hostModule) Instance() *wago.Instance { return h.instance }
func instantiate(t testing.TB, network *wagonet.Network) (*wago.Runtime, hostModule) {
	t.Helper()
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	module, err := runtime.Compile([]byte{0, 0x61, 0x73, 0x6d, 1, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return runtime, hostModule{instance: instance, memory: make([]byte, 4096)}
}
func call(t testing.TB, runtime *wago.Runtime, host hostModule, name string, params ...uint64) guest.Status {
	t.Helper()
	fn, ok := runtime.HostImports()[dhcpbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("import %q missing", name)
	}
	var results [1]uint64
	fn(host, params, results[:])
	return guest.Status(int32(results[0]))
}
