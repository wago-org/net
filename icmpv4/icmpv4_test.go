package icmpv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
	icmpabi "github.com/wago-org/net/internal/abi/icmpv4"
	icmpbinding "github.com/wago-org/net/internal/binding/icmpv4"
	"github.com/wago-org/net/internal/guest"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m hostModule) Memory() []byte           { return m.memory }
func (m hostModule) Instance() *wago.Instance { return m.instance }

func TestSelectiveICMPv4RegistrationAndActualBackendLifecycle(t *testing.T) {
	limits := wagonet.QuotaLimits{Resources: 2, ICMPv4Resources: 1, QueuedBytes: 64, ICMPv4Work: 1, ServiceUnits: 32}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 2}
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{
			Hostname: "icmpv4-guest", RandSeed: 17,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 17}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
			IPv4Address: netip.MustParseAddr("192.0.2.17"), MTU: 1500,
			Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
		},
	}))
	if err := Register(network, WithConfig(Config{MaxEchoes: 1, MaxPayloadBytes: 16, MaxAttempts: 1, RetryServiceAttempts: 1}), AllowLoopback()); err != nil {
		t.Fatal(err)
	}

	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.ICMPv4Module {
			imports++
		}
		if spec.Module == wagonet.UDPModule || spec.Module == wagonet.TCPModule || spec.Module == wagonet.DNSModule {
			t.Fatalf("ICMPv4 selection compiled unrelated module %q", spec.Module)
		}
	}
	if imports != 6 {
		t.Fatalf("ICMPv4 imports = %d, want 6", imports)
	}
	foundCapability := false
	for _, capability := range runtime.Capabilities() {
		foundCapability = foundCapability || capability == wagonet.CapICMPv4
	}
	if !foundCapability {
		t.Fatal("ICMPv4 capability not advertised")
	}

	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	host := hostModule{instance: instance, memory: make([]byte, 512)}
	if got := callImport(t, runtime, host, "namespace_default", 80); got != guest.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[80:88]))
	copy(host.memory[128:], "echo")
	if !icmpabi.EncodeEchoRequestV1(host.memory, 0, nscore.Endpoint{Address: netip.MustParseAddr("127.0.0.1")}, 128, 4) {
		t.Fatal("encode loopback echo request")
	}
	beforeLoopback := append([]byte(nil), host.memory[64:72]...)
	if got := callImport(t, runtime, host, "echo", uint64(namespaceHandle), 0, 64); got != guest.StatusInvalidArgument {
		t.Fatalf("loopback echo = %v", got)
	}
	if !bytes.Equal(host.memory[64:72], beforeLoopback) {
		t.Fatal("loopback echo mutated handle output")
	}
	if !icmpabi.EncodeEchoRequestV1(host.memory, 0, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.99")}, 128, 4) {
		t.Fatal("encode echo request")
	}
	if got := callImport(t, runtime, host, "echo", uint64(namespaceHandle), 0, 64); got != guest.StatusInProgress {
		t.Fatalf("echo = %v", got)
	}
	echoHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[64:72]))
	before := bytes.Repeat([]byte{0xa5}, 64)
	copy(host.memory[160:224], before)
	if got := callImport(t, runtime, host, "result", uint64(echoHandle), 160, 16, 176); got != guest.StatusAgain {
		t.Fatalf("pending result = %v", got)
	}
	if !bytes.Equal(host.memory[160:224], before) {
		t.Fatal("AGAIN result mutated guest outputs")
	}
	if got := callImport(t, runtime, host, "cancel", uint64(echoHandle)); got != guest.StatusOK {
		t.Fatalf("cancel = %v", got)
	}
	if got := callImport(t, runtime, host, "result", uint64(echoHandle), 160, 16, 176); got != guest.StatusCanceled {
		t.Fatalf("canceled result = %v", got)
	}
	if got := callImport(t, runtime, host, "close", uint64(echoHandle)); got != guest.StatusOK {
		t.Fatalf("close = %v", got)
	}
	if got := callImport(t, runtime, host, "result", uint64(echoHandle), 160, 16, 176); got != guest.StatusBadHandle {
		t.Fatalf("stale result = %v", got)
	}
}

func TestICMPv4DenyWinsAndCheckedMemoryPrecedesWork(t *testing.T) {
	limits := wagonet.QuotaLimits{Resources: 2, ICMPv4Resources: 1, QueuedBytes: 16, ICMPv4Work: 1, ServiceUnits: 8}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 2}
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{
			Hostname: "icmpv4-deny", RandSeed: 18,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 18}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
			IPv4Address: netip.MustParseAddr("192.0.2.18"), MTU: 1500,
			Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1},
		},
	}))
	if err := Register(network, WithConfig(Config{MaxEchoes: 1, MaxPayloadBytes: 4, MaxAttempts: 1, RetryServiceAttempts: 1})); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	module, _ := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	instance, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	host := hostModule{instance: instance, memory: make([]byte, 256)}
	if got := callImport(t, runtime, host, "namespace_default", 80); got != guest.StatusOK {
		t.Fatal(got)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[80:88])
	copy(host.memory[128:], "echo")
	if !icmpabi.EncodeEchoRequestV1(host.memory, 0, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.99")}, 128, 4) {
		t.Fatal("encode request")
	}
	if got := callImport(t, runtime, host, "echo", namespaceHandle, 0, 64); got != guest.StatusAccessDenied {
		t.Fatalf("deny-wins echo = %v", got)
	}
	before := append([]byte(nil), host.memory...)
	if got := callImport(t, runtime, host, "echo", namespaceHandle, 0, 20); got != guest.StatusInvalidArgument {
		t.Fatalf("overlapping checked echo = %v", got)
	}
	if !bytes.Equal(before, host.memory) {
		t.Fatal("invalid echo mutated memory")
	}
}

func TestICMPv4OptionsAreFiniteAndConspicuous(t *testing.T) {
	if got := DefaultConfig(); got.MaxEchoes == 0 || got.MaxPayloadBytes <= 0 || got.MaxAttempts == 0 || got.RetryServiceAttempts == 0 {
		t.Fatalf("default config is not finite and enabled: %+v", got)
	}
	if err := Register(wagonet.New(), nil); err != ErrInvalidOption {
		t.Fatalf("nil option error = %v", err)
	}
	if err := Register(wagonet.New(), AllowDestinations()); err != ErrInvalidOption {
		t.Fatalf("empty destination option error = %v", err)
	}
	if err := Register(wagonet.New(), AllowDestinations(netip.MustParsePrefix("2001:db8::/32"))); err != ErrInvalidOption {
		t.Fatalf("IPv6 destination option error = %v", err)
	}
}

func callImport(t testing.TB, runtime *wago.Runtime, host hostModule, name string, params ...uint64) guest.Status {
	t.Helper()
	function, ok := runtime.HostImports()[icmpbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("ICMPv4 import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}
