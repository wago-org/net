package ntp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	wagonet "github.com/wago-org/net"
	ntpabi "github.com/wago-org/net/internal/abi/ntp"
	ntpbinding "github.com/wago-org/net/internal/binding/ntp"
	"github.com/wago-org/net/internal/guest"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m hostModule) Memory() []byte           { return m.memory }
func (m hostModule) Instance() *wago.Instance { return m.instance }

type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

func TestSelectiveNTPRegistrationAndActualBackendLifecycle(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC)}
	limits := wagonet.QuotaLimits{Resources: 2, NTPResources: 1, NTPWork: 1, ServiceUnits: 32}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 2}
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{
			Hostname: "ntp-guest", RandSeed: 19,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 19}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
			IPv4Address: netip.MustParseAddr("192.0.2.19"), MTU: 1500,
			Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
		},
	}))
	if err := Register(network, Server("192.0.2.123"), WithClock(clock)); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.NTPModule {
			imports++
		}
		if spec.Module == wagonet.UDPModule || spec.Module == wagonet.TCPModule || spec.Module == wagonet.DNSModule || spec.Module == wagonet.ICMPv4Module {
			t.Fatalf("NTP selection compiled unrelated module %q", spec.Module)
		}
	}
	if imports != 6 {
		t.Fatalf("NTP imports = %d, want 6", imports)
	}
	foundCapability := false
	for _, capability := range runtime.Capabilities() {
		foundCapability = foundCapability || capability == wagonet.CapNTP
	}
	if !foundCapability {
		t.Fatal("NTP capability not advertised")
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
	host := hostModule{instance: instance, memory: make([]byte, 256)}
	if got := callImport(t, runtime, host, "namespace_default", 80); got != guest.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[80:88]))
	if got := callImport(t, runtime, host, "sync", uint64(namespaceHandle), 64); got != guest.StatusInProgress {
		t.Fatalf("sync = %v", got)
	}
	syncHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[64:72]))
	before := bytes.Repeat([]byte{0xa5}, int(ntpabi.SampleV1Size))
	copy(host.memory[128:128+ntpabi.SampleV1Size], before)
	if got := callImport(t, runtime, host, "result", uint64(syncHandle), 128); got != guest.StatusAgain {
		t.Fatalf("pending result = %v", got)
	}
	if !bytes.Equal(host.memory[128:128+ntpabi.SampleV1Size], before) {
		t.Fatal("AGAIN result mutated guest output")
	}
	if got := callImport(t, runtime, host, "cancel", uint64(syncHandle)); got != guest.StatusOK {
		t.Fatalf("cancel = %v", got)
	}
	if got := callImport(t, runtime, host, "result", uint64(syncHandle), 128); got != guest.StatusCanceled {
		t.Fatalf("canceled result = %v", got)
	}
	if got := callImport(t, runtime, host, "close", uint64(syncHandle)); got != guest.StatusOK {
		t.Fatalf("close = %v", got)
	}
	if got := callImport(t, runtime, host, "result", uint64(syncHandle), 128); got != guest.StatusBadHandle {
		t.Fatalf("stale result = %v", got)
	}
}

func TestNTPDenyWinsAndCheckedMemoryPrecedesWork(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 7, 13, 22, 0, 0, 0, time.UTC)}
	limits := wagonet.QuotaLimits{Resources: 2, NTPResources: 1, NTPWork: 1, ServiceUnits: 8}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 2}
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportNTP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.123/32")},
		}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{
			Hostname: "ntp-deny", RandSeed: 20,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 20}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
			IPv4Address: netip.MustParseAddr("192.0.2.20"), MTU: 1500,
			Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1},
		},
	}))
	if err := Register(network, Server("192.0.2.123"), WithClock(clock)); err != nil {
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
	host := hostModule{instance: instance, memory: make([]byte, 128)}
	if got := callImport(t, runtime, host, "namespace_default", 80); got != guest.StatusOK {
		t.Fatal(got)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[80:88])
	if got := callImport(t, runtime, host, "sync", namespaceHandle, 64); got != guest.StatusAccessDenied {
		t.Fatalf("deny-wins sync = %v", got)
	}
	before := append([]byte(nil), host.memory...)
	if got := callImport(t, runtime, host, "sync", namespaceHandle, 124); got != guest.StatusInvalidArgument {
		t.Fatalf("invalid output sync = %v", got)
	}
	if !bytes.Equal(before, host.memory) {
		t.Fatal("invalid sync mutated memory")
	}
}

func TestNTPOptionsRequireExplicitClockAndFiniteConfiguration(t *testing.T) {
	clock := &fixedClock{now: time.Now().UTC()}
	if got := DefaultConfig(netip.MustParseAddr("192.0.2.123"), clock); got.MaxSyncs == 0 || got.MaxAttempts == 0 || got.RetryServiceAttempts == 0 || got.Clock == nil {
		t.Fatalf("default config is not finite and enabled: %+v", got)
	}
	if err := Register(wagonet.New(), nil); err != ErrInvalidOption {
		t.Fatalf("nil option error = %v", err)
	}
	if err := Register(wagonet.New(), Server("192.0.2.123")); err != ErrIncompleteConfig {
		t.Fatalf("server-only error = %v", err)
	}
	if err := Register(wagonet.New(), WithClock(clock)); err != ErrIncompleteConfig {
		t.Fatalf("clock-only error = %v", err)
	}
	if err := Register(wagonet.New(), Server("224.0.0.1"), WithClock(clock)); err != ErrInvalidServer {
		t.Fatalf("multicast server error = %v", err)
	}
	if err := Register(wagonet.New(), Server("127.0.0.1"), WithClock(clock), AllowLoopback()); err != ErrInvalidServer {
		t.Fatalf("loopback server error = %v", err)
	}
	if err := Register(wagonet.New(), AllowServers()); err != ErrInvalidOption {
		t.Fatalf("empty server authority error = %v", err)
	}
}

func callImport(t testing.TB, runtime *wago.Runtime, host hostModule, name string, params ...uint64) guest.Status {
	t.Helper()
	function, ok := runtime.HostImports()[ntpbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("NTP import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}
