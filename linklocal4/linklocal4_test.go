package linklocal4

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
	"time"

	wagonet "github.com/wago-org/net"
	linklocalabi "github.com/wago-org/net/internal/abi/linklocal4"
	linklocalbinding "github.com/wago-org/net/internal/binding/linklocal4"
	"github.com/wago-org/net/internal/guest"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type fixedClock struct{ value time.Time }

func (c *fixedClock) Now() time.Time { return c.value }

func TestSelectiveRegistrationAndExplicitFiniteConfiguration(t *testing.T) {
	network := wagonet.New()
	if err := Register(network); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{wagonet.CapInfo, wagonet.CapLinkLocal4}) {
		t.Fatalf("capabilities = %v", got)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.LinkLocal4Module {
			imports++
		}
	}
	if imports != 7 {
		t.Fatalf("link-local imports = %d", imports)
	}
	clock := &fixedClock{value: time.Unix(1, 0)}
	if err := Register(wagonet.New(), WithSeed(1)); err != ErrIncompleteConfig {
		t.Fatalf("seed-only error = %v", err)
	}
	if err := Register(wagonet.New(), WithClock(clock)); err != ErrIncompleteConfig {
		t.Fatalf("clock-only error = %v", err)
	}
	if err := Register(wagonet.New(), WithSeed(1), WithClock(clock)); err != nil {
		t.Fatalf("explicit config = %v", err)
	}
}

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m hostModule) Memory() []byte           { return m.memory }
func (m hostModule) Instance() *wago.Instance { return m.instance }

func TestActualBackendExactLifecycleAndDenyWins(t *testing.T) {
	clock := &fixedClock{value: time.Unix(1000, 0)}
	limits := wagonet.QuotaLimits{Resources: 3, LinkLocal4Resources: 2, LinkLocal4Work: 2, ServiceUnits: 16}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 3}
	config := wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportLinkLocal4}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("169.254.42.7/32")}}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{Hostname: "linklocal-guest", RandSeed: 61, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 61}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, IPv4Address: netip.IPv4Unspecified(), MTU: 1500, Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2}},
	}
	network := wagonet.New(wagonet.WithConfig(config))
	if err := Register(network, WithSeed(1), WithClock(clock)); err != nil {
		t.Fatal(err)
	}
	runtime, host := instantiate(t, network)
	if got := callImport(t, runtime, host, "namespace_default", 200); got != guest.StatusOK {
		t.Fatal(got)
	}
	namespace := resource.Handle(binary.LittleEndian.Uint64(host.memory[200:208]))
	request := linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}
	if !linklocalabi.EncodeRequestV1(host.memory, 0, request) {
		t.Fatal("encode request")
	}
	before := append([]byte(nil), host.memory...)
	if got := callImport(t, runtime, host, "claim", uint64(namespace), 0, 64); got != guest.StatusAccessDenied || !bytes.Equal(before, host.memory) {
		t.Fatalf("deny-wins claim = %v mutated=%v", got, !bytes.Equal(before, host.memory))
	}

	config.Policy = wagonet.PolicyConfig{}
	allowed := wagonet.New(wagonet.WithConfig(config))
	if err := Register(allowed, WithSeed(2), WithClock(clock)); err != nil {
		t.Fatal(err)
	}
	runtime2, host2 := instantiate(t, allowed)
	if callImport(t, runtime2, host2, "namespace_default", 200) != guest.StatusOK {
		t.Fatal("namespace")
	}
	namespace = resource.Handle(binary.LittleEndian.Uint64(host2.memory[200:208]))
	linklocalabi.EncodeRequestV1(host2.memory, 0, linklocalns.Request{})
	if got := callImport(t, runtime2, host2, "claim", uint64(namespace), 0, 64); got != guest.StatusInProgress {
		t.Fatalf("claim = %v", got)
	}
	claim := resource.Handle(binary.LittleEndian.Uint64(host2.memory[64:72]))
	if got := callImport(t, runtime2, host2, "cancel", uint64(claim)); got != guest.StatusOK {
		t.Fatalf("cancel = %v", got)
	}
	if got := callImport(t, runtime2, host2, "result", uint64(claim), 128); got != guest.StatusCanceled {
		t.Fatalf("result = %v", got)
	}
	if got := callImport(t, runtime2, host2, "close", uint64(claim)); got != guest.StatusOK {
		t.Fatalf("close = %v", got)
	}
	if got := callImport(t, runtime2, host2, "close", uint64(claim)); got != guest.StatusBadHandle {
		t.Fatalf("stale close = %v", got)
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
	function, ok := runtime.HostImports()[linklocalbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("link-local import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}
