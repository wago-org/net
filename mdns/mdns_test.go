package mdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	wagonet "github.com/wago-org/net"
	mdnsabi "github.com/wago-org/net/internal/abi/mdns"
	mdnsbinding "github.com/wago-org/net/internal/binding/mdns"
	"github.com/wago-org/net/internal/guest"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type hostModule struct {
	instance *wago.Instance
	memory   []byte
}

func (m hostModule) Memory() []byte           { return m.memory }
func (m hostModule) Instance() *wago.Instance { return m.instance }

func TestSelectiveMDNSRegistrationAndActualBackendLifecycle(t *testing.T) {
	limits := wagonet.QuotaLimits{Resources: 4, MDNSResources: 3, QueuedBytes: 1 << 20, MDNSWork: 3, ServiceUnits: 64}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 4}
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{
			Hostname: "mdns-guest", RandSeed: 23,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 23}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
			IPv4Address: netip.MustParseAddr("192.0.2.23"), MTU: 1500,
			Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
		},
	}))
	service := Service{Name: "device._demo._udp.local", Host: "device.local", Address: netip.MustParseAddr("192.0.2.23"), Port: 9000, TXT: []byte{3, 'k', '=', 'v'}}
	if err := Register(network, WithServices(service)); err != nil {
		t.Fatal(err)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(network); err != nil {
		t.Fatal(err)
	}
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.MDNSModule {
			imports++
		}
		if spec.Module == wagonet.UDPModule || spec.Module == wagonet.TCPModule || spec.Module == wagonet.DNSModule || spec.Module == wagonet.ICMPv4Module || spec.Module == wagonet.NTPModule {
			t.Fatalf("mDNS selection compiled unrelated module %q", spec.Module)
		}
	}
	if imports != 10 {
		t.Fatalf("mDNS imports = %d, want 10", imports)
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
	host := hostModule{instance: instance, memory: make([]byte, 2048)}
	if got := callImport(t, runtime, host, "namespace_default", 1500); got != guest.StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[1500:1508]))
	request := mdnsns.Request{Name: "peer.local", Types: mdnsns.RecordsA}
	if !mdnsabi.EncodeQueryV1(host.memory, 0, request) {
		t.Fatal("encode query")
	}
	if got := callImport(t, runtime, host, "query", uint64(namespaceHandle), 0, 300); got != guest.StatusInProgress {
		t.Fatalf("query = %v", got)
	}
	queryHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[300:308]))
	if got := callImport(t, runtime, host, "close_announcement", uint64(queryHandle)); got != guest.StatusBadHandle {
		t.Fatalf("query accepted as announcement = %v", got)
	}
	before := bytes.Repeat([]byte{0xa5}, int(mdnsabi.RecordV1Size))
	copy(host.memory[400:400+mdnsabi.RecordV1Size], before)
	if got := callImport(t, runtime, host, "next", uint64(queryHandle), 400); got != guest.StatusAgain {
		t.Fatalf("next = %v", got)
	}
	if !bytes.Equal(host.memory[400:400+mdnsabi.RecordV1Size], before) {
		t.Fatal("AGAIN mutated record output")
	}
	if got := callImport(t, runtime, host, "cancel_query", uint64(queryHandle)); got != guest.StatusOK {
		t.Fatalf("cancel query = %v", got)
	}
	if got := callImport(t, runtime, host, "next", uint64(queryHandle), 400); got != guest.StatusCanceled {
		t.Fatalf("canceled next = %v", got)
	}
	if got := callImport(t, runtime, host, "close_query", uint64(queryHandle)); got != guest.StatusOK {
		t.Fatalf("close query = %v", got)
	}

	if !mdnsabi.EncodeAnnouncementV1(host.memory, 1600, 0) {
		t.Fatal("encode announcement")
	}
	if got := callImport(t, runtime, host, "announce", uint64(namespaceHandle), 1600, 1700); got != guest.StatusInProgress {
		t.Fatalf("announce = %v", got)
	}
	announcement := resource.Handle(binary.LittleEndian.Uint64(host.memory[1700:1708]))
	if got := callImport(t, runtime, host, "close_query", uint64(announcement)); got != guest.StatusBadHandle {
		t.Fatalf("announcement accepted as query = %v", got)
	}
	if got := callImport(t, runtime, host, "finish_announcement", uint64(announcement)); got != guest.StatusAgain {
		t.Fatalf("pending announcement = %v", got)
	}
	if got := callImport(t, runtime, host, "cancel_announcement", uint64(announcement)); got != guest.StatusOK {
		t.Fatalf("cancel announcement = %v", got)
	}
	if got := callImport(t, runtime, host, "close_announcement", uint64(announcement)); got != guest.StatusOK {
		t.Fatalf("close announcement = %v", got)
	}
}

func TestMDNSDenyWinsAndOptionsAreFinite(t *testing.T) {
	config := DefaultConfig()
	if config.MaxQueries == 0 || config.MaxPacketBytes == 0 || config.MaxRecords == 0 || config.MaxAttempts == 0 || config.RetryServiceAttempts == 0 {
		t.Fatalf("defaults are not finite: %+v", config)
	}
	if err := Register(wagonet.New(), nil); err != ErrInvalidOption {
		t.Fatalf("nil option error = %v", err)
	}
	if err := Register(wagonet.New(), AllowSuffixes()); err != ErrInvalidOption {
		t.Fatalf("empty suffix error = %v", err)
	}
	if err := Register(wagonet.New(), WithServices(Service{Name: "bad.example", Host: "bad.example"})); err != ErrInvalidService {
		t.Fatalf("invalid service error = %v", err)
	}

	limits := wagonet.QuotaLimits{Resources: 2, MDNSResources: 1, QueuedBytes: 1 << 20, MDNSWork: 1, ServiceUnits: 8}
	ready := wagonet.ReadinessConfig{MaxRegistrations: 2}
	network := wagonet.New(wagonet.WithConfig(wagonet.Config{
		Policy: wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{Action: wagonet.PolicyDeny, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportMDNS}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, DNSSuffixes: []string{"secret.local"}}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &wagonet.StaticIPv4Config{Hostname: "mdns-deny", RandSeed: 24, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 24}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, IPv4Address: netip.MustParseAddr("192.0.2.24"), MTU: 1500, Link: wagonet.PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1}},
	}))
	if err := Register(network); err != nil {
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
	host := hostModule{instance: instance, memory: make([]byte, 512)}
	if got := callImport(t, runtime, host, "namespace_default", 400); got != guest.StatusOK {
		t.Fatal(got)
	}
	namespace := binary.LittleEndian.Uint64(host.memory[400:408])
	mdnsabi.EncodeQueryV1(host.memory, 0, mdnsns.Request{Name: "secret.local", Types: mdnsns.RecordsA})
	if got := callImport(t, runtime, host, "query", namespace, 0, 300); got != guest.StatusAccessDenied {
		t.Fatalf("deny-wins query = %v", got)
	}
	before := append([]byte(nil), host.memory...)
	if got := callImport(t, runtime, host, "query", namespace, 0, 508); got != guest.StatusInvalidArgument || !bytes.Equal(before, host.memory) {
		t.Fatalf("invalid output = %v mutated=%v", got, !bytes.Equal(before, host.memory))
	}
}

func callImport(t testing.TB, runtime *wago.Runtime, host hostModule, name string, params ...uint64) guest.Status {
	t.Helper()
	function, ok := runtime.HostImports()[mdnsbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("mDNS import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}
