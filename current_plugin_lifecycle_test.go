package net

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	instancestate "github.com/wago-org/net/internal/instance/core"
	dnsinstance "github.com/wago-org/net/internal/instance/dns"
	tcpinstance "github.com/wago-org/net/internal/instance/tcp"
	udpinstance "github.com/wago-org/net/internal/instance/udp"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
)

type currentPluginManagedOwner struct {
	manager *wago.InstanceManager
}

func (*currentPluginManagedOwner) Info() wago.ExtensionInfo {
	return wago.ExtensionInfo{
		ID: "test.net-current-managed-owner", Name: "networking managed owner", Version: "1.0.0",
		Repository: "https://example.com/net-current-managed-owner", License: "Apache-2.0",
		RequiresCapabilities: []wago.PluginCapability{wago.PluginManagedInstances},
	}
}

func (e *currentPluginManagedOwner) Register(reg *wago.Registry) error {
	var err error
	e.manager, err = reg.ManagedInstances()
	return err
}

func currentPluginNetworkConfig() Config {
	limits := QuotaLimits{
		Resources: 8, UDPResources: 1, TCPResources: 1, DNSResources: 1,
		QueuedBytes: 8192, DNSWork: 1, ServiceUnits: 128,
	}
	ready := ReadinessConfig{MaxRegistrations: 8}
	return Config{
		Policy: PolicyConfig{Rules: []PolicyRule{
			{
				Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportUDP, PolicyTransportTCP},
				Directions: []PolicyDirection{PolicyInbound, PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			},
			{
				Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportDNS},
				Directions: []PolicyDirection{PolicyOutbound}, DNSSuffixes: []string{"example.com"},
			},
		}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &StaticIPv4Config{
			Hostname: "current-plugin-net", RandSeed: 71,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 71}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 72},
			IPv4Address: netip.MustParseAddr("192.0.2.71"), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8},
			UDP:  UDPConfig{MaxSockets: 1, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32},
			TCP:  TCPConfig{MaxListeners: 1, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4},
			DNS:  DNSConfig{Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 1, MaxRecords: 2, MaxResponseBytes: 512, MaxAttempts: 1, RetryServiceAttempts: 2},
		},
	}
}

func currentPluginProtocolModule(t *testing.T, runtime *wago.Runtime) *wago.Module {
	t.Helper()
	importEntry := append(append(wasmtest.Name(UDPModule), wasmtest.Name("namespace_default")...), 0x00, 0x00)
	module, err := runtime.Compile(wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType([]wasm.ValType{wasm.I32}, []wasm.ValType{wasm.I32}))),
		wasmtest.Section(2, wasmtest.Vec(importEntry)),
		wasmtest.Section(3, wasmtest.Vec(wasmtest.ULEB(0))),
		wasmtest.Section(5, wasmtest.Vec([]byte{0x00, 0x01})),
		wasmtest.Section(7, wasmtest.Vec(
			wasmtest.ExportEntry("run", 0, 1),
			wasmtest.ExportEntry("memory", 2, 0),
		)),
		wasmtest.Section(10, wasmtest.Vec(wasmtest.Code([]byte{0x20, 0x00, 0x10, 0x00, 0x0b}))),
	))
	if err != nil {
		t.Fatalf("Compile current plugin protocol module: %v", err)
	}
	return module
}

func TestCurrentPluginLeastAuthorityDirectAndManagedLifecycle(t *testing.T) {
	denied := wago.NewRuntime()
	if err := denied.Use(Init(currentPluginNetworkConfig()), wago.WithPluginGrants(wago.PluginHostImports)); !errors.Is(err, wago.ErrPermissionDenied) {
		t.Fatalf("networking without instance.lifecycle grant = %v, want ErrPermissionDenied", err)
	}
	_ = denied.Close()

	network := Init(currentPluginNetworkConfig())
	owner := &currentPluginManagedOwner{}
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.Use(network, wago.WithPluginGrants(wago.PluginHostImports, wago.PluginInstanceHooks)); err != nil {
		t.Fatalf("Use networking: %v", err)
	}
	if err := runtime.Use(owner, wago.WithPluginGrants(wago.PluginManagedInstances)); err != nil {
		t.Fatalf("Use managed owner: %v", err)
	}
	if got := runtime.Capabilities(); len(got) != 4 || got[0] != CapDNS || got[1] != CapInfo || got[2] != CapTCP || got[3] != CapUDP {
		t.Fatalf("guest capabilities = %v", got)
	}
	if got := len(runtime.HostImports()); got != 24 {
		t.Fatalf("registered networking imports = %d, want 24", got)
	}

	module := currentPluginProtocolModule(t, runtime)
	direct, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("direct Instantiate: %v", err)
	}
	managed, err := owner.manager.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("managed Instantiate: %v", err)
	}
	managedInstance := managed.Instance()
	for _, instance := range []*wago.Instance{direct, managedInstance} {
		results, callErr := instance.Call(context.Background(), "run", wago.ValueI32(0))
		if callErr != nil || len(results) != 1 || Status(results[0].I32()) != StatusOK {
			t.Fatalf("namespace_default exact caller = %v, %v", results, callErr)
		}
		if handle := resource.Handle(binary.LittleEndian.Uint64(instance.Memory().Bytes()[:8])); handle == 0 {
			t.Fatal("namespace_default returned zero handle")
		}
	}

	manager := network.instanceManager()
	directState, directOK := manager.ForInstance(direct)
	managedState, managedOK := manager.ForInstance(managedInstance)
	if !directOK || !managedOK || directState == managedState {
		t.Fatalf("direct/managed states = %p/%p, attached=%v/%v", directState, managedState, directOK, managedOK)
	}
	type ownedHandles struct {
		state         *instancestate.State
		udp, tcp, dns resource.Handle
	}
	var owned []ownedHandles
	for index, state := range []*instancestate.State{directState, managedState} {
		udpHandle, progress, opErr := udpinstance.Bind(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: uint16(4100 + index)})
		if opErr != nil || progress != namespace.ProgressDone {
			t.Fatalf("state %d BindUDP = %v, %v, %v", index, udpHandle, progress, opErr)
		}
		tcpHandle, progress, opErr := tcpinstance.Listen(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: uint16(4200 + index)})
		if opErr != nil || progress != namespace.ProgressDone {
			t.Fatalf("state %d ListenTCP = %v, %v, %v", index, tcpHandle, progress, opErr)
		}
		dnsHandle, progress, opErr := dnsinstance.Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
		if opErr != nil || (progress != namespace.ProgressInProgress && progress != namespace.ProgressDone) {
			t.Fatalf("state %d ResolveDNS = %v, %v, %v", index, dnsHandle, progress, opErr)
		}
		owned = append(owned, ownedHandles{state: state, udp: udpHandle, tcp: tcpHandle, dns: dnsHandle})
	}

	if err := direct.Close(); err != nil {
		t.Fatalf("direct Close: %v", err)
	}
	if err := managed.Close(); err != nil {
		t.Fatalf("managed Close: %v", err)
	}
	if got := manager.Len(); got != 0 {
		t.Fatalf("states after close = %d, want 0", got)
	}
	for index, item := range owned {
		for handle, kind := range map[resource.Handle]resource.Kind{
			item.udp: resource.KindUDPSocket, item.tcp: resource.KindTCPListener, item.dns: resource.KindDNSQuery,
		} {
			if _, lookupErr := item.state.Resources().Lookup(handle, kind); !errors.Is(lookupErr, resource.ErrClosed) {
				t.Fatalf("state %d handle %v after close = %v, want ErrClosed", index, handle, lookupErr)
			}
		}
		if usage, closed := item.state.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
			t.Fatalf("state %d quota after close = %+v, closed=%v", index, usage, closed)
		}
	}
}
