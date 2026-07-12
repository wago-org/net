//go:build !tinygo

package net

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	instancestate "github.com/wago-org/net/internal/instance/core"
	dnsinstance "github.com/wago-org/net/internal/instance/dns"
	tcpinstance "github.com/wago-org/net/internal/instance/tcp"
	udpinstance "github.com/wago-org/net/internal/instance/udp"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/src/core/compiler/wasm"
	"github.com/wago-org/wago/testutil/wasmtest"
	workers "github.com/wago-org/workers"
)

type externalWorkerNetworkSnapshot struct {
	instance              *wago.Instance
	state                 *instancestate.State
	udp, listener, stream resource.Handle
	dns                   resource.Handle
}

type externalWorkerCallerSnapshot struct {
	instance *wago.Instance
	state    *instancestate.State
}

type externalWorkerBridge struct {
	network  *Extension
	service  *workers.Workers
	resolver *wago.CallerResolver

	created chan externalWorkerNetworkSnapshot
	callers chan externalWorkerCallerSnapshot
	errors  chan error
}

func newExternalWorkerBridge(network *Extension, service *workers.Workers) *externalWorkerBridge {
	return &externalWorkerBridge{
		network: network, service: service,
		created: make(chan externalWorkerNetworkSnapshot, 1),
		callers: make(chan externalWorkerCallerSnapshot, 1),
		errors:  make(chan error, 8),
	}
}

func (*externalWorkerBridge) Info() wago.ExtensionInfo {
	return wago.ExtensionInfo{
		ID: "test.net-external-workers", Name: "external workers networking bridge", Version: "1.0.0",
		Repository: "https://example.com/net-external-workers", License: "Apache-2.0",
		RequiresCapabilities: []wago.PluginCapability{wago.PluginHostImports, wago.PluginInstanceHooks},
	}
}

func (e *externalWorkerBridge) Register(reg *wago.Registry) error {
	host, err := reg.HostImports()
	if err != nil {
		return err
	}
	e.resolver = host.CallerResolver()
	lifecycle, err := reg.InstanceLifecycle()
	if err != nil {
		return err
	}
	lifecycle.AfterInstantiate(func(ctx *wago.InstantiateContext, instance *wago.Instance) error {
		if ctx.Origin != wago.InstantiateManaged {
			return nil
		}
		state, ok := e.network.instanceManager().ForInstance(instance)
		if !ok {
			return errors.New("external worker networking state was not attached first")
		}
		udp, progress, err := udpinstance.Bind(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.91"), Port: 4391})
		if err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("bind external-worker UDP: handle=%v progress=%v: %w", udp, progress, err)
		}
		if progress, err = udpinstance.Send(state, udp, []byte("retained-worker-datagram"), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.90"), Port: 4392}); err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("send external-worker UDP: progress=%v: %w", progress, err)
		}
		listener, progress, err := tcpinstance.Listen(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.91"), Port: 4491})
		if err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("listen external-worker TCP: handle=%v progress=%v: %w", listener, progress, err)
		}
		stream, progress, err := tcpinstance.Connect(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.90"), Port: 4492})
		if err != nil || progress != namespace.ProgressInProgress {
			return fmt.Errorf("connect external-worker TCP: handle=%v progress=%v: %w", stream, progress, err)
		}
		dns, progress, err := dnsinstance.Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
		if err != nil || (progress != namespace.ProgressInProgress && progress != namespace.ProgressDone) {
			return fmt.Errorf("resolve external-worker DNS: handle=%v progress=%v: %w", dns, progress, err)
		}
		e.created <- externalWorkerNetworkSnapshot{instance: instance, state: state, udp: udp, listener: listener, stream: stream, dns: dns}
		return nil
	})
	lifecycle.BeforeClose(func(ctx *wago.InstanceContext) {
		if ctx.Origin != wago.InstantiateManaged {
			return
		}
		if state, ok := e.network.instanceManager().ForInstance(ctx.Instance); !ok || state == nil {
			e.record(errors.New("external worker networking state detached before reverse close observer"))
		}
	})
	lifecycle.AfterClose(func(ctx *wago.InstanceContext) {
		if ctx.Origin != wago.InstantiateManaged {
			return
		}
		if _, ok := e.network.instanceManager().ForInstance(ctx.Instance); ok {
			e.record(errors.New("external worker networking state survived AfterClose"))
		}
	})

	module := host.Module("external_worker_net")
	module.Func("spawn", func(caller wago.HostModule, _, results []uint64) {
		id, spawnErr := e.service.Spawn(caller, 0, workers.WorkerOptions{QueueCapacity: 1, MaxPayloadBytes: 1, MaxQueueBytes: 1})
		if spawnErr == nil {
			spawnErr = e.service.Link(caller, id)
			if spawnErr != nil {
				_ = e.service.Kill(id)
			}
		}
		if spawnErr != nil {
			e.record(fmt.Errorf("external worker spawn/link: %w", spawnErr))
			return
		}
		results[0] = uint64(id)
	}).Results(wago.ValI64)
	module.Func("wait", func(caller wago.HostModule, _, _ []uint64) {
		instance, resolveErr := e.resolver.Resolve(caller)
		if resolveErr != nil {
			e.record(fmt.Errorf("external worker exact caller: %w", resolveErr))
			return
		}
		state, ok := e.network.instanceManager().FromHost(caller)
		if !ok || state == nil {
			e.record(errors.New("external worker caller did not resolve networking state"))
			return
		}
		e.callers <- externalWorkerCallerSnapshot{instance: instance, state: state}
		if dispatchErr := e.service.DispatchNext(caller); dispatchErr != nil && !errors.Is(dispatchErr, workers.ErrWorkerParentClosed) {
			e.record(fmt.Errorf("external worker dispatch: %w", dispatchErr))
		}
	})
	return nil
}

func (e *externalWorkerBridge) record(err error) {
	select {
	case e.errors <- err:
	default:
	}
}

func externalWorkerNetworkingConfig() Config {
	limits := QuotaLimits{Resources: 8, UDPResources: 1, TCPResources: 2, DNSResources: 1, QueuedBytes: 8192, DNSWork: 1, ServiceUnits: 64}
	ready := ReadinessConfig{MaxRegistrations: 8}
	return Config{
		Policy: PolicyConfig{Rules: []PolicyRule{
			{Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportUDP, PolicyTransportTCP}, Directions: []PolicyDirection{PolicyInbound, PolicyOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
			{Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportDNS}, Directions: []PolicyDirection{PolicyOutbound}, DNSSuffixes: []string{"example.com"}},
		}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &StaticIPv4Config{
			Hostname: "external-worker-net", RandSeed: 91,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 91}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 92},
			IPv4Address: netip.MustParseAddr("192.0.2.91"), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8},
			UDP:  UDPConfig{MaxSockets: 1, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32},
			TCP:  TCPConfig{MaxListeners: 1, MaxOutboundStreams: 1, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4},
			DNS:  DNSConfig{Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 1, MaxRecords: 4, MaxResponseBytes: 512, MaxAttempts: 1, RetryServiceAttempts: 1},
		},
	}
}

func externalWorkerNetworkingModule(t *testing.T, runtime *wago.Runtime) *wago.Module {
	t.Helper()
	spawnImport := append(append(wasmtest.Name("external_worker_net"), wasmtest.Name("spawn")...), 0x00, 0x00)
	waitImport := append(append(wasmtest.Name("external_worker_net"), wasmtest.Name("wait")...), 0x00, 0x01)
	module, err := runtime.Compile(wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(
			wasmtest.FuncType(nil, []wasm.ValType{wasm.I64}),
			wasmtest.FuncType(nil, nil),
		)),
		wasmtest.Section(2, wasmtest.Vec(spawnImport, waitImport)),
		wasmtest.Section(3, wasmtest.Vec(wasmtest.ULEB(1), wasmtest.ULEB(0))),
		wasmtest.Section(4, wasmtest.Vec([]byte{0x70, 0x00, 0x01})),
		wasmtest.Section(7, wasmtest.Vec(wasmtest.ExportEntry("run", 0, 3))),
		wasmtest.Section(9, wasmtest.Vec(append([]byte{0x00, 0x41, 0x00, 0x0b, 0x01}, wasmtest.ULEB(2)...))),
		wasmtest.Section(10, wasmtest.Vec(
			wasmtest.Code([]byte{0x10, 0x01, 0x0b}),
			wasmtest.Code([]byte{0x10, 0x00, 0x0b}),
		)),
	))
	if err != nil {
		t.Fatalf("Compile external worker networking module: %v", err)
	}
	return module
}

func waitExternalWorkerValue[T any](t *testing.T, values <-chan T, label string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		var zero T
		t.Fatalf("timed out waiting for %s", label)
		return zero
	}
}

func assertExternalWorkerNetworkingClosed(t *testing.T, snapshot externalWorkerNetworkSnapshot) {
	t.Helper()
	for _, owned := range []struct {
		handle resource.Handle
		kind   resource.Kind
	}{
		{snapshot.udp, resource.KindUDPSocket},
		{snapshot.listener, resource.KindTCPListener},
		{snapshot.stream, resource.KindTCPStream},
		{snapshot.dns, resource.KindDNSQuery},
	} {
		if _, err := snapshot.state.Resources().Lookup(owned.handle, owned.kind); !errors.Is(err, resource.ErrClosed) {
			t.Fatalf("retired external-worker handle %v (%v) lookup = %v, want ErrClosed", owned.handle, owned.kind, err)
		}
	}
	if got := snapshot.state.Resources().Len(); got != 0 {
		t.Fatalf("external-worker resources after close = %d, want 0", got)
	}
	if usage, closed := snapshot.state.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("external-worker quota after close = %+v, closed=%v", usage, closed)
	}
	if readiness := snapshot.state.Readiness().Snapshot(); !readiness.Closed || readiness.Registrations != 0 {
		t.Fatalf("external-worker readiness after close = %+v", readiness)
	}
}

func TestExternalWorkersPluginRetiresLinkedNetworkingState(t *testing.T) {
	network := Init(externalWorkerNetworkingConfig())
	workerPlugin := workers.New(workers.WithLimits(workers.WorkerLimits{MaxLiveWorkers: 1, MaxQueueBytes: 1}))
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.Use(network, wago.WithPluginGrants(wago.PluginHostImports, wago.PluginInstanceHooks)); err != nil {
		t.Fatalf("Use networking: %v", err)
	}
	if err := runtime.Use(workerPlugin, wago.WithPluginGrants(wago.PluginManagedInstances, wago.PluginInstanceHooks)); err != nil {
		t.Fatalf("Use external workers: %v", err)
	}
	bridge := newExternalWorkerBridge(network, workerPlugin.Service())
	if err := runtime.Use(bridge, wago.WithPluginGrants(wago.PluginHostImports, wago.PluginInstanceHooks)); err != nil {
		t.Fatalf("Use external worker bridge: %v", err)
	}
	exits := make(chan workers.WorkerExitContext, 1)
	workerPlugin.Service().OnExit(func(ctx *workers.WorkerExitContext) { exits <- *ctx })

	parent, err := runtime.Instantiate(context.Background(), externalWorkerNetworkingModule(t, runtime))
	if err != nil {
		t.Fatalf("Instantiate parent: %v", err)
	}
	parentState, ok := network.instanceManager().ForInstance(parent)
	if !ok {
		t.Fatal("parent networking state missing")
	}
	results, err := parent.Call(context.Background(), "run")
	if err != nil || len(results) != 1 || results[0].I64() == 0 {
		select {
		case bridgeErr := <-bridge.errors:
			t.Fatalf("spawn result = %v, %v; bridge error: %v", results, err, bridgeErr)
		default:
			t.Fatalf("spawn result = %v, %v", results, err)
		}
	}
	workerID := workers.WorkerID(results[0].I64())
	created := waitExternalWorkerValue(t, bridge.created, "external worker networking state")
	caller := waitExternalWorkerValue(t, bridge.callers, "external worker exact caller")
	if caller.instance != created.instance || caller.state != created.state {
		t.Fatalf("external worker caller/state = %p/%p, created = %p/%p", caller.instance, caller.state, created.instance, created.state)
	}
	if got := network.instanceManager().Len(); got != 2 {
		t.Fatalf("networking states with external worker = %d, want 2", got)
	}
	parentLink := concreteNamespace(t, parentState).Link()
	workerLink := concreteNamespace(t, created.state).Link()

	if err := parent.Close(); err != nil {
		t.Fatalf("parent Close: %v", err)
	}
	exit := waitExternalWorkerValue(t, exits, "external worker exit")
	if exit.WorkerID != workerID || exit.Kind != workers.WorkerKilled || !errors.Is(exit.Err, workers.ErrWorkerParentClosed) {
		t.Fatalf("external worker exit = %+v", exit)
	}
	assertExternalWorkerNetworkingClosed(t, created)
	if _, ok := network.instanceManager().ForInstance(created.instance); ok {
		t.Fatal("external worker retained networking state")
	}
	if _, ok := network.instanceManager().ForInstance(parent); ok {
		t.Fatal("parent retained networking state")
	}
	if usage, closed := parentState.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("parent quota after close = %+v, closed=%v", usage, closed)
	}
	for label, link := range map[string]*packetlink.Link{"parent": parentLink, "worker": workerLink} {
		if snapshot := link.Snapshot(); !snapshot.Closed || snapshot.IngressFrames != 0 || snapshot.EgressFrames != 0 {
			t.Fatalf("%s packet link after close = %+v", label, snapshot)
		}
	}
	if got := network.instanceManager().Len(); got != 0 {
		t.Fatalf("networking states after linked close = %d, want 0", got)
	}
	select {
	case bridgeErr := <-bridge.errors:
		t.Fatal(bridgeErr)
	default:
	}
}
