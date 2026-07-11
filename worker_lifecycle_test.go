//go:build !tinygo && wago_legacy_workers

package net

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

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

type workerNetworkSnapshot struct {
	instance *wago.Instance
	state    *instancestate.State
	udp      resource.Handle
	tcp      resource.Handle
	dns      resource.Handle
}

type workerHostSnapshot struct {
	instance *wago.Instance
	state    *instancestate.State
}

type workerNetworkExtension struct {
	network *Extension
	workers *wago.Workers

	created  chan workerNetworkSnapshot
	callers  chan workerHostSnapshot
	exits    chan wago.WorkerExitContext
	spawnErr chan error
	hookErr  chan error

	mu     sync.Mutex
	events []string
}

func newWorkerNetworkExtension(network *Extension) *workerNetworkExtension {
	return &workerNetworkExtension{
		network:  network,
		created:  make(chan workerNetworkSnapshot, 8),
		callers:  make(chan workerHostSnapshot, 8),
		exits:    make(chan wago.WorkerExitContext, 8),
		spawnErr: make(chan error, 8),
		hookErr:  make(chan error, 8),
	}
}

func (*workerNetworkExtension) Info() wago.ExtensionInfo {
	return wago.ExtensionInfo{ID: "test.net-worker-lifecycle", Version: "1.0.0", Stability: wago.Stable}
}

func (e *workerNetworkExtension) Register(reg *wago.Registry) error {
	e.workers = reg.Workers()
	e.workers.OnExit(func(ctx *wago.WorkerExitContext) {
		if ctx != nil {
			e.exits <- *ctx
		}
	})
	reg.Hooks().AfterInstantiate(func(ctx *wago.InstantiateContext, instance *wago.Instance) error {
		if ctx.Origin != wago.InstantiateWorker {
			return nil
		}
		state, ok := e.network.instanceManager().ForInstance(instance)
		if !ok {
			return errors.New("worker networking state was not attached first")
		}
		udp, progress, err := udpinstance.Bind(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.81"), Port: 4381})
		if err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("bind worker UDP: handle=%v progress=%v: %w", udp, progress, err)
		}
		tcp, progress, err := tcpinstance.Listen(state, state.NamespaceHandle(), namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.81"), Port: 4481})
		if err != nil || progress != namespace.ProgressDone {
			return fmt.Errorf("listen worker TCP: handle=%v progress=%v: %w", tcp, progress, err)
		}
		dns, progress, err := dnsinstance.Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
		if err != nil || progress != namespace.ProgressInProgress {
			return fmt.Errorf("resolve worker DNS: handle=%v progress=%v: %w", dns, progress, err)
		}
		e.created <- workerNetworkSnapshot{instance: instance, state: state, udp: udp, tcp: tcp, dns: dns}
		return nil
	})
	reg.Hooks().BeforeClose(func(ctx *wago.InstanceContext) {
		if ctx.Origin != wago.InstantiateWorker {
			return
		}
		e.addEvent("observe")
		if state, ok := e.network.instanceManager().ForInstance(ctx.Instance); !ok || state == nil {
			e.recordHookError(errors.New("worker networking state detached before reverse close observer"))
		}
	})
	reg.Hooks().BeforeClose(func(ctx *wago.InstanceContext) {
		if ctx.Origin == wago.InstantiateWorker {
			e.addEvent("panic")
			panic("worker close observer panic")
		}
	})
	reg.Hooks().AfterClose(func(ctx *wago.InstanceContext) {
		if ctx.Origin != wago.InstantiateWorker {
			return
		}
		e.addEvent("after")
		if _, ok := e.network.instanceManager().ForInstance(ctx.Instance); ok {
			e.recordHookError(errors.New("worker networking state survived AfterClose"))
		}
	})

	module := reg.ImportModule("worker_net")
	module.Func("spawn", func(caller wago.HostModule, _, results []uint64) {
		id, err := e.workers.Spawn(caller, 0, wago.WorkerOptions{QueueCapacity: 1, MaxPayloadBytes: 1, MaxQueueBytes: 1})
		if err == nil {
			err = e.workers.Link(caller, id)
			if err != nil {
				_ = e.workers.Kill(id)
			}
		}
		if err != nil {
			e.spawnErr <- fmt.Errorf("caller %T: %w", caller, err)
			return
		}
		results[0] = uint64(id)
	}).Results(wago.ValI64)
	module.Func("wait", func(caller wago.HostModule, _, _ []uint64) {
		identity, ok := caller.(wago.InstanceHostModule)
		if !ok || identity.Instance() == nil {
			e.recordHookError(errors.New("worker host call lacked exact instance identity"))
		} else {
			state, found := e.network.instanceManager().FromHost(caller)
			if !found {
				e.recordHookError(errors.New("worker host identity did not resolve networking state"))
			}
			e.callers <- workerHostSnapshot{instance: identity.Instance(), state: state}
		}
		if err := e.workers.DispatchNext(caller); err != nil {
			e.recordHookError(fmt.Errorf("worker dispatch returned: %w", err))
		}
	})
	return nil
}

func (e *workerNetworkExtension) addEvent(event string) {
	e.mu.Lock()
	e.events = append(e.events, event)
	e.mu.Unlock()
}

func (e *workerNetworkExtension) recordedEvents() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.events...)
}

func (e *workerNetworkExtension) recordHookError(err error) {
	select {
	case e.hookErr <- err:
	default:
	}
}

func workerNetworkingConfig() Config {
	limits := QuotaLimits{
		Resources: 4, UDPResources: 1, TCPResources: 1, DNSResources: 1,
		QueuedBytes: 8192, DNSWork: 1, ServiceUnits: 128,
	}
	ready := ReadinessConfig{MaxRegistrations: 4}
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
			Hostname: "worker-net", RandSeed: 81,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 81}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 82},
			IPv4Address: netip.MustParseAddr("192.0.2.81"), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8},
			UDP:  UDPConfig{MaxSockets: 1, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32},
			TCP:  TCPConfig{MaxListeners: 1, MaxOutboundStreams: 0, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4},
			DNS:  DNSConfig{Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 1, MaxRecords: 2, MaxResponseBytes: 512, MaxAttempts: 1, RetryServiceAttempts: 2},
		},
	}
}

func workerNetworkingModule(t *testing.T, runtime *wago.Runtime, validCallback bool) *wago.Module {
	t.Helper()
	callbackType := uint32(1)
	callbackParams := []wasm.ValType(nil)
	if !validCallback {
		callbackType = 2
		callbackParams = []wasm.ValType{wasm.I32}
	}
	spawnImport := append(append(wasmtest.Name("worker_net"), wasmtest.Name("spawn")...), 0x00, 0x00)
	waitImport := append(append(wasmtest.Name("worker_net"), wasmtest.Name("wait")...), 0x00, 0x01)
	entry := uint32(2)
	module, err := runtime.Compile(wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(
			wasmtest.FuncType(nil, []wasm.ValType{wasm.I64}),
			wasmtest.FuncType(nil, nil),
			wasmtest.FuncType(callbackParams, nil),
		)),
		wasmtest.Section(2, wasmtest.Vec(spawnImport, waitImport)),
		wasmtest.Section(3, wasmtest.Vec(wasmtest.ULEB(callbackType), wasmtest.ULEB(0))),
		wasmtest.Section(4, wasmtest.Vec([]byte{0x70, 0x00, 0x01})),
		wasmtest.Section(7, wasmtest.Vec(wasmtest.ExportEntry("run", 0, 3))),
		wasmtest.Section(9, wasmtest.Vec(append([]byte{0x00, 0x41, 0x00, 0x0b, 0x01}, wasmtest.ULEB(entry)...))),
		wasmtest.Section(10, wasmtest.Vec(
			wasmtest.Code([]byte{0x10, 0x01, 0x0b}),
			wasmtest.Code([]byte{0x10, 0x00, 0x0b}),
		)),
	))
	if err != nil {
		t.Fatalf("Compile worker networking module: %v", err)
	}
	return module
}

func callWorkerSpawn(t *testing.T, instance *wago.Instance) wago.WorkerID {
	t.Helper()
	results, err := instance.Call(context.Background(), "run")
	if err != nil {
		t.Fatalf("Call worker spawn: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("worker spawn results = %v", results)
	}
	return wago.WorkerID(results[0].I64())
}

func waitWorkerSnapshot(t *testing.T, channel <-chan workerNetworkSnapshot) workerNetworkSnapshot {
	t.Helper()
	select {
	case snapshot := <-channel:
		return snapshot
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for worker networking state")
		return workerNetworkSnapshot{}
	}
}

func waitWorkerHost(t *testing.T, channel <-chan workerHostSnapshot) workerHostSnapshot {
	t.Helper()
	select {
	case snapshot := <-channel:
		return snapshot
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for worker host identity")
		return workerHostSnapshot{}
	}
}

func waitWorkerExit(t *testing.T, channel <-chan wago.WorkerExitContext) wago.WorkerExitContext {
	t.Helper()
	select {
	case exit := <-channel:
		return exit
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for worker exit")
		return wago.WorkerExitContext{}
	}
}

func assertWorkerNetworkingClosed(t *testing.T, snapshot workerNetworkSnapshot) {
	t.Helper()
	for _, owned := range []struct {
		handle resource.Handle
		kind   resource.Kind
	}{
		{snapshot.udp, resource.KindUDPSocket},
		{snapshot.tcp, resource.KindTCPListener},
		{snapshot.dns, resource.KindDNSQuery},
	} {
		if _, err := snapshot.state.Resources().Lookup(owned.handle, owned.kind); !errors.Is(err, resource.ErrClosed) {
			t.Fatalf("retired worker handle %v (%v) lookup = %v, want ErrClosed", owned.handle, owned.kind, err)
		}
	}
	if usage, closed := snapshot.state.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("worker quota after close = %+v, closed=%v", usage, closed)
	}
	if readiness := snapshot.state.Readiness().Snapshot(); !readiness.Closed || readiness.Registrations != 0 {
		t.Fatalf("worker readiness after close = %+v", readiness)
	}
}

func assertNoWorkerHookError(t *testing.T, extension *workerNetworkExtension) {
	t.Helper()
	select {
	case err := <-extension.hookErr:
		t.Fatal(err)
	default:
	}
}

func TestWorkerNetworkingReinstantiatesAndRetiresEveryProtocolBetweenClassLeases(t *testing.T) {
	network := Init(workerNetworkingConfig())
	worker := newWorkerNetworkExtension(network)
	runtime := wago.NewRuntime(wago.WithWorkerLimits(wago.WorkerLimits{MaxLiveWorkers: 1, MaxQueueBytes: 1}))
	defer runtime.Close()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use networking: %v", err)
	}
	if err := runtime.Use(worker); err != nil {
		t.Fatalf("Use workers: %v", err)
	}
	class, err := runtime.Class(workerNetworkingModule(t, runtime, true), wago.ClassOptions{
		Pool: wago.PoolOptions{MinInstances: 1, MaxInstances: 1, Reset: wago.ResetMemorySnapshot},
	})
	if err != nil {
		t.Fatalf("Class: %v", err)
	}
	if got := class.ResetPolicy(); got != wago.ResetReinstantiate {
		t.Fatalf("worker networking class reset = %v, want reinstantiate", got)
	}

	lease, err := class.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire first lease: %v", err)
	}
	oldParent := lease.Instance()
	oldParentState, ok := network.instanceManager().ForInstance(oldParent)
	if !ok {
		t.Fatal("first parent networking state missing")
	}
	firstID := callWorkerSpawn(t, oldParent)
	if firstID == 0 {
		select {
		case spawnErr := <-worker.spawnErr:
			t.Fatalf("first worker spawn: %v", spawnErr)
		default:
			t.Fatal("first worker ID is zero")
		}
	}
	first := waitWorkerSnapshot(t, worker.created)
	caller := waitWorkerHost(t, worker.callers)
	if caller.instance != first.instance || caller.state != first.state {
		t.Fatalf("worker host identity/state = %p/%p, attached = %p/%p", caller.instance, caller.state, first.instance, first.state)
	}
	if got := network.instanceManager().Len(); got != 2 {
		t.Fatalf("states with first worker = %d, want 2", got)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release first lease: %v", err)
	}
	firstExit := waitWorkerExit(t, worker.exits)
	if firstExit.WorkerID != firstID || firstExit.Kind != wago.WorkerKilled || !errors.Is(firstExit.Err, wago.ErrWorkerParentClosed) {
		t.Fatalf("first worker exit = %+v", firstExit)
	}
	assertWorkerNetworkingClosed(t, first)
	if _, ok := network.instanceManager().ForInstance(first.instance); ok {
		t.Fatal("first worker instance retained networking state")
	}
	if _, ok := network.instanceManager().ForInstance(oldParent); ok {
		t.Fatal("first parent retained networking state")
	}
	if usage, closed := oldParentState.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("first parent quota after release = %+v, closed=%v", usage, closed)
	}
	if got := network.instanceManager().Len(); got != 1 {
		t.Fatalf("states after first replacement = %d, want one fresh parent", got)
	}
	if got := worker.recordedEvents(); fmt.Sprint(got) != fmt.Sprint([]string{"panic", "observe", "after"}) {
		t.Fatalf("first worker close events = %v", got)
	}
	assertNoWorkerHookError(t, worker)

	freshLease, err := class.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire fresh lease: %v", err)
	}
	freshParent := freshLease.Instance()
	freshParentState, ok := network.instanceManager().ForInstance(freshParent)
	if !ok || freshParent == oldParent || freshParentState == oldParentState {
		t.Fatalf("fresh parent/state = %p/%p, old = %p/%p, attached=%v", freshParent, freshParentState, oldParent, oldParentState, ok)
	}
	secondID := callWorkerSpawn(t, freshParent)
	if secondID <= firstID {
		t.Fatalf("second worker ID = %d, want greater than %d", secondID, firstID)
	}
	second := waitWorkerSnapshot(t, worker.created)
	secondCaller := waitWorkerHost(t, worker.callers)
	if second.instance == first.instance || second.state == first.state || secondCaller.instance != second.instance || secondCaller.state != second.state {
		t.Fatalf("second worker identity/state was not fresh")
	}
	if err := freshLease.Release(); err != nil {
		t.Fatalf("Release fresh lease: %v", err)
	}
	secondExit := waitWorkerExit(t, worker.exits)
	if secondExit.WorkerID != secondID || secondExit.Kind != wago.WorkerKilled || !errors.Is(secondExit.Err, wago.ErrWorkerParentClosed) {
		t.Fatalf("second worker exit = %+v", secondExit)
	}
	assertWorkerNetworkingClosed(t, second)
	assertNoWorkerHookError(t, worker)
	if err := class.Close(); err != nil {
		t.Fatalf("Class.Close: %v", err)
	}
	if got := network.instanceManager().Len(); got != 0 {
		t.Fatalf("states after class close = %d, want 0", got)
	}
}

func TestFailedWorkerCallbackValidationRetiresNetworkingAndReleasesWorkerQuota(t *testing.T) {
	network := Init(workerNetworkingConfig())
	worker := newWorkerNetworkExtension(network)
	runtime := wago.NewRuntime(wago.WithWorkerLimits(wago.WorkerLimits{MaxLiveWorkers: 1, MaxQueueBytes: 1}))
	defer runtime.Close()
	if err := runtime.Use(network); err != nil {
		t.Fatalf("Use networking: %v", err)
	}
	if err := runtime.Use(worker); err != nil {
		t.Fatalf("Use workers: %v", err)
	}
	invalidModule := workerNetworkingModule(t, runtime, false)
	invalid, err := runtime.Instantiate(context.Background(), invalidModule)
	if err != nil {
		t.Fatalf("Instantiate invalid-callback parent: %v", err)
	}
	if id := callWorkerSpawn(t, invalid); id != 0 {
		t.Fatalf("invalid callback worker ID = %d, want 0", id)
	}
	select {
	case spawnErr := <-worker.spawnErr:
		if spawnErr == nil {
			t.Fatal("invalid callback spawn error is nil")
		}
		if !strings.Contains(spawnErr.Error(), "signature") {
			t.Fatalf("invalid callback spawn error = %v", spawnErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for invalid callback spawn error")
	}
	failed := waitWorkerSnapshot(t, worker.created)
	assertWorkerNetworkingClosed(t, failed)
	if got := network.instanceManager().Len(); got != 1 {
		t.Fatalf("states after failed worker spawn = %d, want parent only", got)
	}
	assertNoWorkerHookError(t, worker)
	if err := invalid.Close(); err != nil {
		t.Fatalf("Close invalid parent: %v", err)
	}
	goruntime.KeepAlive(invalidModule)

	validModule := workerNetworkingModule(t, runtime, true)
	valid, err := runtime.Instantiate(context.Background(), validModule)
	if err != nil {
		t.Fatalf("Instantiate valid parent: %v", err)
	}
	id := callWorkerSpawn(t, valid)
	if id == 0 {
		t.Fatal("worker quota was not released after failed spawn")
	}
	live := waitWorkerSnapshot(t, worker.created)
	_ = waitWorkerHost(t, worker.callers)
	if err := valid.Close(); err != nil {
		t.Fatalf("Close valid parent: %v", err)
	}
	exit := waitWorkerExit(t, worker.exits)
	if exit.WorkerID != id || !errors.Is(exit.Err, wago.ErrWorkerParentClosed) {
		t.Fatalf("valid worker exit = %+v", exit)
	}
	assertWorkerNetworkingClosed(t, live)
	goruntime.KeepAlive(validModule)
	assertNoWorkerHookError(t, worker)
	if got := network.instanceManager().Len(); got != 0 {
		t.Fatalf("states after validation cleanup = %d, want 0", got)
	}
}
