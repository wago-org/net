package net

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
	"github.com/wago-org/wago/testutil/wasmtest"
)

type lifecycleResource struct {
	closed atomic.Int32
}

func (r *lifecycleResource) Close() error {
	if r.closed.Add(1) != 1 {
		panic("lifecycle resource closed more than once")
	}
	return nil
}

type observerExtension struct {
	fn wago.HostFunc
}

func (observerExtension) Info() wago.ExtensionInfo {
	return wago.ExtensionInfo{ID: "test.net-observer", Version: "1.0.0", Stability: wago.Stable}
}

func (e observerExtension) Register(reg *wago.Registry) error {
	reg.ImportModule("env").Func("observe", e.fn)
	return nil
}

type failingSetupExtension struct {
	netup    *Extension
	resource *lifecycleResource
	err      error
}

func (failingSetupExtension) Info() wago.ExtensionInfo {
	return wago.ExtensionInfo{ID: "test.net-failing-setup", Version: "1.0.0", Stability: wago.Stable}
}

func (e failingSetupExtension) Register(reg *wago.Registry) error {
	reg.Hooks().AfterInstantiate(func(_ *wago.InstantiateContext, instance *wago.Instance) error {
		state, ok := e.netup.instanceManager().ForInstance(instance)
		if !ok {
			return errors.New("networking state was not attached before later setup")
		}
		if _, err := state.Resources().Add(resource.KindNamespace, e.resource); err != nil {
			return err
		}
		return e.err
	})
	return nil
}

func emptyModule(t *testing.T, runtime *wago.Runtime) *wago.Module {
	t.Helper()
	module, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Compile empty module: %v", err)
	}
	return module
}

func observerModule(t *testing.T, runtime *wago.Runtime) *wago.Module {
	t.Helper()
	importEntry := append(append(wasmtest.Name("env"), wasmtest.Name("observe")...), 0x00, 0x00)
	wasm := wasmtest.Module(
		wasmtest.Section(1, wasmtest.Vec(wasmtest.FuncType(nil, nil))),
		wasmtest.Section(2, wasmtest.Vec(importEntry)),
		wasmtest.Section(3, wasmtest.Vec(wasmtest.ULEB(0))),
		wasmtest.Section(7, wasmtest.Vec(wasmtest.ExportEntry("run", 0, 1))),
		wasmtest.Section(10, wasmtest.Vec(wasmtest.Code([]byte{0x10, 0x00, 0x0b}))),
	)
	module, err := runtime.Compile(wasm)
	if err != nil {
		t.Fatalf("Compile observer module: %v", err)
	}
	return module
}

func TestInstanceStateIsolationHostIdentityAndCrossTableHandles(t *testing.T) {
	extension := Init(Config{})
	manager := extension.instanceManager()
	var observed []*wago.Instance
	var observedState any
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use net extension: %v", err)
	}
	if err := runtime.Use(observerExtension{fn: func(module wago.HostModule, _, _ []uint64) {
		identity, ok := module.(wago.InstanceHostModule)
		if !ok {
			t.Fatal("host module has no instance identity")
		}
		observed = append(observed, identity.Instance())
		state, ok := manager.FromHost(module)
		if !ok {
			t.Fatal("networking state missing for host caller")
		}
		observedState = state
	}}); err != nil {
		t.Fatalf("Use observer extension: %v", err)
	}
	module := observerModule(t, runtime)
	first, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate first: %v", err)
	}
	defer first.Close()
	second, err := runtime.Instantiate(context.Background(), module)
	if err != nil {
		t.Fatalf("Instantiate second: %v", err)
	}
	defer second.Close()

	firstState, firstOK := manager.ForInstance(first)
	secondState, secondOK := manager.ForInstance(second)
	if !firstOK || !secondOK || firstState == secondState || firstState.Resources() == secondState.Resources() || firstState.Readiness() == secondState.Readiness() {
		t.Fatalf("isolated states = (%p,%v) (%p,%v)", firstState, firstOK, secondState, secondOK)
	}
	if got := manager.Len(); got != 2 {
		t.Fatalf("attached state count = %d, want 2", got)
	}

	handle, err := firstState.Resources().Add(resource.KindUDPSocket, &lifecycleResource{})
	if err != nil {
		t.Fatalf("Add first resource: %v", err)
	}
	if _, err := secondState.Resources().Lookup(handle, resource.KindUDPSocket); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("cross-instance Lookup error = %v, want ErrBadHandle", err)
	}

	if _, err := first.Call(context.Background(), "run"); err != nil {
		t.Fatalf("Call first: %v", err)
	}
	if len(observed) != 1 || observed[0] != first || observedState != firstState {
		t.Fatalf("first host identity/state = %v/%p, want %p/%p", observed, observedState, first, firstState)
	}
	if _, err := second.Call(context.Background(), "run"); err != nil {
		t.Fatalf("Call second: %v", err)
	}
	if len(observed) != 2 || observed[1] != second || observedState != secondState {
		t.Fatalf("second host identity/state = %v/%p, want %p/%p", observed, observedState, second, secondState)
	}
}

func TestConfiguredNamespaceUDPHandlesReadinessAndCleanup(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	limits := QuotaLimits{Resources: 2, UDPResources: 1, QueuedBytes: 64}
	readinessConfig := ReadinessConfig{MaxRegistrations: 2}
	extension := Init(Config{
		Policy: PolicyConfig{Rules: []PolicyRule{{
			Action:     PolicyAllow,
			Transports: []PolicyTransport{PolicyTransportUDP},
			Directions: []PolicyDirection{PolicyInbound, PolicyOutbound},
			Prefixes:   []netip.Prefix{prefix},
		}}},
		Limits:    &limits,
		Readiness: &readinessConfig,
		StaticIPv4: &StaticIPv4Config{
			Hostname:               "instance1",
			RandSeed:               1,
			HardwareAddress:        [6]byte{2, 0, 0, 0, 0, 1},
			GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 2},
			IPv4Address:            netip.MustParseAddr("192.0.2.1"),
			MTU:                    1500,
			Link:                   PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
			UDP: UDPConfig{
				MaxSockets:        1,
				ReceiveBytes:      32,
				TransmitBytes:     32,
				ReceiveDatagrams:  1,
				TransmitDatagrams: 1,
				MaxPayloadBytes:   32,
			},
		},
	})
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use: %v", err)
	}
	firstInstance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime))
	if err != nil {
		t.Fatalf("Instantiate first: %v", err)
	}
	secondInstance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime))
	if err != nil {
		t.Fatalf("Instantiate second: %v", err)
	}
	defer secondInstance.Close()
	first, _ := extension.instanceManager().ForInstance(firstInstance)
	second, _ := extension.instanceManager().ForInstance(secondInstance)
	local := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 4100}
	firstUDP, progress, err := first.BindUDP(first.NamespaceHandle(), local)
	if err != nil || progress != namespace.ProgressDone || firstUDP == 0 {
		t.Fatalf("first BindUDP = %v, %v, %v", firstUDP, progress, err)
	}
	secondUDP, progress, err := second.BindUDP(second.NamespaceHandle(), local)
	if err != nil || progress != namespace.ProgressDone || secondUDP == 0 {
		t.Fatalf("second BindUDP = %v, %v, %v", secondUDP, progress, err)
	}
	if _, err := second.Resources().Lookup(firstUDP, resource.KindUDPSocket); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("cross-instance UDP lookup = %v", err)
	}
	if snapshot := first.Readiness().Snapshot(); snapshot.Registrations != 2 || snapshot.Capacity != 2 {
		t.Fatalf("UDP readiness registration = %+v", snapshot)
	}
	events := make([]readiness.Event, 2)
	budget := readiness.Budget{Scans: 2, Events: 2}
	report, pollProgress, err := first.Readiness().TryPoll(events, budget)
	if err != nil || pollProgress != namespace.ProgressDone || report.Events != 2 {
		t.Fatalf("UDP poll = %+v, %v, %v, events=%+v", report, pollProgress, err, events)
	}
	seenUDP := false
	for _, event := range events {
		if event.Handle == firstUDP && event.Readiness == namespace.ReadyWritable {
			seenUDP = true
		}
	}
	if !seenUDP {
		t.Fatalf("UDP writable event missing: %+v", events)
	}
	if err := first.CloseHandle(firstUDP, resource.KindTCPStream); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("wrong-kind close = %v", err)
	}
	if snapshot := first.Readiness().Snapshot(); snapshot.Registrations != 2 {
		t.Fatalf("wrong-kind close changed readiness = %+v", snapshot)
	}
	if err := first.CloseHandle(firstUDP, resource.KindUDPSocket); err != nil {
		t.Fatalf("CloseHandle UDP: %v", err)
	}
	if _, err := first.Resources().Lookup(firstUDP, resource.KindUDPSocket); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("stale UDP handle lookup = %v", err)
	}
	if usage, closed := first.Quotas().Snapshot(); closed || usage.Resources != 1 || usage.UDPResources != 0 || usage.QueuedBytes != 0 {
		t.Fatalf("UDP cleanup quota = %+v, closed=%v", usage, closed)
	}
	rebound, progress, err := first.BindUDP(first.NamespaceHandle(), local)
	if err != nil || progress != namespace.ProgressDone || rebound == 0 || rebound == firstUDP {
		t.Fatalf("UDP rebound = %v, %v, %v", rebound, progress, err)
	}
	if err := firstInstance.Close(); err != nil {
		t.Fatalf("Close first: %v", err)
	}
	if usage, closed := first.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("first teardown quota = %+v, closed=%v", usage, closed)
	}
	if snapshot := first.Readiness().Snapshot(); !snapshot.Closed || snapshot.Registrations != 0 {
		t.Fatalf("first teardown readiness = %+v", snapshot)
	}
	if _, err := first.Resources().Lookup(rebound, resource.KindUDPSocket); !errors.Is(err, resource.ErrClosed) {
		t.Fatalf("teardown stale UDP lookup = %v", err)
	}
}

func TestInstanceStateCleanupOnRepeatedAndConcurrentClose(t *testing.T) {
	for _, test := range []struct {
		name  string
		close func(*wago.Instance)
	}{
		{"repeated", func(instance *wago.Instance) { _ = instance.Close(); _ = instance.Close() }},
		{"concurrent", func(instance *wago.Instance) {
			var wait sync.WaitGroup
			for range 16 {
				wait.Add(1)
				go func() {
					defer wait.Done()
					_ = instance.Close()
				}()
			}
			wait.Wait()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			extension := Init(Config{})
			manager := extension.instanceManager()
			runtime := wago.NewRuntime()
			if err := runtime.Use(extension); err != nil {
				t.Fatalf("Use: %v", err)
			}
			instance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime))
			if err != nil {
				t.Fatalf("Instantiate: %v", err)
			}
			state, ok := manager.ForInstance(instance)
			if !ok {
				t.Fatal("state not attached")
			}
			owned := &lifecycleResource{}
			if _, err := state.Resources().Add(resource.KindTCPStream, owned); err != nil {
				t.Fatalf("Add resource: %v", err)
			}
			test.close(instance)
			if owned.closed.Load() != 1 {
				t.Fatalf("resource close count = %d, want 1", owned.closed.Load())
			}
			if manager.Len() != 0 {
				t.Fatalf("attached states after close = %d, want 0", manager.Len())
			}
			if _, ok := manager.ForInstance(instance); ok {
				t.Fatal("closed instance retained state")
			}
		})
	}
}

func TestInstanceStateCleanupClosesQuotaLedger(t *testing.T) {
	extension := Init(Config{})
	manager := extension.instanceManager()
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use: %v", err)
	}
	instance, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime))
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("state not attached")
	}
	poller := state.Readiness()
	if poller == nil {
		t.Fatal("readiness coordinator not attached")
	}
	pending, err := state.Quotas().ReserveQueuedBytes(4096)
	if err != nil {
		t.Fatalf("ReserveQueuedBytes: %v", err)
	}
	reservation, err := state.Quotas().ReserveDNSWork(1)
	if err != nil {
		t.Fatalf("ReserveDNSWork: %v", err)
	}
	allocation, ok := reservation.Commit()
	if !ok {
		t.Fatal("Commit DNS work failed")
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if usage, closed := state.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("quota after instance close = %+v, closed=%v", usage, closed)
	}
	if snapshot := poller.Snapshot(); !snapshot.Closed || snapshot.Registrations != 0 {
		t.Fatalf("readiness after instance close = %+v", snapshot)
	}
	if _, err := state.Quotas().ReserveService(1); !errors.Is(err, quota.ErrClosed) {
		t.Fatalf("reserve after instance close error = %v", err)
	}
	if !pending.Rollback() || !allocation.Release() {
		t.Fatal("late token cleanup was not locally accepted")
	}
}

func TestInstanceStateCleanupAfterLaterSetupFailure(t *testing.T) {
	setupErr := errors.New("later extension setup failed")
	extension := Init(Config{})
	owned := &lifecycleResource{}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use net extension: %v", err)
	}
	if err := runtime.Use(failingSetupExtension{netup: extension, resource: owned, err: setupErr}); err != nil {
		t.Fatalf("Use failing extension: %v", err)
	}
	if _, err := runtime.Instantiate(context.Background(), emptyModule(t, runtime)); !errors.Is(err, setupErr) {
		t.Fatalf("Instantiate error = %v, want %v", err, setupErr)
	}
	if owned.closed.Load() != 1 {
		t.Fatalf("failed-setup resource close count = %d, want 1", owned.closed.Load())
	}
	if got := extension.instanceManager().Len(); got != 0 {
		t.Fatalf("attached states after failed setup = %d, want 0", got)
	}
}

func TestNetworkingRequirementReinstantiatesSnapshotClass(t *testing.T) {
	limits := QuotaLimits{Resources: 4, UDPResources: 1, TCPResources: 2, QueuedBytes: 2048, ServiceUnits: 64}
	ready := ReadinessConfig{MaxRegistrations: 4}
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	extension := Init(Config{
		Policy: PolicyConfig{Rules: []PolicyRule{{
			Action: PolicyAllow, Transports: []PolicyTransport{PolicyTransportUDP, PolicyTransportTCP},
			Directions: []PolicyDirection{PolicyInbound, PolicyOutbound}, Prefixes: []netip.Prefix{prefix},
		}}},
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &StaticIPv4Config{
			Hostname: "pooled-net", RandSeed: 71,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 71}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 72},
			IPv4Address: netip.MustParseAddr("192.0.2.71"), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8},
			UDP:  UDPConfig{MaxSockets: 1, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32},
			TCP:  TCPConfig{MaxListeners: 1, MaxOutboundStreams: 1, AcceptBacklog: 1, ReceiveBytes: 256, TransmitBytes: 256, TransmitPackets: 4},
		},
	})
	manager := extension.instanceManager()
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use: %v", err)
	}
	class, err := runtime.Class(emptyModule(t, runtime), wago.ClassOptions{
		Pool: wago.PoolOptions{MinInstances: 1, MaxInstances: 1, Reset: wago.ResetMemorySnapshot},
	})
	if err != nil {
		t.Fatalf("Class: %v", err)
	}
	if got := class.ResetPolicy(); got != wago.ResetReinstantiate {
		t.Fatalf("effective reset policy = %v, want reinstantiate", got)
	}

	lease, err := class.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	oldInstance := lease.Instance()
	oldState, ok := manager.ForInstance(oldInstance)
	if !ok {
		t.Fatal("old instance state not attached")
	}
	localUDP := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: 4100}
	udpHandle, progress, err := oldState.BindUDP(oldState.NamespaceHandle(), localUDP)
	if err != nil || progress != namespace.ProgressDone {
		t.Fatalf("BindUDP = %v, %v, %v", udpHandle, progress, err)
	}
	localTCP := namespace.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: 4200}
	tcpHandle, progress, err := oldState.ListenTCP(oldState.NamespaceHandle(), localTCP)
	if err != nil || progress != namespace.ProgressDone {
		t.Fatalf("ListenTCP = %v, %v, %v", tcpHandle, progress, err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok := manager.ForInstance(oldInstance); ok {
		t.Fatal("snapshot-configured class retained old networking state")
	}
	if _, err := oldState.Resources().Lookup(udpHandle, resource.KindUDPSocket); !errors.Is(err, resource.ErrClosed) {
		t.Fatalf("old UDP handle after release = %v, want ErrClosed", err)
	}
	if _, err := oldState.Resources().Lookup(tcpHandle, resource.KindTCPListener); !errors.Is(err, resource.ErrClosed) {
		t.Fatalf("old TCP handle after release = %v, want ErrClosed", err)
	}
	if usage, closed := oldState.Quotas().Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("old quota after release = %+v, closed=%v", usage, closed)
	}

	freshLease, err := class.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire fresh: %v", err)
	}
	freshInstance := freshLease.Instance()
	freshState, ok := manager.ForInstance(freshInstance)
	if !ok || freshInstance == oldInstance || freshState == oldState {
		t.Fatalf("fresh instance/state = %p/%p, old = %p/%p, attached=%v", freshInstance, freshState, oldInstance, oldState, ok)
	}
	if _, err := freshState.Resources().Lookup(udpHandle, resource.KindUDPSocket); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("old UDP handle in fresh lease = %v, want ErrBadHandle", err)
	}
	if _, err := freshState.Resources().Lookup(tcpHandle, resource.KindTCPListener); !errors.Is(err, resource.ErrBadHandle) {
		t.Fatalf("old TCP handle in fresh lease = %v, want ErrBadHandle", err)
	}
	if usage, closed := freshState.Quotas().Snapshot(); closed || usage.Resources != 1 || usage.UDPResources != 0 || usage.TCPResources != 0 {
		t.Fatalf("fresh quota before resources = %+v, closed=%v", usage, closed)
	}
	if rebound, progress, err := freshState.BindUDP(freshState.NamespaceHandle(), localUDP); err != nil || progress != namespace.ProgressDone || rebound == 0 {
		t.Fatalf("fresh BindUDP = %v, %v, %v", rebound, progress, err)
	}
	if relistened, progress, err := freshState.ListenTCP(freshState.NamespaceHandle(), localTCP); err != nil || progress != namespace.ProgressDone || relistened == 0 {
		t.Fatalf("fresh ListenTCP = %v, %v, %v", relistened, progress, err)
	}
	if err := freshLease.Release(); err != nil {
		t.Fatalf("Release fresh: %v", err)
	}
	if err := class.Close(); err != nil {
		t.Fatalf("Class.Close: %v", err)
	}
	if got := manager.Len(); got != 0 {
		t.Fatalf("states after Class.Close = %d, want 0", got)
	}
}
