package net

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

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
	if !firstOK || !secondOK || firstState == secondState || firstState.Resources() == secondState.Resources() {
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

func TestResetReinstantiateReleaseCleansOldInstanceState(t *testing.T) {
	extension := Init(Config{})
	manager := extension.instanceManager()
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use: %v", err)
	}
	class, err := runtime.Class(emptyModule(t, runtime), wago.ClassOptions{
		Pool: wago.PoolOptions{MaxInstances: 1, Reset: wago.ResetReinstantiate},
	})
	if err != nil {
		t.Fatalf("Class: %v", err)
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
	owned := &lifecycleResource{}
	if _, err := oldState.Resources().Add(resource.KindDNSQuery, owned); err != nil {
		t.Fatalf("Add resource: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if owned.closed.Load() != 1 {
		t.Fatalf("released resource close count = %d, want 1", owned.closed.Load())
	}
	if _, ok := manager.ForInstance(oldInstance); ok {
		t.Fatal("ResetReinstantiate retained old instance state")
	}
	if got := manager.Len(); got != 1 {
		t.Fatalf("fresh idle instance states = %d, want 1", got)
	}
	if err := class.Close(); err != nil {
		t.Fatalf("Class.Close: %v", err)
	}
	if got := manager.Len(); got != 0 {
		t.Fatalf("states after Class.Close = %d, want 0", got)
	}
}
