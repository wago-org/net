// Package icmpv6 owns exact-instance ICMPv6/NDP resource operations.
package icmpv6

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/resource"
)

func Operations(state *core.State, namespace resource.Handle) (operations icmpns.Operations, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := lookupNamespace(locked, namespace)
		if lookupErr != nil {
			return lookupErr
		}
		operations = backend.Operations()
		if operations&^icmpns.SupportedOperations != 0 {
			operations = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		if operations == 0 {
			return nscore.Fail(nscore.FailureNotSupported, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}

func Echo(state *core.State, namespace resource.Handle, request icmpns.EchoRequest) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := lookupNamespace(locked, namespace)
		if lookupErr != nil {
			return lookupErr
		}
		value, backendProgress, backendErr := backend.TryEcho(request)
		progress = backendProgress
		if backendErr != nil {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			return backendErr
		}
		typed, ok := value.(icmpns.Echo)
		if !ok || resource.IsNil(typed) || (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindICMPv6Echo, typed)
		if err != nil {
			_ = typed.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindICMPv6Echo); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindICMPv6Echo)
			handle = 0
			return err
		}
		return nil
	})
	if err != nil {
		handle, progress = 0, 0
	}
	return
}

func EchoResult(state *core.State, handle resource.Handle, dst []byte) (result icmpns.EchoResult, next icmpns.Next, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		echo, lookupErr := lookupEcho(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		scratchSize := min(len(dst), icmpns.MaxEchoPayloadBytes)
		scratch := locked.OutputScratch(scratchSize)
		result, next, err = echo.TryResult(scratch)
		if err != nil {
			result, next = icmpns.EchoResult{}, 0
			return err
		}
		if next == icmpns.NextWouldBlock {
			result = icmpns.EchoResult{}
			return nil
		}
		if next != icmpns.NextReady || !result.Valid(scratchSize) {
			result, next = icmpns.EchoResult{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		copy(dst, scratch[:result.Copied])
		return nil
	})
	return
}

func CancelEcho(state *core.State, handle resource.Handle) error {
	return state.WithLock(func(locked core.LockedState) error {
		echo, err := lookupEcho(locked, handle)
		if err != nil {
			return err
		}
		return echo.Cancel()
	})
}

func Resolve(state *core.State, namespace resource.Handle, request icmpns.NeighborRequest) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := lookupNamespace(locked, namespace)
		if lookupErr != nil {
			return lookupErr
		}
		value, backendProgress, backendErr := backend.TryResolve(request)
		progress = backendProgress
		if backendErr != nil {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			return backendErr
		}
		typed, ok := value.(icmpns.Resolution)
		if !ok || resource.IsNil(typed) || (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindICMPv6Neighbor, typed)
		if err != nil {
			_ = typed.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindICMPv6Neighbor); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindICMPv6Neighbor)
			handle = 0
			return err
		}
		return nil
	})
	if err != nil {
		handle, progress = 0, 0
	}
	return
}

func NeighborResult(state *core.State, handle resource.Handle) (result icmpns.Neighbor, next icmpns.Next, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		resolution, lookupErr := lookupResolution(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, next, err = resolution.TryResult()
		if err != nil {
			result, next = icmpns.Neighbor{}, 0
			return err
		}
		if next == icmpns.NextReady && !result.Valid() {
			result, next = icmpns.Neighbor{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		if next != icmpns.NextReady && next != icmpns.NextWouldBlock {
			result, next = icmpns.Neighbor{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}

func CancelNeighbor(state *core.State, handle resource.Handle) error {
	return state.WithLock(func(locked core.LockedState) error {
		resolution, err := lookupResolution(locked, handle)
		if err != nil {
			return err
		}
		return resolution.Cancel()
	})
}

func Lookup(state *core.State, namespace resource.Handle, request icmpns.NeighborRequest) (neighbor icmpns.Neighbor, found bool, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := lookupNamespace(locked, namespace)
		if lookupErr != nil {
			return lookupErr
		}
		neighbor, found, err = backend.LookupNeighbor(request)
		if err != nil {
			neighbor, found = icmpns.Neighbor{}, false
			return err
		}
		if found && !neighbor.Valid() {
			neighbor, found = icmpns.Neighbor{}, false
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		if !found {
			neighbor = icmpns.Neighbor{}
		}
		return nil
	})
	return
}

func Seed(state *core.State, namespace resource.Handle, neighbor icmpns.Neighbor) error {
	return state.WithLock(func(locked core.LockedState) error {
		backend, err := lookupNamespace(locked, namespace)
		if err != nil {
			return err
		}
		return backend.SeedNeighbor(neighbor)
	})
}

func Remove(state *core.State, namespace resource.Handle, request icmpns.NeighborRequest) error {
	return state.WithLock(func(locked core.LockedState) error {
		backend, err := lookupNamespace(locked, namespace)
		if err != nil {
			return err
		}
		return backend.RemoveNeighbor(request)
	})
}

func lookupNamespace(locked core.LockedState, handle resource.Handle) (icmpns.Namespace, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindNamespace)
	if err != nil {
		return nil, err
	}
	backend, ok := nscore.ResolveNamespaceService(value, icmpns.ServiceKey).(icmpns.Namespace)
	if !ok || resource.IsNil(backend) {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return backend, nil
}

func lookupEcho(locked core.LockedState, handle resource.Handle) (icmpns.Echo, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindICMPv6Echo)
	if err != nil {
		return nil, err
	}
	echo, ok := value.(icmpns.Echo)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return echo, nil
}

func lookupResolution(locked core.LockedState, handle resource.Handle) (icmpns.Resolution, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindICMPv6Neighbor)
	if err != nil {
		return nil, err
	}
	resolution, ok := value.(icmpns.Resolution)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return resolution, nil
}
