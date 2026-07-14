// Package icmpv4 owns instance-local ICMPv4 operations over the shared core.
package icmpv4

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
	"github.com/wago-org/net/internal/resource"
)

// Echo owns and poll-registers one immediate or in-progress exchange.
func Echo(state *core.State, namespaceHandle resource.Handle, request icmpns.Request) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		backend, ok := nscore.ResolveNamespaceService(value, icmpns.ServiceKey).(icmpns.Namespace)
		if !ok || resource.IsNil(backend) {
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		exchange, backendProgress, backendErr := backend.TryEcho(request)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		typed, ok := exchange.(icmpns.Echo)
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || !ok || resource.IsNil(typed) {
			if !resource.IsNil(exchange) {
				_ = exchange.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindICMPv4Echo, typed)
		if err != nil {
			_ = exchange.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindICMPv4Echo); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindICMPv4Echo)
			handle = 0
			progress = 0
			return err
		}
		return nil
	})
	return
}

// Result performs one nonblocking copied reply read from an exact exchange.
func Result(state *core.State, handle resource.Handle, dst []byte) (result icmpns.Result, next icmpns.Next, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		exchange, lookupErr := lookupEcho(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, next, err = exchange.TryResult(dst)
		if err == nil && next == icmpns.NextReady && !result.Valid(len(dst)) {
			result, next = icmpns.Result{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		if err == nil && next != icmpns.NextReady && next != icmpns.NextWouldBlock {
			result, next = icmpns.Result{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return err
	})
	return
}

// Cancel makes one unfinished exchange terminal without retiring its handle.
func Cancel(state *core.State, handle resource.Handle) error {
	return state.WithLock(func(locked core.LockedState) error {
		exchange, err := lookupEcho(locked, handle)
		if err != nil {
			return err
		}
		return exchange.Cancel()
	})
}

func lookupEcho(locked core.LockedState, handle resource.Handle) (icmpns.Echo, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindICMPv4Echo)
	if err != nil {
		return nil, err
	}
	exchange, ok := value.(icmpns.Echo)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return exchange, nil
}
