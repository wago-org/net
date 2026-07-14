// Package dhcpv4 owns exact-instance DHCPv4 lease operations.
package dhcpv4

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
	"github.com/wago-org/net/internal/resource"
)

func Acquire(state *core.State, namespaceHandle resource.Handle, request dhcpns.Request) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := namespace(locked, namespaceHandle)
		if lookupErr != nil {
			return lookupErr
		}
		value, backendProgress, backendErr := backend.TryAcquire(request)
		progress = backendProgress
		if backendErr != nil {
			progress = 0
			return backendErr
		}
		lease, ok := value.(dhcpns.Resource)
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || !ok || resource.IsNil(lease) {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindDHCPv4Lease, lease)
		if err != nil {
			_ = lease.Close()
			progress = 0
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindDHCPv4Lease); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindDHCPv4Lease)
			handle, progress = 0, 0
			return err
		}
		return nil
	})
	return
}

func Result(state *core.State, handle resource.Handle) (lease dhcpns.Lease, result dhcpns.ResultState, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := lookup(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		lease, result, err = value.TryResult()
		if err != nil {
			lease, result = dhcpns.Lease{}, 0
			return err
		}
		if result == dhcpns.ResultWouldBlock {
			lease = dhcpns.Lease{}
			return nil
		}
		if result != dhcpns.ResultReady || !lease.Valid() {
			lease, result = dhcpns.Lease{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}

func Cancel(state *core.State, handle resource.Handle) error {
	return withLease(state, handle, func(value dhcpns.Resource) error { return value.Cancel() })
}

func Release(state *core.State, handle resource.Handle) error {
	return withLease(state, handle, func(value dhcpns.Resource) error { return value.Release() })
}

func withLease(state *core.State, handle resource.Handle, operation func(dhcpns.Resource) error) error {
	return state.WithLock(func(locked core.LockedState) error {
		value, err := lookup(locked, handle)
		if err != nil {
			return err
		}
		return operation(value)
	})
}

func namespace(locked core.LockedState, handle resource.Handle) (dhcpns.Namespace, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindNamespace)
	if err != nil {
		return nil, err
	}
	backend, ok := nscore.ResolveNamespaceService(value, dhcpns.ServiceKey).(dhcpns.Namespace)
	if !ok || resource.IsNil(backend) {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return backend, nil
}

func lookup(locked core.LockedState, handle resource.Handle) (dhcpns.Resource, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindDHCPv4Lease)
	if err != nil {
		return nil, err
	}
	lease, ok := value.(dhcpns.Resource)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return lease, nil
}
