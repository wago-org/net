// Package dhcpv6 owns exact-instance DHCPv6 acquisition operations.
package dhcpv6

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/resource"
)

func Operations(state *core.State, namespaceHandle resource.Handle) (operations dhcpns.Operations, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := namespace(locked, namespaceHandle)
		if lookupErr != nil {
			return lookupErr
		}
		operations = backend.Operations()
		if operations == 0 {
			return nscore.Fail(nscore.FailureNotSupported, core.ErrInvalidBackendResult)
		}
		if operations&^dhcpns.SupportedOperations != 0 {
			operations = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}

func Start(state *core.State, namespaceHandle resource.Handle, operation dhcpns.Operation) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := namespace(locked, namespaceHandle)
		if lookupErr != nil {
			return lookupErr
		}
		if operation != dhcpns.OperationAcquire {
			if operation >= dhcpns.OperationRenew && operation <= dhcpns.OperationRawPacket {
				return nscore.Fail(nscore.FailureNotSupported, core.ErrInvalidBackendResult)
			}
			return nscore.Fail(nscore.FailureInvalidArgument, core.ErrInvalidBackendResult)
		}
		value, backendProgress, backendErr := backend.TryAcquire()
		progress = backendProgress
		if backendErr != nil {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			progress = 0
			return backendErr
		}
		lease, ok := value.(dhcpns.Resource)
		if !ok || resource.IsNil(lease) || (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindDHCPv6Lease, lease)
		if err != nil {
			_ = lease.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindDHCPv6Lease); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindDHCPv6Lease)
			handle, progress = 0, 0
			return err
		}
		return nil
	})
	if err != nil {
		handle, progress = 0, 0
	}
	return
}

func Result(state *core.State, handle resource.Handle) (configuration dhcpns.Configuration, result dhcpns.ResultState, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := lookup(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		configuration, result, err = value.TryResult()
		if err != nil {
			configuration, result = dhcpns.Configuration{}, 0
			return err
		}
		if result == dhcpns.ResultWouldBlock {
			configuration = dhcpns.Configuration{}
			return nil
		}
		if result != dhcpns.ResultReady || !configuration.Valid() {
			configuration, result = dhcpns.Configuration{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}

func Cancel(state *core.State, handle resource.Handle) error {
	return state.WithLock(func(locked core.LockedState) error {
		value, err := lookup(locked, handle)
		if err != nil {
			return err
		}
		return value.Cancel()
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
	value, err := locked.Resources.Lookup(handle, resource.KindDHCPv6Lease)
	if err != nil {
		return nil, err
	}
	lease, ok := value.(dhcpns.Resource)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return lease, nil
}
