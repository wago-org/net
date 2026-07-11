// Package udp owns instance-local UDP operations over the shared lifecycle core.
package udp

import (
	core "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

// Bind transactionally creates, owns, and poll-registers one backend socket.
func Bind(state *core.State, namespaceHandle resource.Handle, local namespace.Endpoint) (handle resource.Handle, progress namespace.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		if carrier, ok := value.(nscore.NamespaceCarrier); ok {
			value = carrier.NamespaceBackend()
		}
		backend, ok := value.(namespace.Namespace)
		if !ok {
			return namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
		}
		socket, backendProgress, backendErr := backend.TryBindUDP(local)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		if progress == namespace.ProgressWouldBlock {
			if socket != nil {
				_ = socket.Close()
				progress = 0
				return namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
			}
			return nil
		}
		if progress != namespace.ProgressDone || socket == nil {
			if socket != nil {
				_ = socket.Close()
			}
			progress = 0
			return namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindUDPSocket, socket)
		if err != nil {
			_ = socket.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindUDPSocket); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindUDPSocket)
			handle = 0
			progress = 0
			return err
		}
		return nil
	})
	return
}

// Send performs one nonblocking datagram send through an exact live handle.
func Send(state *core.State, handle resource.Handle, payload []byte, remote namespace.Endpoint) (progress namespace.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		socket, lookupErr := lookupSocket(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		progress, err = socket.TrySend(payload, remote)
		return err
	})
	return
}

// Receive performs one nonblocking datagram receive through an exact handle.
func Receive(state *core.State, handle resource.Handle, dst []byte) (result namespace.DatagramResult, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		socket, lookupErr := lookupSocket(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, err = socket.TryReceive(dst)
		if err == nil && !result.Valid(len(dst)) {
			result = namespace.DatagramResult{}
			return namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
		}
		return err
	})
	return
}

func lookupSocket(locked core.LockedState, handle resource.Handle) (namespace.UDPSocket, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindUDPSocket)
	if err != nil {
		return nil, err
	}
	socket, ok := value.(namespace.UDPSocket)
	if !ok {
		return nil, namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
	}
	return socket, nil
}
