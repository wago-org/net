// Package udp owns instance-local UDP operations over the shared lifecycle core.
package udp

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/resource"
)

// Bind transactionally creates, owns, and poll-registers one backend socket.
func Bind(state *core.State, namespaceHandle resource.Handle, local nscore.Endpoint) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		backend, ok := nscore.ResolveNamespaceService(value, udpns.ServiceKey).(udpns.Namespace)
		if !ok {
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		socket, backendProgress, backendErr := backend.TryBindUDP(local)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		if progress == nscore.ProgressWouldBlock {
			if socket != nil {
				_ = socket.Close()
				progress = 0
				return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
			}
			return nil
		}
		if progress != nscore.ProgressDone || socket == nil {
			if socket != nil {
				_ = socket.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		typedSocket, ok := socket.(udpns.Socket)
		if !ok {
			_ = socket.Close()
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindUDPSocket, typedSocket)
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
func Send(state *core.State, handle resource.Handle, payload []byte, remote nscore.Endpoint) (progress nscore.Progress, err error) {
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
func Receive(state *core.State, handle resource.Handle, dst []byte) (result udpns.DatagramResult, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		socket, lookupErr := lookupSocket(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, err = socket.TryReceive(dst)
		if err == nil && !result.Valid(len(dst)) {
			result = udpns.DatagramResult{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return err
	})
	return
}

func lookupSocket(locked core.LockedState, handle resource.Handle) (udpns.Socket, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindUDPSocket)
	if err != nil {
		return nil, err
	}
	socket, ok := value.(udpns.Socket)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return socket, nil
}
