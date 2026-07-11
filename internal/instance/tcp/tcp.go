// Package tcp owns instance-local TCP operations over the shared lifecycle core.
package tcp

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	"github.com/wago-org/net/internal/resource"
)

// Listen transactionally creates, owns, and poll-registers one listener.
func Listen(state *core.State, namespaceHandle resource.Handle, local nscore.Endpoint) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		backend, ok := nscore.ResolveNamespaceService(value, tcpns.ServiceKey).(tcpns.Namespace)
		if !ok {
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		listener, backendProgress, backendErr := backend.TryListenTCP(local)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		if progress != nscore.ProgressDone || listener == nil {
			if listener != nil {
				_ = listener.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		typedListener, ok := listener.(tcpns.Listener)
		if !ok {
			_ = listener.Close()
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindTCPListener, typedListener)
		if err != nil {
			_ = listener.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindTCPListener); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindTCPListener)
			handle = 0
			progress = 0
			return err
		}
		return nil
	})
	return
}

// Connect owns and poll-registers one immediate or in-progress stream.
func Connect(state *core.State, namespaceHandle resource.Handle, remote nscore.Endpoint) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		backend, ok := nscore.ResolveNamespaceService(value, tcpns.ServiceKey).(tcpns.Namespace)
		if !ok {
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		stream, backendProgress, backendErr := backend.TryConnectTCP(remote)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || stream == nil {
			if stream != nil {
				_ = stream.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		typedStream, ok := stream.(tcpns.Stream)
		if !ok {
			_ = stream.Close()
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = ownStream(locked, typedStream)
		if err != nil {
			progress = 0
		}
		return err
	})
	return
}

// Accept owns one fully established stream returned by a live listener.
func Accept(state *core.State, listenerHandle resource.Handle) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(listenerHandle, resource.KindTCPListener)
		if lookupErr != nil {
			return lookupErr
		}
		listener, ok := value.(tcpns.Listener)
		if !ok {
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		stream, backendProgress, backendErr := listener.TryAccept()
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		if progress == nscore.ProgressWouldBlock {
			if stream != nil {
				_ = stream.Close()
				progress = 0
				return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
			}
			return nil
		}
		if progress != nscore.ProgressDone || stream == nil {
			if stream != nil {
				_ = stream.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		typedStream, ok := stream.(tcpns.Stream)
		if !ok {
			_ = stream.Close()
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = ownStream(locked, typedStream)
		if err != nil {
			progress = 0
		}
		return err
	})
	return
}

func ownStream(locked core.LockedState, stream tcpns.Stream) (resource.Handle, error) {
	handle, err := locked.Resources.Add(resource.KindTCPStream, stream)
	if err != nil {
		_ = stream.Close()
		return 0, err
	}
	if err := locked.Readiness.Register(handle, resource.KindTCPStream); err != nil {
		_ = locked.Resources.CloseHandle(handle, resource.KindTCPStream)
		return 0, err
	}
	return handle, nil
}

// Endpoints returns backend-neutral local and remote endpoints for one stream.
func Endpoints(state *core.State, handle resource.Handle) (local, remote nscore.Endpoint, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		local, remote = stream.LocalEndpoint(), stream.RemoteEndpoint()
		if !local.Valid() || !remote.Valid() {
			local, remote = nscore.Endpoint{}, nscore.Endpoint{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}

// FinishConnect performs one nonblocking connection-completion check.
func FinishConnect(state *core.State, handle resource.Handle) (progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		progress, err = stream.TryFinishConnect()
		return err
	})
	return
}

// Read performs one bounded stream read into caller-owned memory.
func Read(state *core.State, handle resource.Handle, dst []byte) (result nscore.IOResult, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, err = stream.TryRead(dst)
		if err == nil && !result.Valid(len(dst)) {
			result = nscore.IOResult{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return err
	})
	return
}

// Write performs one bounded partial stream write from caller-owned memory.
func Write(state *core.State, handle resource.Handle, src []byte) (result nscore.IOResult, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, err = stream.TryWrite(src)
		if err == nil && !result.Valid(len(src)) {
			result = nscore.IOResult{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return err
	})
	return
}

// ShutdownWrite initiates a nonblocking write-half close.
func ShutdownWrite(state *core.State, handle resource.Handle) (progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		progress, err = stream.TryShutdownWrite()
		return err
	})
	return
}

func lookupStream(locked core.LockedState, handle resource.Handle) (tcpns.Stream, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindTCPStream)
	if err != nil {
		return nil, err
	}
	stream, ok := value.(tcpns.Stream)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return stream, nil
}
