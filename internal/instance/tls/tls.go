// Package tls owns instance-local secure-stream operations.
package tls

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/resource"
)

func Connect(state *core.State, namespaceHandle resource.Handle, remote nscore.Endpoint, profileID uint32, serverName string) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		backend, ok := nscore.ResolveNamespaceService(value, tlsns.ServiceKey).(tlsns.Namespace)
		if !ok || resource.IsNil(backend) {
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		created, backendProgress, backendErr := backend.TryConnectTLS(remote, profileID, serverName)
		progress = backendProgress
		if backendErr != nil {
			if !resource.IsNil(created) {
				_ = created.Close()
			}
			return backendErr
		}
		stream, ok := created.(tlsns.Stream)
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || !ok || resource.IsNil(stream) {
			if !resource.IsNil(created) {
				_ = created.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindTLSStream, stream)
		if err != nil {
			_ = stream.Close()
			progress = 0
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindTLSStream); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindTLSStream)
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

func FinishConnect(state *core.State, handle resource.Handle) (progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		progress, err = stream.TryFinishConnect()
		if err != nil {
			progress = 0
			return err
		}
		if !progress.Valid() {
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	if err != nil {
		progress = 0
	}
	return
}

func Read(state *core.State, handle resource.Handle, dst []byte) (result nscore.IOResult, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		scratchSize := min(len(dst), tlsns.MaxReadBytes)
		scratch := locked.OutputScratch(scratchSize)
		result, err = stream.TryRead(scratch)
		if err != nil {
			result = nscore.IOResult{}
			return err
		}
		if !result.Valid(scratchSize) {
			result = nscore.IOResult{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		if result.State == nscore.IOReady {
			copy(dst, scratch[:result.Bytes])
		}
		return nil
	})
	if err != nil {
		result = nscore.IOResult{}
	}
	return
}

func Write(state *core.State, handle resource.Handle, src []byte) (result nscore.IOResult, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, err = stream.TryWrite(src)
		if err != nil {
			result = nscore.IOResult{}
			return err
		}
		if !result.Valid(len(src)) {
			result = nscore.IOResult{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	if err != nil {
		result = nscore.IOResult{}
	}
	return
}

func ShutdownWrite(state *core.State, handle resource.Handle) (progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		progress, err = stream.TryShutdownWrite()
		if err != nil {
			progress = 0
			return err
		}
		if !progress.Valid() {
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	if err != nil {
		progress = 0
	}
	return
}

func ConnectionInfo(state *core.State, handle resource.Handle) (info tlsns.ConnectionInfo, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		stream, lookupErr := lookupStream(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		var ok bool
		info, ok = stream.ConnectionInfo()
		if !ok {
			progress = nscore.ProgressWouldBlock
			return nil
		}
		if !info.Valid(32) {
			info = tlsns.ConnectionInfo{}
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		progress = nscore.ProgressDone
		return nil
	})
	if err != nil {
		info, progress = tlsns.ConnectionInfo{}, 0
	}
	return
}

func lookupStream(locked core.LockedState, handle resource.Handle) (tlsns.Stream, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindTLSStream)
	if err != nil {
		return nil, err
	}
	stream, ok := value.(tlsns.Stream)
	if !ok || resource.IsNil(stream) {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return stream, nil
}
