// Package ntp owns instance-local NTP operations over the shared core.
package ntp

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
	"github.com/wago-org/net/internal/resource"
)

// Sync owns and poll-registers one immediate or in-progress synchronization.
func Sync(state *core.State, namespaceHandle resource.Handle) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := locked.Resources.Lookup(namespaceHandle, resource.KindNamespace)
		if lookupErr != nil {
			return lookupErr
		}
		backend, ok := nscore.ResolveNamespaceService(value, ntpns.ServiceKey).(ntpns.Namespace)
		if !ok || resource.IsNil(backend) {
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		synchronization, backendProgress, backendErr := backend.TrySync()
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		typed, ok := synchronization.(ntpns.Sync)
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || !ok || resource.IsNil(typed) {
			if !resource.IsNil(synchronization) {
				_ = synchronization.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindNTPSync, typed)
		if err != nil {
			_ = synchronization.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindNTPSync); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindNTPSync)
			handle = 0
			progress = 0
			return err
		}
		return nil
	})
	return
}

// Result performs one nonblocking sample read from an exact synchronization.
func Result(state *core.State, handle resource.Handle) (sample ntpns.Sample, next ntpns.Next, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		synchronization, lookupErr := lookupSync(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		sample, next, err = synchronization.TryResult()
		if err == nil && next == ntpns.NextReady && !sample.Valid() {
			sample, next = ntpns.Sample{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		if err == nil && next != ntpns.NextReady && next != ntpns.NextWouldBlock {
			sample, next = ntpns.Sample{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return err
	})
	return
}

// Cancel makes one unfinished synchronization terminal without retiring its
// handle.
func Cancel(state *core.State, handle resource.Handle) error {
	return state.WithLock(func(locked core.LockedState) error {
		synchronization, err := lookupSync(locked, handle)
		if err != nil {
			return err
		}
		return synchronization.Cancel()
	})
}

func lookupSync(locked core.LockedState, handle resource.Handle) (ntpns.Sync, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindNTPSync)
	if err != nil {
		return nil, err
	}
	synchronization, ok := value.(ntpns.Sync)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return synchronization, nil
}
