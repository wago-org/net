// Package linklocal4 owns exact-instance IPv4 link-local claim operations.
package linklocal4

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/resource"
)

func Claim(state *core.State, namespaceHandle resource.Handle, request linklocalns.Request) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := namespace(locked, namespaceHandle)
		if lookupErr != nil {
			return lookupErr
		}
		value, backendProgress, backendErr := backend.TryClaim(request)
		progress = backendProgress
		if backendErr != nil {
			progress = 0
			return backendErr
		}
		claim, ok := value.(linklocalns.Resource)
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || !ok || resource.IsNil(claim) {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindLinkLocal4Claim, claim)
		if err != nil {
			_ = claim.Close()
			progress = 0
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindLinkLocal4Claim); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindLinkLocal4Claim)
			handle, progress = 0, 0
			return err
		}
		return nil
	})
	return
}

func Result(state *core.State, handle resource.Handle) (result linklocalns.Result, stateResult linklocalns.ResultState, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		value, lookupErr := lookup(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		result, stateResult, err = value.TryResult()
		if err != nil {
			result, stateResult = linklocalns.Result{}, 0
			return err
		}
		if stateResult == linklocalns.ResultWouldBlock {
			result = linklocalns.Result{}
			return nil
		}
		if stateResult != linklocalns.ResultReady || !result.Valid() {
			result, stateResult = linklocalns.Result{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	return
}

func Cancel(state *core.State, handle resource.Handle) error {
	return withClaim(state, handle, func(value linklocalns.Resource) error { return value.Cancel() })
}

func Release(state *core.State, handle resource.Handle) error {
	return withClaim(state, handle, func(value linklocalns.Resource) error { return value.Release() })
}

func withClaim(state *core.State, handle resource.Handle, operation func(linklocalns.Resource) error) error {
	return state.WithLock(func(locked core.LockedState) error {
		value, err := lookup(locked, handle)
		if err != nil {
			return err
		}
		return operation(value)
	})
}

func namespace(locked core.LockedState, handle resource.Handle) (linklocalns.Namespace, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindNamespace)
	if err != nil {
		return nil, err
	}
	backend, ok := nscore.ResolveNamespaceService(value, linklocalns.ServiceKey).(linklocalns.Namespace)
	if !ok || resource.IsNil(backend) {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return backend, nil
}

func lookup(locked core.LockedState, handle resource.Handle) (linklocalns.Resource, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindLinkLocal4Claim)
	if err != nil {
		return nil, err
	}
	claim, ok := value.(linklocalns.Resource)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return claim, nil
}
