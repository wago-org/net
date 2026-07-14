// Package mdns owns exact-instance multicast DNS query and announcement operations.
package mdns

import (
	core "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
	"github.com/wago-org/net/internal/resource"
)

func Query(state *core.State, namespaceHandle resource.Handle, request mdnsns.Request) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := namespace(locked, namespaceHandle)
		if lookupErr != nil {
			return lookupErr
		}
		value, backendProgress, backendErr := backend.TryQuery(request)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		typed, ok := value.(mdnsns.Query)
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || !ok || resource.IsNil(typed) {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindMDNSQuery, typed)
		if err != nil {
			_ = typed.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindMDNSQuery); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindMDNSQuery)
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

func Next(state *core.State, handle resource.Handle) (record mdnsns.Record, next mdnsns.Next, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		query, lookupErr := lookupQuery(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		record, next, err = query.TryNext()
		if err != nil {
			record, next = mdnsns.Record{}, 0
			return err
		}
		switch next {
		case mdnsns.NextReady:
			if !record.Valid() {
				record, next = mdnsns.Record{}, 0
				return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
			}
		case mdnsns.NextWouldBlock, mdnsns.NextEOF:
			record = mdnsns.Record{}
		default:
			record, next = mdnsns.Record{}, 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	if err != nil {
		record, next = mdnsns.Record{}, 0
	}
	return
}

func CancelQuery(state *core.State, handle resource.Handle) error {
	return state.WithLock(func(locked core.LockedState) error {
		query, err := lookupQuery(locked, handle)
		if err != nil {
			return err
		}
		return query.Cancel()
	})
}

func Announce(state *core.State, namespaceHandle resource.Handle, service uint16) (handle resource.Handle, progress nscore.Progress, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		backend, lookupErr := namespace(locked, namespaceHandle)
		if lookupErr != nil {
			return lookupErr
		}
		value, backendProgress, backendErr := backend.TryAnnounce(service)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		typed, ok := value.(mdnsns.Announcement)
		if (progress != nscore.ProgressDone && progress != nscore.ProgressInProgress) || !ok || resource.IsNil(typed) {
			if !resource.IsNil(value) {
				_ = value.Close()
			}
			progress = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindMDNSAnnouncement, typed)
		if err != nil {
			_ = typed.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindMDNSAnnouncement); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindMDNSAnnouncement)
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

func FinishAnnouncement(state *core.State, handle resource.Handle) (next mdnsns.Next, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		announcement, lookupErr := lookupAnnouncement(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		next, err = announcement.TryFinish()
		if err != nil {
			next = 0
			return err
		}
		if next != mdnsns.NextReady && next != mdnsns.NextWouldBlock {
			next = 0
			return nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
		}
		return nil
	})
	if err != nil {
		next = 0
	}
	return
}

func CancelAnnouncement(state *core.State, handle resource.Handle) error {
	return state.WithLock(func(locked core.LockedState) error {
		announcement, err := lookupAnnouncement(locked, handle)
		if err != nil {
			return err
		}
		return announcement.Cancel()
	})
}

func namespace(locked core.LockedState, handle resource.Handle) (mdnsns.Namespace, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindNamespace)
	if err != nil {
		return nil, err
	}
	backend, ok := nscore.ResolveNamespaceService(value, mdnsns.ServiceKey).(mdnsns.Namespace)
	if !ok || resource.IsNil(backend) {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return backend, nil
}

func lookupQuery(locked core.LockedState, handle resource.Handle) (mdnsns.Query, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindMDNSQuery)
	if err != nil {
		return nil, err
	}
	query, ok := value.(mdnsns.Query)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return query, nil
}

func lookupAnnouncement(locked core.LockedState, handle resource.Handle) (mdnsns.Announcement, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindMDNSAnnouncement)
	if err != nil {
		return nil, err
	}
	announcement, ok := value.(mdnsns.Announcement)
	if !ok {
		return nil, nscore.Fail(nscore.FailureIO, core.ErrInvalidBackendResult)
	}
	return announcement, nil
}
