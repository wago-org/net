// Package dns owns instance-local DNS operations over the shared lifecycle core.
package dns

import (
	core "github.com/wago-org/net/internal/instance/core"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

// Resolve owns and poll-registers one immediate or in-progress DNS query.
func Resolve(state *core.State, namespaceHandle resource.Handle, request namespace.DNSRequest) (handle resource.Handle, progress namespace.Progress, err error) {
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
		query, backendProgress, backendErr := backend.TryResolve(request)
		progress = backendProgress
		if backendErr != nil {
			return backendErr
		}
		if (progress != namespace.ProgressDone && progress != namespace.ProgressInProgress) || query == nil {
			if query != nil {
				_ = query.Close()
			}
			progress = 0
			return namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
		}
		handle, err = locked.Resources.Add(resource.KindDNSQuery, query)
		if err != nil {
			_ = query.Close()
			return err
		}
		if err = locked.Readiness.Register(handle, resource.KindDNSQuery); err != nil {
			_ = locked.Resources.CloseHandle(handle, resource.KindDNSQuery)
			handle = 0
			progress = 0
			return err
		}
		return nil
	})
	return
}

// Next performs one nonblocking copied-record read from an exact live query.
func Next(state *core.State, handle resource.Handle) (record namespace.DNSRecord, next namespace.DNSNext, err error) {
	err = state.WithLock(func(locked core.LockedState) error {
		query, lookupErr := lookupQuery(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		record, next, err = query.TryNext()
		if err == nil && next == namespace.DNSNextReady && !record.Valid() {
			record, next = namespace.DNSRecord{}, 0
			return namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
		}
		if err == nil && next != namespace.DNSNextReady && next != namespace.DNSNextWouldBlock && next != namespace.DNSNextEOF {
			record, next = namespace.DNSRecord{}, 0
			return namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
		}
		return err
	})
	return
}

// Cancel makes one unfinished query terminal without retiring its handle.
func Cancel(state *core.State, handle resource.Handle) (err error) {
	return state.WithLock(func(locked core.LockedState) error {
		query, lookupErr := lookupQuery(locked, handle)
		if lookupErr != nil {
			return lookupErr
		}
		return query.Cancel()
	})
}

func lookupQuery(locked core.LockedState, handle resource.Handle) (namespace.DNSQuery, error) {
	value, err := locked.Resources.Lookup(handle, resource.KindDNSQuery)
	if err != nil {
		return nil, err
	}
	query, ok := value.(namespace.DNSQuery)
	if !ok {
		return nil, namespace.Fail(namespace.FailureIO, core.ErrInvalidBackendResult)
	}
	return query, nil
}
