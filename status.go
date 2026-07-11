package net

import (
	"github.com/wago-org/net/internal/guest"
	"github.com/wago-org/net/internal/namespace"
)

// Status is a stable numeric result returned by networking host imports. Unknown
// internal errors map to StatusOther; Go error strings are never part of the
// guest ABI.
type Status = guest.Status

const (
	StatusOK                  = guest.StatusOK
	StatusAgain               = guest.StatusAgain
	StatusInProgress          = guest.StatusInProgress
	StatusEOF                 = guest.StatusEOF
	StatusAccessDenied        = guest.StatusAccessDenied
	StatusInvalidArgument     = guest.StatusInvalidArgument
	StatusBadHandle           = guest.StatusBadHandle
	StatusInvalidState        = guest.StatusInvalidState
	StatusNotSupported        = guest.StatusNotSupported
	StatusNoMemory            = guest.StatusNoMemory
	StatusResourceLimit       = guest.StatusResourceLimit
	StatusAddressInUse        = guest.StatusAddressInUse
	StatusAddressNotAvailable = guest.StatusAddressNotAvailable
	StatusRemoteUnreachable   = guest.StatusRemoteUnreachable
	StatusConnectionRefused   = guest.StatusConnectionRefused
	StatusConnectionReset     = guest.StatusConnectionReset
	StatusConnectionAborted   = guest.StatusConnectionAborted
	StatusConnectionBroken    = guest.StatusConnectionBroken
	StatusTimedOut            = guest.StatusTimedOut
	StatusMessageTooLarge     = guest.StatusMessageTooLarge
	StatusNameNotFound        = guest.StatusNameNotFound
	StatusTemporaryFailure    = guest.StatusTemporaryFailure
	StatusIO                  = guest.StatusIO
	StatusCanceled            = guest.StatusCanceled
	StatusOther               = guest.StatusOther
)

// Compatibility wrappers keep existing root-package tests and aggregate
// bindings on the same shared status implementation used by protocol packages.
func statusFromProgress(progress namespace.Progress) Status {
	return guest.FromProgress(progress)
}

func statusFromIOResult(result namespace.IOResult, bufferSize int) Status {
	return guest.FromIOResult(result, bufferSize)
}

func statusFromDNSNext(next namespace.DNSNext) Status {
	return guest.FromDNSNext(next)
}

func statusFromError(err error) Status {
	return guest.FromError(err)
}
