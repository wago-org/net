package net

import (
	"errors"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
)

// Status is a stable numeric result returned by networking host imports. Unknown
// internal errors map to StatusOther; Go error strings are never part of the
// guest ABI.
type Status int32

const (
	StatusOK Status = iota
	StatusAgain
	StatusInProgress
	StatusEOF
	StatusAccessDenied
	StatusInvalidArgument
	StatusBadHandle
	StatusInvalidState
	StatusNotSupported
	StatusNoMemory
	StatusResourceLimit
	StatusAddressInUse
	StatusAddressNotAvailable
	StatusRemoteUnreachable
	StatusConnectionRefused
	StatusConnectionReset
	StatusConnectionAborted
	StatusConnectionBroken
	StatusTimedOut
	StatusMessageTooLarge
	StatusNameNotFound
	StatusTemporaryFailure
	StatusIO
	StatusCanceled
	StatusOther
)

// String returns the stable symbolic name used by diagnostics and tests.
// statusFromProgress maps a valid nonblocking progress value onto the stable
// guest taxonomy. Invalid progress fails closed as OTHER.
func statusFromProgress(progress namespace.Progress) Status {
	switch progress {
	case namespace.ProgressDone:
		return StatusOK
	case namespace.ProgressWouldBlock:
		return StatusAgain
	case namespace.ProgressInProgress:
		return StatusInProgress
	default:
		return StatusOther
	}
}

// statusFromIOResult maps one validated nonblocking stream result. Output bytes
// are written only for StatusOK; AGAIN and EOF leave guest outputs unchanged.
func statusFromIOResult(result namespace.IOResult, bufferSize int) Status {
	if !result.Valid(bufferSize) {
		return StatusOther
	}
	switch result.State {
	case namespace.IOReady:
		return StatusOK
	case namespace.IOWouldBlock:
		return StatusAgain
	case namespace.IOEOF:
		return StatusEOF
	default:
		return StatusOther
	}
}

// statusFromError maps backend-neutral failures and ownership/accounting errors
// to stable guest values. Error text and backend-specific causes never cross the
// ABI. Access denial is mapped explicitly without changing existing numbers.
func statusFromError(err error) Status {
	if err == nil {
		return StatusOK
	}
	if failure, ok := namespace.FailureOf(err); ok {
		switch failure {
		case namespace.FailureInvalidArgument:
			return StatusInvalidArgument
		case namespace.FailureInvalidState, namespace.FailureClosed:
			return StatusInvalidState
		case namespace.FailureNotSupported:
			return StatusNotSupported
		case namespace.FailureNoMemory:
			return StatusNoMemory
		case namespace.FailureResourceLimit:
			return StatusResourceLimit
		case namespace.FailureAddressInUse:
			return StatusAddressInUse
		case namespace.FailureAddressUnavailable:
			return StatusAddressNotAvailable
		case namespace.FailureRemoteUnreachable:
			return StatusRemoteUnreachable
		case namespace.FailureConnectionRefused:
			return StatusConnectionRefused
		case namespace.FailureConnectionReset:
			return StatusConnectionReset
		case namespace.FailureConnectionAborted:
			return StatusConnectionAborted
		case namespace.FailureConnectionBroken:
			return StatusConnectionBroken
		case namespace.FailureTimedOut:
			return StatusTimedOut
		case namespace.FailureMessageTooLarge:
			return StatusMessageTooLarge
		case namespace.FailureNameNotFound:
			return StatusNameNotFound
		case namespace.FailureTemporary:
			return StatusTemporaryFailure
		case namespace.FailureIO:
			return StatusIO
		case namespace.FailureCanceled:
			return StatusCanceled
		case namespace.FailureAccessDenied:
			return StatusAccessDenied
		default:
			return StatusOther
		}
	}
	switch {
	case errors.Is(err, resource.ErrBadHandle):
		return StatusBadHandle
	case errors.Is(err, quota.ErrLimit), errors.Is(err, readiness.ErrLimit), errors.Is(err, resource.ErrExhausted):
		return StatusResourceLimit
	case errors.Is(err, quota.ErrInvalidUnits), errors.Is(err, readiness.ErrInvalidBudget), errors.Is(err, readiness.ErrInvalidConfig), errors.Is(err, readiness.ErrInvalidRegistration):
		return StatusInvalidArgument
	case errors.Is(err, quota.ErrClosed), errors.Is(err, readiness.ErrClosed), errors.Is(err, resource.ErrClosed):
		return StatusInvalidState
	default:
		return StatusOther
	}
}

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusAgain:
		return "AGAIN"
	case StatusInProgress:
		return "IN_PROGRESS"
	case StatusEOF:
		return "EOF"
	case StatusAccessDenied:
		return "ACCESS_DENIED"
	case StatusInvalidArgument:
		return "INVALID_ARGUMENT"
	case StatusBadHandle:
		return "BAD_HANDLE"
	case StatusInvalidState:
		return "INVALID_STATE"
	case StatusNotSupported:
		return "NOT_SUPPORTED"
	case StatusNoMemory:
		return "NO_MEMORY"
	case StatusResourceLimit:
		return "RESOURCE_LIMIT"
	case StatusAddressInUse:
		return "ADDRESS_IN_USE"
	case StatusAddressNotAvailable:
		return "ADDRESS_NOT_AVAILABLE"
	case StatusRemoteUnreachable:
		return "REMOTE_UNREACHABLE"
	case StatusConnectionRefused:
		return "CONNECTION_REFUSED"
	case StatusConnectionReset:
		return "CONNECTION_RESET"
	case StatusConnectionAborted:
		return "CONNECTION_ABORTED"
	case StatusConnectionBroken:
		return "CONNECTION_BROKEN"
	case StatusTimedOut:
		return "TIMED_OUT"
	case StatusMessageTooLarge:
		return "MESSAGE_TOO_LARGE"
	case StatusNameNotFound:
		return "NAME_NOT_FOUND"
	case StatusTemporaryFailure:
		return "TEMPORARY_FAILURE"
	case StatusIO:
		return "IO"
	case StatusCanceled:
		return "CANCELED"
	case StatusOther:
		return "OTHER"
	default:
		return "UNKNOWN"
	}
}
