// Package guest provides protocol-neutral checked host-call helpers shared by
// independently compiled networking binding packages.
package guest

import (
	"errors"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

// Status is the stable numeric result returned by networking host imports.
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

// FromProgress maps valid nonblocking progress onto the stable guest taxonomy.
func FromProgress(progress namespace.Progress) Status {
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

// FromIOResult maps one validated nonblocking stream result. Callers write
// output bytes only for StatusOK, so AGAIN and EOF preserve guest outputs.
func FromIOResult(result namespace.IOResult, bufferSize int) Status {
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

// FromDNSNext maps one validated nonblocking DNS iteration state.
func FromDNSNext(next namespace.DNSNext) Status {
	switch next {
	case namespace.DNSNextReady:
		return StatusOK
	case namespace.DNSNextWouldBlock:
		return StatusAgain
	case namespace.DNSNextEOF:
		return StatusEOF
	default:
		return StatusOther
	}
}

// FromError maps backend-neutral failures and shared ownership errors without
// exposing backend-specific error text to the guest ABI.
func FromError(err error) Status {
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

// Memory returns the calling module's current linear memory without retaining it.
func Memory(module wago.HostModule) []byte {
	if module == nil {
		return nil
	}
	return module.Memory()
}

// SetStatus writes one i32 status result when a result slot is available.
func SetStatus(results []uint64, status Status) {
	if len(results) != 0 {
		results[0] = wago.I32(int32(status))
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
