// Package guest provides protocol-neutral checked host-call helpers shared by
// independently compiled networking binding packages.
package guest

import (
	"errors"

	nscore "github.com/wago-org/net/internal/namespace/core"
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
func FromProgress(progress nscore.Progress) Status {
	switch progress {
	case nscore.ProgressDone:
		return StatusOK
	case nscore.ProgressWouldBlock:
		return StatusAgain
	case nscore.ProgressInProgress:
		return StatusInProgress
	default:
		return StatusOther
	}
}

// FromIOResult maps one validated nonblocking stream result. Callers write
// output bytes only for StatusOK, so AGAIN and EOF preserve guest outputs.
func FromIOResult(result nscore.IOResult, bufferSize int) Status {
	if !result.Valid(bufferSize) {
		return StatusOther
	}
	switch result.State {
	case nscore.IOReady:
		return StatusOK
	case nscore.IOWouldBlock:
		return StatusAgain
	case nscore.IOEOF:
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
	switch {
	case err == resource.ErrBadHandle:
		return StatusBadHandle
	case err == quota.ErrLimit, err == readiness.ErrLimit, err == resource.ErrExhausted:
		return StatusResourceLimit
	case err == quota.ErrInvalidUnits, err == readiness.ErrInvalidBudget, err == readiness.ErrInvalidConfig, err == readiness.ErrInvalidRegistration:
		return StatusInvalidArgument
	case err == quota.ErrClosed, err == readiness.ErrClosed, err == resource.ErrClosed:
		return StatusInvalidState
	}
	if failure, ok := nscore.FailureOf(err); ok {
		switch failure {
		case nscore.FailureInvalidArgument:
			return StatusInvalidArgument
		case nscore.FailureInvalidState, nscore.FailureClosed:
			return StatusInvalidState
		case nscore.FailureNotSupported:
			return StatusNotSupported
		case nscore.FailureNoMemory:
			return StatusNoMemory
		case nscore.FailureResourceLimit:
			return StatusResourceLimit
		case nscore.FailureAddressInUse:
			return StatusAddressInUse
		case nscore.FailureAddressUnavailable:
			return StatusAddressNotAvailable
		case nscore.FailureRemoteUnreachable:
			return StatusRemoteUnreachable
		case nscore.FailureConnectionRefused:
			return StatusConnectionRefused
		case nscore.FailureConnectionReset:
			return StatusConnectionReset
		case nscore.FailureConnectionAborted:
			return StatusConnectionAborted
		case nscore.FailureConnectionBroken:
			return StatusConnectionBroken
		case nscore.FailureTimedOut:
			return StatusTimedOut
		case nscore.FailureMessageTooLarge:
			return StatusMessageTooLarge
		case nscore.FailureNameNotFound:
			return StatusNameNotFound
		case nscore.FailureTemporary:
			return StatusTemporaryFailure
		case nscore.FailureIO:
			return StatusIO
		case nscore.FailureCanceled:
			return StatusCanceled
		case nscore.FailureAccessDenied:
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
