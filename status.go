package net

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
