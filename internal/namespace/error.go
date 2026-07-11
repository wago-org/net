package namespace

import nscore "github.com/wago-org/net/internal/namespace/core"

type Failure = nscore.Failure

const (
	FailureInvalidArgument    = nscore.FailureInvalidArgument
	FailureInvalidState       = nscore.FailureInvalidState
	FailureNotSupported       = nscore.FailureNotSupported
	FailureNoMemory           = nscore.FailureNoMemory
	FailureResourceLimit      = nscore.FailureResourceLimit
	FailureAddressInUse       = nscore.FailureAddressInUse
	FailureAddressUnavailable = nscore.FailureAddressUnavailable
	FailureRemoteUnreachable  = nscore.FailureRemoteUnreachable
	FailureConnectionRefused  = nscore.FailureConnectionRefused
	FailureConnectionReset    = nscore.FailureConnectionReset
	FailureConnectionAborted  = nscore.FailureConnectionAborted
	FailureConnectionBroken   = nscore.FailureConnectionBroken
	FailureTimedOut           = nscore.FailureTimedOut
	FailureMessageTooLarge    = nscore.FailureMessageTooLarge
	FailureNameNotFound       = nscore.FailureNameNotFound
	FailureTemporary          = nscore.FailureTemporary
	FailureIO                 = nscore.FailureIO
	FailureCanceled           = nscore.FailureCanceled
	FailureClosed             = nscore.FailureClosed
	FailureAccessDenied       = nscore.FailureAccessDenied
)

type Error = nscore.Error

func Fail(failure Failure, cause error) error { return nscore.Fail(failure, cause) }
func FailureOf(err error) (Failure, bool)     { return nscore.FailureOf(err) }
