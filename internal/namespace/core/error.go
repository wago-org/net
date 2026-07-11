package core

import (
	"errors"
	"fmt"
)

// Failure is a backend-neutral semantic error category. Protocol adapters map
// these categories to stable guest statuses; backend error text is diagnostic
// only and never crosses the guest ABI.
type Failure uint8

const (
	FailureInvalidArgument Failure = iota + 1
	FailureInvalidState
	FailureNotSupported
	FailureNoMemory
	FailureResourceLimit
	FailureAddressInUse
	FailureAddressUnavailable
	FailureRemoteUnreachable
	FailureConnectionRefused
	FailureConnectionReset
	FailureConnectionAborted
	FailureConnectionBroken
	FailureTimedOut
	FailureMessageTooLarge
	FailureNameNotFound
	FailureTemporary
	FailureIO
	FailureCanceled
	FailureClosed
	FailureAccessDenied
)

// Valid reports whether failure is a defined category.
func (f Failure) Valid() bool { return f >= FailureInvalidArgument && f <= FailureAccessDenied }

// Error wraps a backend cause with a stable semantic category.
type Error struct {
	Failure Failure
	Cause   error
}

func (e *Error) Error() string {
	if e == nil {
		return "net: namespace failure"
	}
	if e.Cause == nil {
		return fmt.Sprintf("net: namespace failure %d", e.Failure)
	}
	return fmt.Sprintf("net: namespace failure %d: %v", e.Failure, e.Cause)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Fail constructs a categorized error. Invalid categories are converted to IO
// so an implementation cannot accidentally expose an uncategorized success.
func Fail(failure Failure, cause error) error {
	if !failure.Valid() {
		failure = FailureIO
	}
	return &Error{Failure: failure, Cause: cause}
}

// FailureOf extracts a semantic category through wrapped errors.
func FailureOf(err error) (Failure, bool) {
	var namespaceError *Error
	if !errors.As(err, &namespaceError) || namespaceError == nil || !namespaceError.Failure.Valid() {
		return 0, false
	}
	return namespaceError.Failure, true
}
