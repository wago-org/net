package net

import (
	"errors"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
)

func TestStatusFromProgress(t *testing.T) {
	for _, test := range []struct {
		progress namespace.Progress
		want     Status
	}{
		{namespace.ProgressDone, StatusOK},
		{namespace.ProgressWouldBlock, StatusAgain},
		{namespace.ProgressInProgress, StatusInProgress},
		{0, StatusOther},
	} {
		if got := statusFromProgress(test.progress); got != test.want {
			t.Fatalf("statusFromProgress(%d) = %v, want %v", test.progress, got, test.want)
		}
	}
}

func TestStatusFromError(t *testing.T) {
	failures := []struct {
		failure namespace.Failure
		want    Status
	}{
		{namespace.FailureInvalidArgument, StatusInvalidArgument},
		{namespace.FailureInvalidState, StatusInvalidState},
		{namespace.FailureNotSupported, StatusNotSupported},
		{namespace.FailureNoMemory, StatusNoMemory},
		{namespace.FailureResourceLimit, StatusResourceLimit},
		{namespace.FailureAddressInUse, StatusAddressInUse},
		{namespace.FailureAddressUnavailable, StatusAddressNotAvailable},
		{namespace.FailureRemoteUnreachable, StatusRemoteUnreachable},
		{namespace.FailureConnectionRefused, StatusConnectionRefused},
		{namespace.FailureConnectionReset, StatusConnectionReset},
		{namespace.FailureConnectionAborted, StatusConnectionAborted},
		{namespace.FailureConnectionBroken, StatusConnectionBroken},
		{namespace.FailureTimedOut, StatusTimedOut},
		{namespace.FailureMessageTooLarge, StatusMessageTooLarge},
		{namespace.FailureNameNotFound, StatusNameNotFound},
		{namespace.FailureTemporary, StatusTemporaryFailure},
		{namespace.FailureIO, StatusIO},
		{namespace.FailureCanceled, StatusCanceled},
		{namespace.FailureClosed, StatusInvalidState},
		{namespace.FailureAccessDenied, StatusAccessDenied},
	}
	for _, test := range failures {
		err := namespace.Fail(test.failure, errors.New("backend detail"))
		if got := statusFromError(err); got != test.want {
			t.Fatalf("statusFromError(%d) = %v, want %v", test.failure, got, test.want)
		}
	}
	for _, test := range []struct {
		err  error
		want Status
	}{
		{nil, StatusOK},
		{resource.ErrBadHandle, StatusBadHandle},
		{resource.ErrExhausted, StatusResourceLimit},
		{resource.ErrClosed, StatusInvalidState},
		{quota.ErrLimit, StatusResourceLimit},
		{quota.ErrInvalidUnits, StatusInvalidArgument},
		{readiness.ErrLimit, StatusResourceLimit},
		{readiness.ErrInvalidBudget, StatusInvalidArgument},
		{errors.New("unknown"), StatusOther},
	} {
		if got := statusFromError(test.err); got != test.want {
			t.Fatalf("statusFromError(%v) = %v, want %v", test.err, got, test.want)
		}
	}
}
