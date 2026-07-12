package guest

import (
	"errors"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

var benchmarkStatus Status

func BenchmarkFromProgress(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkStatus = FromProgress(nscore.ProgressDone)
	}
}

func BenchmarkFromIOResult(b *testing.B) {
	result := nscore.IOResult{Bytes: 1024, State: nscore.IOReady}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkStatus = FromIOResult(result, 4096)
	}
}

func BenchmarkFromError(b *testing.B) {
	b.Run("semantic", func(b *testing.B) {
		err := nscore.Fail(nscore.FailureConnectionReset, errors.New("reset"))
		b.ReportAllocs()
		for b.Loop() {
			benchmarkStatus = FromError(err)
		}
	})
	b.Run("shared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkStatus = FromError(resource.ErrBadHandle)
		}
	})
}
