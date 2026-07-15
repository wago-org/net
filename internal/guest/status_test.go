package guest

import (
	"bytes"
	"errors"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

var benchmarkStatus Status

type panicMemoryHost struct {
	memory []byte
}

func (h *panicMemoryHost) Memory() []byte {
	if h == nil {
		panic("typed-nil Memory call")
	}
	return h.memory
}

func TestMemoryRejectsTypedNilHostModule(t *testing.T) {
	var typedNil *panicMemoryHost
	if memory := Memory(typedNil); memory != nil {
		t.Fatalf("typed-nil memory = %v, want nil", memory)
	}
	if memory := Memory(nil); memory != nil {
		t.Fatalf("nil memory = %v, want nil", memory)
	}
	want := []byte{1, 2, 3}
	if memory := Memory(&panicMemoryHost{memory: want}); !bytes.Equal(memory, want) {
		t.Fatalf("valid memory = %v, want %v", memory, want)
	}
}

func TestFromErrorFastPathsDoNotAllocate(t *testing.T) {
	semantic := nscore.Fail(nscore.FailureConnectionReset, errors.New("reset"))
	for name, err := range map[string]error{"semantic": semantic, "shared": resource.ErrBadHandle} {
		t.Run(name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				benchmarkStatus = FromError(err)
			})
			if allocs != 0 {
				t.Fatalf("FromError allocations = %v, want 0", allocs)
			}
		})
	}
}

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
