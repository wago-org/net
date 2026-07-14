package packetlink

import (
	"bytes"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLinkCopiesFramesPreservesOrderAndReportsTruncation(t *testing.T) {
	link := newTestLink(t, Config{MaxFrameBytes: 4, IngressFrames: 2, EgressFrames: 1})
	frame := []byte{1, 2, 3}
	if err := link.TryEnqueue(Ingress, frame); err != nil {
		t.Fatal(err)
	}
	frame[0] = 9
	if err := link.TryEnqueue(Ingress, nil); err != nil {
		t.Fatal(err)
	}
	if err := link.TryEnqueue(Ingress, []byte{4}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full enqueue error = %v", err)
	}

	dst := make([]byte, 2)
	result, err := link.TryDequeue(Ingress, dst)
	if err != nil || !result.Valid(len(dst)) {
		t.Fatalf("dequeue = %+v, %v", result, err)
	}
	if !bytes.Equal(dst, []byte{1, 2}) || result.FrameBytes != 3 || !result.Truncated {
		t.Fatalf("first frame = %v, %+v", dst, result)
	}
	result, err = link.TryDequeue(Ingress, nil)
	if err != nil || !result.Valid(0) || !result.Ready || result.FrameBytes != 0 {
		t.Fatalf("empty frame = %+v, %v", result, err)
	}
	result, err = link.TryDequeue(Ingress, dst)
	if err != nil || !result.Valid(len(dst)) || result.Ready {
		t.Fatalf("empty queue = %+v, %v", result, err)
	}
}

func TestLinkExactCapacityBudgetAndOversizeRollback(t *testing.T) {
	link := newTestLink(t, Config{MaxFrameBytes: 4, IngressFrames: 1, EgressFrames: 1})
	if err := link.TryEnqueue(Ingress, []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("exact-size enqueue: %v", err)
	}
	if _, err := link.TryDequeueWithin(Ingress, make([]byte, 4), 3); !errors.Is(err, ErrFrameBudget) {
		t.Fatalf("budget error = %v", err)
	}
	if got := link.Snapshot(); got.IngressFrames != 1 || got.IngressBytes != 4 {
		t.Fatalf("budget failure mutated queue: %+v", got)
	}
	if _, err := link.TryDequeueWithin(Ingress, make([]byte, 4), 4); err != nil {
		t.Fatalf("exact budget dequeue: %v", err)
	}
	if err := link.TryEnqueue(Ingress, make([]byte, 5)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversize enqueue error = %v", err)
	}
	if got := link.Snapshot(); got.IngressFrames != 0 || got.IngressBytes != 0 {
		t.Fatalf("oversize enqueue mutated queue: %+v", got)
	}
}

func TestLinkFillCommitsAtomicallyAndRollsBackFailures(t *testing.T) {
	link := newTestLink(t, Config{MaxFrameBytes: 4, IngressFrames: 1, EgressFrames: 1})
	fillErr := errors.New("fill failed")
	if _, err := link.TryFill(Egress, func(dst []byte) (int, error) {
		copy(dst, []byte{9, 9, 9})
		return 3, fillErr
	}); !errors.Is(err, fillErr) {
		t.Fatalf("fill error = %v", err)
	}
	if got := link.Snapshot(); got.EgressFrames != 0 || got.EgressBytes != 0 {
		t.Fatalf("failed fill committed: %+v", got)
	}
	if !allZero(link.egress.storage) {
		t.Fatal("failed fill retained bytes")
	}
	if _, err := link.TryFill(Egress, func(dst []byte) (int, error) {
		dst[0] = 8
		return len(dst) + 1, nil
	}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversize fill error = %v", err)
	}
	result, err := link.TryFill(Egress, func(dst []byte) (int, error) {
		copy(dst, []byte{1, 2, 3, 4})
		return 4, nil
	})
	if err != nil || !result.Ready || result.FrameBytes != 4 {
		t.Fatalf("exact fill = %+v, %v", result, err)
	}
	called := false
	if _, err := link.TryFill(Egress, func([]byte) (int, error) {
		called = true
		return 1, nil
	}); !errors.Is(err, ErrQueueFull) || called {
		t.Fatalf("full fill = called %v, error %v", called, err)
	}
	got := make([]byte, 4)
	if _, err := link.TryDequeue(Egress, got); err != nil || !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("committed fill data = %v, %v", got, err)
	}
}

func TestZeroLengthFillRollbackRemainsDistinctFromCommittedEmptyFrame(t *testing.T) {
	link := newTestLink(t, Config{MaxFrameBytes: 4, IngressFrames: 1, EgressFrames: 1})
	result, err := link.TryFill(Egress, func(dst []byte) (int, error) {
		copy(dst, []byte{1, 2, 3, 4})
		return 0, nil
	})
	if err != nil || result != (FrameResult{}) {
		t.Fatalf("zero fill = %+v, %v", result, err)
	}
	if snapshot := link.Snapshot(); snapshot.EgressFrames != 0 || snapshot.EgressBytes != 0 {
		t.Fatalf("zero fill committed queue state: %+v", snapshot)
	}
	if !allZero(link.egress.storage) {
		t.Fatal("zero fill retained callback bytes")
	}

	if err := link.TryEnqueue(Egress, nil); err != nil {
		t.Fatal(err)
	}
	if snapshot := link.Snapshot(); snapshot.EgressFrames != 1 || snapshot.EgressBytes != 0 {
		t.Fatalf("empty frame snapshot = %+v", snapshot)
	}
	called := false
	if _, err := link.TryFill(Egress, func([]byte) (int, error) {
		called = true
		return 1, nil
	}); !errors.Is(err, ErrQueueFull) || called {
		t.Fatalf("full queue fill = called %v, error %v", called, err)
	}
	result, err = link.TryDequeue(Egress, nil)
	if err != nil || result != (FrameResult{Ready: true}) || !result.Valid(0) {
		t.Fatalf("empty frame dequeue = %+v, %v", result, err)
	}
	if snapshot := link.Snapshot(); snapshot.EgressFrames != 0 || snapshot.EgressBytes != 0 {
		t.Fatalf("empty frame drain = %+v", snapshot)
	}

	result, err = link.TryFill(Egress, func(dst []byte) (int, error) {
		dst[0] = 9
		return 1, nil
	})
	if err != nil || result != (FrameResult{Copied: 1, FrameBytes: 1, Ready: true}) {
		t.Fatalf("fill after empty frame = %+v, %v", result, err)
	}
	var dst [1]byte
	if result, err = link.TryDequeue(Egress, dst[:]); err != nil || result.FrameBytes != 1 || dst[0] != 9 {
		t.Fatalf("filled frame dequeue = %+v, %v, data=%v", result, err, dst)
	}
}

func TestLinkRejectsInvalidConfigQueueAndFill(t *testing.T) {
	invalid := []Config{
		{},
		{MaxFrameBytes: 1, IngressFrames: 1},
		{MaxFrameBytes: 1, EgressFrames: 1},
		{MaxFrameBytes: math.MaxInt, IngressFrames: 2, EgressFrames: 1},
	}
	for _, config := range invalid {
		if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(%+v) error = %v", config, err)
		}
	}
	link := newTestLink(t, Config{MaxFrameBytes: 4, IngressFrames: 1, EgressFrames: 1})
	if err := link.TryEnqueue(Queue(99), nil); !errors.Is(err, ErrInvalidQueue) {
		t.Fatalf("invalid queue enqueue = %v", err)
	}
	if _, err := link.TryDequeue(Queue(99), nil); !errors.Is(err, ErrInvalidQueue) {
		t.Fatalf("invalid queue dequeue = %v", err)
	}
	if _, err := link.TryFill(Egress, nil); !errors.Is(err, ErrInvalidFill) {
		t.Fatalf("nil fill = %v", err)
	}
	if _, err := link.TryFill(Egress, func([]byte) (int, error) { return -1, nil }); !errors.Is(err, ErrInvalidFill) {
		t.Fatalf("negative fill = %v", err)
	}
	if _, err := link.TryDequeueWithin(Ingress, nil, -1); !errors.Is(err, ErrFrameBudget) {
		t.Fatalf("negative budget = %v", err)
	}
}

func TestLinkCloseClearsQueuesAndRacesSafely(t *testing.T) {
	link := newTestLink(t, Config{MaxFrameBytes: 64, IngressFrames: 8, EgressFrames: 8})
	for i := 0; i < 8; i++ {
		if err := link.TryEnqueue(Ingress, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if err := link.TryEnqueue(Egress, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	var unexpected atomic.Value
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			buf := make([]byte, 64)
			for j := 0; j < 1000; j++ {
				err := link.TryEnqueue(Ingress, []byte{id})
				if err != nil && !errors.Is(err, ErrQueueFull) && !errors.Is(err, ErrClosed) {
					unexpected.Store(err)
					return
				}
				_, err = link.TryDequeue(Ingress, buf)
				if err != nil && !errors.Is(err, ErrClosed) {
					unexpected.Store(err)
					return
				}
			}
		}(byte(i))
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if value := unexpected.Load(); value != nil {
		t.Fatalf("unexpected race error: %v", value)
	}
	if err := link.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := link.Snapshot(); !got.Closed || got.IngressFrames != 0 || got.IngressBytes != 0 || got.EgressFrames != 0 || got.EgressBytes != 0 {
		t.Fatalf("closed snapshot = %+v", got)
	}
	if !allZero(link.ingress.storage) || !allZero(link.egress.storage) {
		t.Fatal("close retained frame bytes")
	}
	if err := link.TryEnqueue(Ingress, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("enqueue after close = %v", err)
	}
	if _, err := link.TryDequeue(Egress, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("dequeue after close = %v", err)
	}
}

func FuzzLinkFrameOwnership(f *testing.F) {
	f.Add([]byte("frame"), uint8(3))
	f.Add([]byte{}, uint8(0))
	f.Add(make([]byte, 33), uint8(8))
	f.Fuzz(func(t *testing.T, frame []byte, dstSize uint8) {
		const maxFrameBytes = 32
		link, err := New(Config{MaxFrameBytes: maxFrameBytes, IngressFrames: 1, EgressFrames: 1})
		if err != nil {
			t.Fatal(err)
		}
		original := append([]byte(nil), frame...)
		err = link.TryEnqueue(Ingress, frame)
		if len(frame) > maxFrameBytes {
			if !errors.Is(err, ErrFrameTooLarge) || link.Snapshot().IngressFrames != 0 {
				t.Fatalf("oversize frame = %v, %+v", err, link.Snapshot())
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		clear(frame)
		dst := make([]byte, int(dstSize)%40)
		result, err := link.TryDequeue(Ingress, dst)
		if err != nil || !result.Valid(len(dst)) || !result.Ready || result.FrameBytes != len(original) {
			t.Fatalf("dequeue = %+v, %v", result, err)
		}
		wantCopied := min(len(dst), len(original))
		if result.Copied != wantCopied || !bytes.Equal(dst[:wantCopied], original[:wantCopied]) {
			t.Fatalf("copied %d bytes %v, want %v", result.Copied, dst[:wantCopied], original[:wantCopied])
		}
	})
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func newTestLink(t testing.TB, config Config) *Link {
	t.Helper()
	link, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return link
}
