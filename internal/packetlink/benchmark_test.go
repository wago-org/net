package packetlink

import "testing"

var (
	benchmarkFrameResult FrameResult
	benchmarkSnapshot    Snapshot
	benchmarkErr         error
)

func BenchmarkLinkTryEnqueueDequeue(b *testing.B) {
	for _, size := range []int{64, 512, 1514} {
		b.Run(frameSizeName(size), func(b *testing.B) {
			link := newTestLink(b, Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1})
			frame := make([]byte, size)
			dst := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if err := link.TryEnqueue(Ingress, frame); err != nil {
					b.Fatal(err)
				}
				benchmarkFrameResult, benchmarkErr = link.TryDequeue(Ingress, dst)
				if benchmarkErr != nil || !benchmarkFrameResult.Ready {
					b.Fatalf("dequeue = %+v, %v", benchmarkFrameResult, benchmarkErr)
				}
			}
		})
	}
}

func BenchmarkLinkTryFillDequeue(b *testing.B) {
	link := newTestLink(b, Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1})
	dst := make([]byte, 1514)
	fill := func(frame []byte) (int, error) {
		frame[0] = 1
		return 1514, nil
	}
	b.SetBytes(1514)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFrameResult, benchmarkErr = link.TryFill(Egress, fill)
		if benchmarkErr != nil || !benchmarkFrameResult.Ready {
			b.Fatalf("fill = %+v, %v", benchmarkFrameResult, benchmarkErr)
		}
		benchmarkFrameResult, benchmarkErr = link.TryDequeue(Egress, dst)
		if benchmarkErr != nil || !benchmarkFrameResult.Ready {
			b.Fatalf("dequeue = %+v, %v", benchmarkFrameResult, benchmarkErr)
		}
	}
}

func BenchmarkLinkSnapshot(b *testing.B) {
	link := newTestLink(b, Config{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8})
	b.ReportAllocs()
	for b.Loop() {
		benchmarkSnapshot = link.Snapshot()
	}
}

func frameSizeName(size int) string {
	switch size {
	case 64:
		return "bytes=64"
	case 512:
		return "bytes=512"
	default:
		return "bytes=1514"
	}
}
