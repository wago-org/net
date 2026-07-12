package tcp

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

var benchmarkBool bool

func BenchmarkCheckListenV1(b *testing.B) {
	memory := make([]byte, 256)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = CheckListenV1(memory, 0, 64)
	}
}

func BenchmarkCheckCreateV1(b *testing.B) {
	memory := make([]byte, 256)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = CheckCreateV1(memory, 0, 64)
	}
}

func BenchmarkCheckIOV1(b *testing.B) {
	memory := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = CheckIOV1(memory, 0, 2048, 3072)
	}
}

func BenchmarkEncodeStreamV1(b *testing.B) {
	memory := make([]byte, StreamV1Size)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 49152}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeStreamV1(memory, 0, resource.Handle(0x0102030405060708), local, remote)
	}
}

func BenchmarkEncodeIOResultV1(b *testing.B) {
	memory := make([]byte, IOResultV1Size)
	result := nscore.IOResult{Bytes: 1024, State: nscore.IOReady}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeIOResultV1(memory, 0, result, 4096)
	}
}
