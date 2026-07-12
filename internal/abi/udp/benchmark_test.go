package udp

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
)

var benchmarkBool bool

func BenchmarkEncodeReceiveResultV1(b *testing.B) {
	memory := make([]byte, ReceiveResultV1Size)
	result := udpns.DatagramResult{
		Copied: 1200, DatagramBytes: 1400, Truncated: true, Ready: true,
		Source: nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 5300},
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeReceiveResultV1(memory, 0, result, 1200)
	}
}

func BenchmarkValidReceiveFlagsV1(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = ValidReceiveFlagsV1(ReceiveFlagTruncated)
	}
}
