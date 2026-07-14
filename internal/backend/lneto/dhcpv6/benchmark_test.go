package dhcpv6

import (
	"net/netip"
	"testing"

	lnetodhcp "github.com/soypat/lneto/dhcp/dhcpv6"
	nscore "github.com/wago-org/net/internal/namespace/core"
)

var (
	benchmarkPacketInfo packetInfo
	benchmarkAccepted   bool
)

func BenchmarkInspectMessageReply(b *testing.B) {
	config := defaultConfig()
	xid := uint32(0x123456)
	iaid := [4]byte{2, 0, 0, 1}
	clientDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	payload := buildServerPayload(b, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, netip.MustParseAddr("2001:db8::10"), true)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkPacketInfo, benchmarkAccepted = inspectMessage(payload, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID)
		if !benchmarkAccepted {
			b.Fatal("valid reply rejected")
		}
	}
}

func BenchmarkAdapterTryAcquireClose(b *testing.B) {
	_, adapter, _ := newTestAdapter(b, defaultConfig())
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resource, progress, err := adapter.TryAcquire()
		if err != nil || progress != nscore.ProgressInProgress {
			b.Fatalf("TryAcquire = %T %v %v", resource, progress, err)
		}
		if err := resource.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
