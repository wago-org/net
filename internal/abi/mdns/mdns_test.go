package mdns

import (
	"bytes"
	"net/netip"
	"testing"

	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
)

func TestCheckedQueryAnnouncementAndAtomicRecords(t *testing.T) {
	memory := make([]byte, 1400)
	request := mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR | mdnsns.RecordsSRV}
	if !EncodeQueryV1(memory, 0, request) {
		t.Fatal("encode query")
	}
	if decoded, ok := DecodeQueryV1(memory, 0); !ok || decoded != request {
		t.Fatalf("decode query = %+v, %v", decoded, ok)
	}
	if CheckQueryV1(memory, 0, 264) || !CheckQueryV1(memory, 0, 300) {
		t.Fatal("query range overlap validation failed")
	}
	if !EncodeAnnouncementV1(memory, 600, 7) {
		t.Fatal("encode announcement")
	}
	if service, ok := DecodeAnnouncementV1(memory, 600); !ok || service != 7 {
		t.Fatalf("decode announcement = %d, %v", service, ok)
	}

	records := []mdnsns.Record{
		{Name: "device.local", Type: mdnsns.RecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.2"), CacheFlush: true},
		{Name: "_demo._udp.local", Type: mdnsns.RecordPTR, TTLSeconds: 120, Target: "device._demo._udp.local"},
		{Name: "device._demo._udp.local", Type: mdnsns.RecordSRV, TTLSeconds: 120, Target: "device.local", Port: 9000},
		{Name: "device._demo._udp.local", Type: mdnsns.RecordTXT, TTLSeconds: 120, TXTLength: 4},
	}
	copy(records[3].TXT[:], []byte{3, 'k', '=', 'v'})
	for _, record := range records {
		before := bytes.Repeat([]byte{0xa5}, int(RecordV1Size))
		copy(memory[0:RecordV1Size], before)
		if !EncodeRecordV1(memory, 0, record) || bytes.Equal(memory[0:RecordV1Size], before) {
			t.Fatalf("record encode failed: %+v", record)
		}
	}
	before := append([]byte(nil), memory...)
	if EncodeRecordV1(memory, uint32(len(memory))-RecordV1Size+1, records[0]) || !bytes.Equal(before, memory) {
		t.Fatal("short record output mutated memory")
	}
}

func TestNameAndReservedBytesRejectMalformedInput(t *testing.T) {
	memory := make([]byte, QueryV1Size)
	request := mdnsns.Request{Name: "_demo._udp.local", Types: mdnsns.RecordsPTR}
	EncodeQueryV1(memory, 0, request)
	memory[2] = 1
	if _, ok := DecodeQueryV1(memory, 0); ok {
		t.Fatal("reserved name field accepted")
	}
	EncodeQueryV1(memory, 0, request)
	memory[queryReserved] = 1
	if _, ok := DecodeQueryV1(memory, 0); ok {
		t.Fatal("reserved query field accepted")
	}
}
