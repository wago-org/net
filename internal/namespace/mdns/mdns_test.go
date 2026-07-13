package mdns

import (
	"net/netip"
	"testing"
)

func TestRequestsServicesAndRecordsAreFiniteAndCanonical(t *testing.T) {
	if !(Request{Name: "_http._tcp.local", Types: RecordsPTR | RecordsSRV}).Valid() {
		t.Fatal("valid request rejected")
	}
	for _, request := range []Request{{}, {Name: "example.com", Types: RecordsA}, {Name: "host.local", Types: 1 << 7}} {
		if request.Valid() {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
	service := Service{Name: "device._http._tcp.local", Host: "device.local", Address: netip.MustParseAddr("192.0.2.2"), TTLSeconds: 120, Port: 80}
	if !service.Valid() {
		t.Fatal("valid service rejected")
	}
	service.TXTLength = MaxTXTBytes + 1
	if service.Valid() {
		t.Fatal("oversized TXT accepted")
	}

	records := []Record{
		{Name: "device.local", Type: RecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.2"), CacheFlush: true},
		{Name: "_http._tcp.local", Type: RecordPTR, TTLSeconds: 120, Target: "device._http._tcp.local"},
		{Name: "device._http._tcp.local", Type: RecordSRV, TTLSeconds: 120, Target: "device.local", Port: 80},
		{Name: "device._http._tcp.local", Type: RecordTXT, TTLSeconds: 120, TXTLength: 3},
	}
	for _, record := range records {
		if !record.Valid() {
			t.Fatalf("valid record rejected: %+v", record)
		}
	}
	records[0].Target = "wrong.local"
	if records[0].Valid() {
		t.Fatal("type-confused A record accepted")
	}
}
