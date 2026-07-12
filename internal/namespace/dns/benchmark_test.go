package dns

import (
	"net/netip"
	"testing"
)

var benchmarkBool bool

func BenchmarkRequestValid(b *testing.B) {
	request := Request{Name: "service.api.example.com", Types: RecordsA | RecordsAAAA}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = request.Valid()
	}
}

func BenchmarkRecordValid(b *testing.B) {
	record := Record{Name: "service.api.example.com", Type: RecordAAAA, TTLSeconds: 60, Address: netip.MustParseAddr("2001:db8::1")}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = record.Valid()
	}
}
