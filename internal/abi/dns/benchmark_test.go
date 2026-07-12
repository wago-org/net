package dns

import (
	"net/netip"
	"testing"

	dnsns "github.com/wago-org/net/internal/namespace/dns"
)

var (
	benchmarkBool    bool
	benchmarkName    string
	benchmarkRequest dnsns.Request
)

func BenchmarkEncodeDNSNameV1(b *testing.B) {
	memory := make([]byte, DNSNameV1Size)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeDNSNameV1(memory, 0, "service.api.example.com")
	}
}

func BenchmarkDecodeDNSNameV1(b *testing.B) {
	memory := make([]byte, DNSNameV1Size)
	if !EncodeDNSNameV1(memory, 0, "service.api.example.com") {
		b.Fatal("encode name")
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkName, benchmarkBool = DecodeDNSNameV1(memory, 0)
	}
}

func BenchmarkEncodeDNSQueryV1(b *testing.B) {
	memory := make([]byte, DNSQueryV1Size)
	request := dnsns.Request{Name: "service.api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeDNSQueryV1(memory, 0, request)
	}
}

func BenchmarkDecodeDNSQueryV1(b *testing.B) {
	memory := make([]byte, DNSQueryV1Size)
	request := dnsns.Request{Name: "service.api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	if !EncodeDNSQueryV1(memory, 0, request) {
		b.Fatal("encode query")
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkRequest, benchmarkBool = DecodeDNSQueryV1(memory, 0)
	}
}

func BenchmarkCheckDNSResolveV1(b *testing.B) {
	memory := make([]byte, 512)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = CheckDNSResolveV1(memory, 0, 320)
	}
}

func BenchmarkEncodeDNSRecordV1(b *testing.B) {
	records := []struct {
		name   string
		record dnsns.Record
	}{
		{"A", dnsns.Record{Name: "service.api.example.com", Type: dnsns.RecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.1")}},
		{"AAAA", dnsns.Record{Name: "service.api.example.com", Type: dnsns.RecordAAAA, TTLSeconds: 60, Address: netip.MustParseAddr("2001:db8::1")}},
		{"CNAME", dnsns.Record{Name: "service.api.example.com", Type: dnsns.RecordCNAME, TTLSeconds: 60, CanonicalName: "api.example.com"}},
	}
	for _, test := range records {
		b.Run(test.name, func(b *testing.B) {
			memory := make([]byte, DNSRecordV1Size)
			b.ReportAllocs()
			for b.Loop() {
				benchmarkBool = EncodeDNSRecordV1(memory, 0, test.record)
			}
		})
	}
}
