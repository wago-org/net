package dns

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
)

func TestDNSV1LayoutConstantsAndQueryRoundTrip(t *testing.T) {
	if DNSNameV1Size != 260 || DNSQueryV1Size != 268 || DNSRecordV1Size != 560 {
		t.Fatalf("DNS layout sizes = %d/%d/%d", DNSNameV1Size, DNSQueryV1Size, DNSRecordV1Size)
	}
	if DNSRecordTypesA != 1 || DNSRecordTypesAAAA != 2 || DNSRecordTypeA != 1 || DNSRecordTypeAAAA != 2 || DNSRecordTypeCNAME != 3 {
		t.Fatal("DNS ABI numeric values changed")
	}
	request := dnsns.Request{Name: "api.example.com", Types: dnsns.RecordsA | dnsns.RecordsAAAA}
	memory := bytes.Repeat([]byte{0x5a}, int(DNSQueryV1Size)+16)
	if !EncodeDNSQueryV1(memory, 4, request) {
		t.Fatal("EncodeDNSQueryV1 failed")
	}
	got, ok := DecodeDNSQueryV1(memory, 4)
	if !ok || got != request {
		t.Fatalf("DecodeDNSQueryV1 = %+v, %v", got, ok)
	}
	if !CheckDNSResolveV1(make([]byte, 300), 0, DNSQueryV1Size) || CheckDNSResolveV1(make([]byte, 300), 0, 260) {
		t.Fatal("DNS resolve range validation mismatch")
	}
}

func TestDNSNameV1RejectsNoncanonicalAndReservedBytes(t *testing.T) {
	memory := make([]byte, DNSNameV1Size)
	if !EncodeDNSNameV1(memory, 0, "example.com") {
		t.Fatal("valid DNS name encoding failed")
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b[2:4], 1) },
		func(b []byte) { b[DNSNameV1Size-1] = 1 },
		func(b []byte) { copy(b[4:], "Example.com") },
		func(b []byte) { binary.LittleEndian.PutUint16(b[0:2], 254) },
	} {
		candidate := append([]byte(nil), memory...)
		mutate(candidate)
		if _, ok := DecodeDNSNameV1(candidate, 0); ok {
			t.Fatalf("malformed DNS name accepted: %x", candidate[:8])
		}
	}
}

func TestDNSRecordV1AtomicEncoding(t *testing.T) {
	tests := []struct {
		record dnsns.Record
		typeID uint32
	}{
		{dnsns.Record{Name: "example.com", Type: dnsns.RecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.1")}, DNSRecordTypeA},
		{dnsns.Record{Name: "example.com", Type: dnsns.RecordAAAA, TTLSeconds: 120, Address: netip.MustParseAddr("2001:db8::1")}, DNSRecordTypeAAAA},
		{dnsns.Record{Name: "www.example.com", Type: dnsns.RecordCNAME, TTLSeconds: 180, CanonicalName: "example.com"}, DNSRecordTypeCNAME},
	}
	for _, test := range tests {
		memory := bytes.Repeat([]byte{0xa5}, int(DNSRecordV1Size)+2)
		if !EncodeDNSRecordV1(memory, 1, test.record) {
			t.Fatalf("EncodeDNSRecordV1(%+v)", test.record)
		}
		encoded := memory[1 : 1+DNSRecordV1Size]
		if name, ok := DecodeDNSNameV1(encoded, 0); !ok || name != test.record.Name {
			t.Fatalf("record name = %q, %v", name, ok)
		}
		if got := binary.LittleEndian.Uint32(encoded[260:264]); got != test.typeID {
			t.Fatalf("record type = %d", got)
		}
		if got := binary.LittleEndian.Uint32(encoded[264:268]); got != test.record.TTLSeconds {
			t.Fatalf("record TTL = %d", got)
		}
		if test.record.Type == dnsns.RecordCNAME {
			if canonical, ok := DecodeDNSNameV1(encoded, 300); !ok || canonical != test.record.CanonicalName {
				t.Fatalf("canonical name = %q, %v", canonical, ok)
			}
			if !bytes.Equal(encoded[268:300], make([]byte, 32)) {
				t.Fatal("CNAME encoded an address")
			}
		} else {
			endpoint, ok := abicore.DecodeEndpointV1(encoded, 268)
			if !ok || endpoint.Address != test.record.Address || endpoint.Port != 0 {
				t.Fatalf("record address = %+v, %v", endpoint, ok)
			}
			if !bytes.Equal(encoded[300:560], make([]byte, 260)) {
				t.Fatal("address record encoded a canonical name")
			}
		}
	}

	memory := bytes.Repeat([]byte{0x5a}, int(DNSRecordV1Size))
	before := append([]byte(nil), memory...)
	if EncodeDNSRecordV1(memory, 1, tests[0].record) || EncodeDNSRecordV1(memory, 0, dnsns.Record{}) {
		t.Fatal("invalid DNS record encoding succeeded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("rejected DNS record encoding mutated memory")
	}
}

func FuzzDNSV1Layouts(f *testing.F) {
	f.Add(make([]byte, DNSQueryV1Size), uint32(0), uint32(DNSQueryV1Size))
	f.Add([]byte{1, 2, 3}, ^uint32(0), ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, queryPtr, outputPtr uint32) {
		before := append([]byte(nil), memory...)
		_, _ = DecodeDNSNameV1(memory, queryPtr)
		_, _ = DecodeDNSQueryV1(memory, queryPtr)
		_ = CheckDNSResolveV1(memory, queryPtr, outputPtr)
		_ = EncodeDNSNameV1(memory, outputPtr, "example.com")
		if uint64(outputPtr)+uint64(DNSNameV1Size) > uint64(len(memory)) && !bytes.Equal(memory, before) {
			t.Fatal("rejected DNS name write mutated memory")
		}
	})
}
