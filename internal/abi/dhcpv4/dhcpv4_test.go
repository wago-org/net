package dhcpv4

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
)

func TestRequestAndLeaseFixedAtomicCodecs(t *testing.T) {
	memory := make([]byte, 512)
	request := dhcpns.Request{RequestedAddr: netip.MustParseAddr("192.0.2.20"), HostnameLength: 4, ClientIDLength: 2}
	copy(request.Hostname[:], "host")
	copy(request.ClientID[:], "id")
	if !EncodeRequestV1(memory, 8, request) {
		t.Fatal("encode request")
	}
	got, ok := DecodeRequestV1(memory, 8)
	if !ok || got != request {
		t.Fatalf("request = %+v, %v", got, ok)
	}
	lease := dhcpns.Lease{AssignedAddr: netip.MustParseAddr("192.0.2.20"), ServerAddr: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, DNSCount: 1, DNSServers: [dhcpns.MaxDNSServers]netip.Addr{netip.MustParseAddr("192.0.2.53")}, Applied: true}
	if !EncodeLeaseV1(memory, 128, lease) {
		t.Fatal("encode lease")
	}
	before := append([]byte(nil), memory...)
	if EncodeLeaseV1(memory, uint32(len(memory)-1), lease) || string(before) != string(memory) {
		t.Fatal("out-of-range lease encoding mutated memory")
	}
}

func TestRequestRejectsMalformedFixedFields(t *testing.T) {
	memory := make([]byte, RequestV1Size)
	if !EncodeRequestV1(memory, 0, dhcpns.Request{}) {
		t.Fatal("encode empty request")
	}
	for name, mutate := range map[string]func([]byte){
		"unknown family": func(encoded []byte) { encoded[0] = 0xff },
		"address flags":  func(encoded []byte) { encoded[1] = 1 },
		"limited broadcast": func(encoded []byte) {
			copy(encoded[8:12], []byte{255, 255, 255, 255})
		},
		"port": func(encoded []byte) { binary.LittleEndian.PutUint16(encoded[2:4], 68) },
		"hostname length": func(encoded []byte) {
			binary.LittleEndian.PutUint16(encoded[requestHostnameLength:requestHostnameLength+2], ^uint16(0))
		},
		"client ID length": func(encoded []byte) {
			binary.LittleEndian.PutUint16(encoded[requestClientIDLength:requestClientIDLength+2], ^uint16(0))
		},
		"reserved": func(encoded []byte) { encoded[requestReserved] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			malformed := append([]byte(nil), memory...)
			mutate(malformed)
			if _, ok := DecodeRequestV1(malformed, 0); ok {
				t.Fatal("malformed request accepted")
			}
		})
	}
	if CheckRequestV1(memory, ^uint32(0)-RequestV1Size+2, 0) || CheckRequestV1(memory, 0, ^uint32(0)) {
		t.Fatal("overflowing fixed range accepted")
	}
	before := append([]byte(nil), memory...)
	if EncodeRequestV1(memory, 0, dhcpns.Request{RequestedAddr: netip.MustParseAddr("255.255.255.255")}) || !bytes.Equal(memory, before) {
		t.Fatal("limited-broadcast request encoding was accepted or mutated output")
	}
}

func FuzzDHCPv4V1Layouts(f *testing.F) {
	valid := make([]byte, 512)
	request := dhcpns.Request{RequestedAddr: netip.MustParseAddr("192.0.2.20"), HostnameLength: 4, ClientIDLength: 2}
	copy(request.Hostname[:], "host")
	copy(request.ClientID[:], "id")
	if !EncodeRequestV1(valid, 8, request) {
		f.Fatal("seed request")
	}
	f.Add(valid, uint32(8), uint32(400))
	f.Add([]byte{0xff, 1, 2, 3}, ^uint32(0), ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, requestPtr, outputPtr uint32) {
		if len(memory) > 4096 {
			t.Skip()
		}
		before := append([]byte(nil), memory...)
		decoded, ok := DecodeRequestV1(memory, requestPtr)
		_ = CheckRequestV1(memory, requestPtr, outputPtr)
		if !bytes.Equal(memory, before) {
			t.Fatal("request validation mutated memory")
		}
		if ok {
			if !decoded.Valid() {
				t.Fatal("decoded invalid request")
			}
			canonical := make([]byte, RequestV1Size)
			if !EncodeRequestV1(canonical, 0, decoded) {
				t.Fatal("decoded request did not re-encode")
			}
			if roundTrip, roundTripOK := DecodeRequestV1(canonical, 0); !roundTripOK || roundTrip != decoded {
				t.Fatalf("request round trip = %+v, %v", roundTrip, roundTripOK)
			}
		}

		encoded := append([]byte(nil), memory...)
		encodedBefore := append([]byte(nil), encoded...)
		if !EncodeRequestV1(encoded, outputPtr, request) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed request encode mutated memory")
		}
		lease := dhcpns.Lease{AssignedAddr: netip.MustParseAddr("192.0.2.20"), ServerAddr: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600}
		encoded = append(encoded[:0], memory...)
		encodedBefore = append(encodedBefore[:0], encoded...)
		if !EncodeLeaseV1(encoded, outputPtr, lease) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed lease encode mutated memory")
		}
	})
}
