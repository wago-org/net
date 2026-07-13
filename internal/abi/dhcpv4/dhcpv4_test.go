package dhcpv4

import (
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
