package mdns

import (
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/policy"
)

func TestOptionsDeepCopyConfigurationRespectOrderAndSuppressDefaults(t *testing.T) {
	service := Service{
		Name: "device._demo._udp.local", Host: "device.local", Address: netip.MustParseAddr("192.0.2.44"),
		TTLSeconds: 60, Port: 9000, TXT: []byte{3, 'k', '=', 'v'},
	}
	input := DefaultConfig()
	input.Services = []Service{service}
	input.MaxServices = 1
	config := registration{defaultAuthority: true}
	for _, option := range []Option{WithConfig(input), WithServices(service), AllowAllNames(), WithoutDefaultAuthority()} {
		if err := option.applyMDNS(&config); err != nil {
			t.Fatal(err)
		}
	}
	input.Services[0].Name = "mutated.local"
	input.Services[0].TXT[0] = 0xff
	service.TXT[0] = 0xee
	if got := config.config.Services[0]; got.Name != "device._demo._udp.local" || got.TXT[0] != 3 {
		t.Fatalf("copied service = %+v", got)
	}
	compiled, err := policy.Compile(config.authority())
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckDNS(policy.OperationMDNSQuery, "anything.local") || !compiled.CheckDNS(policy.OperationMDNSRespond, "anything.local") {
		t.Fatal("AllowAllNames did not grant both mDNS name directions")
	}
	multicast := netip.AddrFrom4([4]byte{224, 0, 0, 251})
	if compiled.CheckEndpoint(policy.OperationMDNSSend, multicast, 5353) {
		t.Fatal("default multicast endpoint authority survived suppression")
	}
}

func TestWithServicesAfterDisabledConfigAddsOnlyFiniteServiceBounds(t *testing.T) {
	service := Service{Name: "device._demo._udp.local", Host: "device.local", Address: netip.MustParseAddr("192.0.2.45"), Port: 9000}
	config := registration{}
	if err := WithConfig(Config{}).applyMDNS(&config); err != nil {
		t.Fatal(err)
	}
	if err := WithServices(service).applyMDNS(&config); err != nil {
		t.Fatal(err)
	}
	if len(config.config.Services) != 1 || config.config.MaxServices != 1 || config.config.MaxAnnouncements != 4 || config.config.MaxQueuedResponses != 4 {
		t.Fatalf("service option = %+v", config.config)
	}
}
