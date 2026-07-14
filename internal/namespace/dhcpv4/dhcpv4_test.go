package dhcpv4

import (
	"net/netip"
	"testing"
)

func TestRequestOwnsFiniteInlineValues(t *testing.T) {
	request := Request{RequestedAddr: netip.MustParseAddr("192.0.2.10"), HostnameLength: 4, ClientIDLength: 3}
	copy(request.Hostname[:], "host")
	copy(request.ClientID[:], "id1")
	if !request.Valid() || request.HostnameString() != "host" || request.ClientIDString() != "id1" {
		t.Fatalf("request = %+v", request)
	}
	request.Hostname[10] = 'x'
	if request.Valid() {
		t.Fatal("nonzero hostname padding accepted")
	}
}

func TestRequestRejectsLimitedBroadcastAddress(t *testing.T) {
	if request := (Request{RequestedAddr: limitedBroadcast}); request.Valid() {
		t.Fatalf("limited-broadcast request accepted: %+v", request)
	}
}

func TestLeaseValidationBoundsOptions(t *testing.T) {
	lease := Lease{
		AssignedAddr: netip.MustParseAddr("192.0.2.10"), ServerAddr: netip.MustParseAddr("192.0.2.1"),
		RouterAddr: netip.MustParseAddr("192.0.2.1"), BroadcastAddr: netip.MustParseAddr("192.0.2.255"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, RenewalSeconds: 1800, RebindSeconds: 3150,
		DNSCount: 1, DNSServers: [MaxDNSServers]netip.Addr{netip.MustParseAddr("192.0.2.53")}, Applied: true,
	}
	if !lease.Valid() {
		t.Fatalf("valid lease rejected: %+v", lease)
	}
	lease.DNSCount = MaxDNSServers + 1
	if lease.Valid() {
		t.Fatal("excess DNS count accepted")
	}
	lease.DNSCount = 1
	lease.RenewalSeconds = 3200
	if lease.Valid() {
		t.Fatal("renewal after rebind accepted")
	}
}

func TestLeaseRejectsLimitedBroadcastAddresses(t *testing.T) {
	valid := Lease{
		AssignedAddr: netip.MustParseAddr("192.0.2.10"), ServerAddr: netip.MustParseAddr("192.0.2.1"),
		RouterAddr: netip.MustParseAddr("192.0.2.1"), BroadcastAddr: netip.MustParseAddr("192.0.2.255"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600,
		DNSCount: 1, DNSServers: [MaxDNSServers]netip.Addr{netip.MustParseAddr("192.0.2.53")},
	}
	for _, mutate := range []struct {
		name string
		do   func(*Lease)
	}{
		{name: "assigned", do: func(lease *Lease) { lease.AssignedAddr = limitedBroadcast }},
		{name: "server", do: func(lease *Lease) { lease.ServerAddr = limitedBroadcast }},
		{name: "router", do: func(lease *Lease) { lease.RouterAddr = limitedBroadcast }},
		{name: "broadcast", do: func(lease *Lease) { lease.BroadcastAddr = limitedBroadcast }},
		{name: "DNS", do: func(lease *Lease) { lease.DNSServers[0] = limitedBroadcast }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			lease := valid
			mutate.do(&lease)
			if lease.Valid() {
				t.Fatalf("limited-broadcast %s accepted: %+v", mutate.name, lease)
			}
		})
	}
}
