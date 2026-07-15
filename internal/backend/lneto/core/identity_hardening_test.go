package core

import (
	"net/netip"
	"testing"
)

func TestIPv4IdentityLeaseRejectsNonWireAddressesWithoutMutation(t *testing.T) {
	config := testConfig(32)
	config.IPv4Address = netip.IPv4Unspecified()
	ns, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })

	tests := []struct {
		name    string
		address netip.Addr
		subnet  netip.Prefix
	}{
		{
			name:    "loopback",
			address: netip.MustParseAddr("127.0.0.1"),
			subnet:  netip.MustParsePrefix("127.0.0.0/8"),
		},
		{
			name:    "limited broadcast",
			address: netip.MustParseAddr("255.255.255.255"),
			subnet:  netip.MustParsePrefix("0.0.0.0/0"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var lease IPv4IdentityLease
			ns.Lock()
			beforeAddress := ns.IPv4AddressLocked()
			beforeLease := ns.ipv4IdentityLease
			applied := ns.TryApplyIPv4IdentityLocked(&lease, test.address, test.subnet)
			afterAddress := ns.IPv4AddressLocked()
			afterLease := ns.ipv4IdentityLease
			ns.Unlock()
			if applied {
				t.Fatalf("TryApplyIPv4IdentityLocked accepted %s", test.address)
			}
			if afterAddress != beforeAddress || afterLease != beforeLease || lease.Active() {
				t.Fatalf("rejected identity mutated state: address=%v/%v lease=%p/%p active=%v", afterAddress, beforeAddress, afterLease, beforeLease, lease.Active())
			}
		})
	}
}
