package core

import (
	"net/netip"
	"testing"
)

func TestIPv4IdentityLeaseAppliesExactlyAndRollsBack(t *testing.T) {
	config := testConfig(31)
	config.IPv4Address = netip.IPv4Unspecified()
	ns, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	var first, second IPv4IdentityLease
	assigned := netip.MustParseAddr("192.0.2.31")
	subnet := netip.MustParsePrefix("192.0.2.0/24")
	ns.Lock()
	if !ns.TryApplyIPv4IdentityLocked(&first, assigned, subnet) || ns.IPv4AddressLocked() != assigned || !first.Active() {
		ns.Unlock()
		t.Fatal("first identity application failed")
	}
	if ns.TryApplyIPv4IdentityLocked(&second, netip.MustParseAddr("192.0.2.32"), subnet) {
		ns.Unlock()
		t.Fatal("second identity contribution accepted")
	}
	if !first.ReleaseLocked() || ns.IPv4AddressLocked() != netip.IPv4Unspecified() || first.Active() {
		ns.Unlock()
		t.Fatal("identity rollback failed")
	}
	ns.Unlock()
}
