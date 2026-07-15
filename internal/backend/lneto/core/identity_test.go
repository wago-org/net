package core

import (
	"net/netip"
	"testing"
)

type ipv4IdentitySnapshot struct {
	stackPresent bool
	stackAddress [4]byte
	address      netip.Addr
	subnet       netip.Prefix
	current      *IPv4IdentityLease
	leaseOwner   *Namespace
	leaseActive  bool
}

func TestIPv4IdentityLeaseRejectsInvalidDynamicIdentityWithoutMutation(t *testing.T) {
	validAddress := netip.MustParseAddr("192.0.2.31")
	validSubnet := netip.MustParsePrefix("192.0.2.0/24")
	tests := []struct {
		name    string
		address netip.Addr
		subnet  netip.Prefix
	}{
		{name: "invalid address", address: netip.Addr{}, subnet: validSubnet},
		{name: "unspecified", address: netip.IPv4Unspecified(), subnet: netip.MustParsePrefix("0.0.0.0/0")},
		{name: "loopback", address: netip.MustParseAddr("127.0.0.1"), subnet: netip.MustParsePrefix("127.0.0.0/8")},
		{name: "multicast", address: netip.MustParseAddr("224.0.0.1"), subnet: netip.MustParsePrefix("224.0.0.0/4")},
		{name: "limited broadcast", address: netip.AddrFrom4([4]byte{255, 255, 255, 255}), subnet: netip.MustParsePrefix("255.255.255.0/24")},
		{name: "IPv6", address: netip.MustParseAddr("2001:db8::31"), subnet: netip.MustParsePrefix("2001:db8::/64")},
		{name: "mapped IPv4", address: netip.MustParseAddr("::ffff:192.0.2.31"), subnet: netip.MustParsePrefix("::ffff:192.0.2.0/120")},
		{name: "invalid prefix", address: validAddress, subnet: netip.PrefixFrom(validAddress, 33)},
		{name: "non-IPv4 prefix", address: validAddress, subnet: netip.MustParsePrefix("2001:db8::/64")},
		{name: "outside subnet", address: validAddress, subnet: netip.MustParsePrefix("198.51.100.0/24")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ns := newDynamicIPv4Namespace(t, byte(len(test.name)+1))
			var lease IPv4IdentityLease
			ns.Lock()
			before := snapshotIPv4IdentityLocked(ns, &lease)
			accepted := ns.TryApplyIPv4IdentityLocked(&lease, test.address, test.subnet)
			after := snapshotIPv4IdentityLocked(ns, &lease)
			ns.Unlock()
			if accepted {
				t.Fatalf("accepted invalid dynamic identity address=%v subnet=%v", test.address, test.subnet)
			}
			if after != before {
				t.Fatalf("rejection mutated identity:\n before=%+v\n after=%+v", before, after)
			}
		})
	}
}

func TestIPv4IdentityLeaseAcceptsUsableDynamicAddressesAndRollsBackExactly(t *testing.T) {
	for _, test := range []struct {
		name    string
		address netip.Addr
		subnet  netip.Prefix
	}{
		{name: "private", address: netip.MustParseAddr("10.20.30.40"), subnet: netip.MustParsePrefix("10.0.0.0/8")},
		{name: "link local", address: netip.MustParseAddr("169.254.31.32"), subnet: netip.MustParsePrefix("169.254.0.0/16")},
		{name: "global", address: netip.MustParseAddr("8.8.8.8"), subnet: netip.MustParsePrefix("8.8.8.0/24")},
	} {
		t.Run(test.name, func(t *testing.T) {
			ns := newDynamicIPv4Namespace(t, byte(len(test.name)+40))
			var lease IPv4IdentityLease
			ns.Lock()
			if !ns.TryApplyIPv4IdentityLocked(&lease, test.address, test.subnet) {
				ns.Unlock()
				t.Fatalf("rejected usable dynamic identity address=%v subnet=%v", test.address, test.subnet)
			}
			if got := netip.AddrFrom4(ns.stack.Addr4()); got != test.address {
				ns.Unlock()
				t.Fatalf("stack address = %v, want %v", got, test.address)
			}
			if ns.IPv4AddressLocked() != test.address || ns.IPv4SubnetLocked() != test.subnet.Masked() || ns.ipv4IdentityLease != &lease || !lease.Active() || lease.owner != ns {
				ns.Unlock()
				t.Fatalf("applied identity address=%v subnet=%v current=%p active=%v owner=%p", ns.IPv4AddressLocked(), ns.IPv4SubnetLocked(), ns.ipv4IdentityLease, lease.Active(), lease.owner)
			}
			if !lease.ReleaseLocked() {
				ns.Unlock()
				t.Fatal("exact active lease did not release")
			}
			wantStatic := netip.IPv4Unspecified()
			if got := netip.AddrFrom4(ns.stack.Addr4()); got != wantStatic || ns.IPv4AddressLocked() != wantStatic || ns.IPv4SubnetLocked() != netip.PrefixFrom(wantStatic, 32) || ns.ipv4IdentityLease != nil || lease.Active() || lease.owner != nil {
				ns.Unlock()
				t.Fatalf("rollback stack=%v address=%v subnet=%v current=%p active=%v owner=%p", got, ns.IPv4AddressLocked(), ns.IPv4SubnetLocked(), ns.ipv4IdentityLease, lease.Active(), lease.owner)
			}
			beforeRepeat := snapshotIPv4IdentityLocked(ns, &lease)
			if lease.ReleaseLocked() {
				ns.Unlock()
				t.Fatal("repeated release succeeded")
			}
			afterRepeat := snapshotIPv4IdentityLocked(ns, &lease)
			ns.Unlock()
			if afterRepeat != beforeRepeat {
				t.Fatalf("repeated release mutated identity:\n before=%+v\n after=%+v", beforeRepeat, afterRepeat)
			}
		})
	}
}

func TestIPv4IdentityLeaseRejectsActiveAndCompetingContributions(t *testing.T) {
	ns := newDynamicIPv4Namespace(t, 70)
	var active, competing IPv4IdentityLease
	address := netip.MustParseAddr("192.0.2.70")
	subnet := netip.MustParsePrefix("192.0.2.0/24")
	ns.Lock()
	if !ns.TryApplyIPv4IdentityLocked(&active, address, subnet) {
		ns.Unlock()
		t.Fatal("initial identity application failed")
	}
	beforeActive := snapshotIPv4IdentityLocked(ns, &active)
	if ns.TryApplyIPv4IdentityLocked(&active, netip.MustParseAddr("192.0.2.71"), subnet) {
		ns.Unlock()
		t.Fatal("active lease accepted a second identity")
	}
	if after := snapshotIPv4IdentityLocked(ns, &active); after != beforeActive {
		ns.Unlock()
		t.Fatalf("active-lease rejection mutated identity:\n before=%+v\n after=%+v", beforeActive, after)
	}
	beforeCompeting := snapshotIPv4IdentityLocked(ns, &competing)
	if ns.TryApplyIPv4IdentityLocked(&competing, netip.MustParseAddr("192.0.2.72"), subnet) {
		ns.Unlock()
		t.Fatal("competing lease accepted while identity was owned")
	}
	if after := snapshotIPv4IdentityLocked(ns, &competing); after != beforeCompeting {
		ns.Unlock()
		t.Fatalf("competing-lease rejection mutated identity:\n before=%+v\n after=%+v", beforeCompeting, after)
	}

	foreign := IPv4IdentityLease{owner: ns, active: true}
	beforeForeign := snapshotIPv4IdentityLocked(ns, &active)
	if foreign.ReleaseLocked() {
		ns.Unlock()
		t.Fatal("foreign lease released active identity")
	}
	if after := snapshotIPv4IdentityLocked(ns, &active); after != beforeForeign {
		ns.Unlock()
		t.Fatalf("foreign release mutated active identity:\n before=%+v\n after=%+v", beforeForeign, after)
	}
	if foreign.Active() || foreign.owner != nil {
		ns.Unlock()
		t.Fatal("foreign lease retained false ownership")
	}
	if !active.ReleaseLocked() {
		ns.Unlock()
		t.Fatal("active lease release failed after rejected competitors")
	}
	ns.Unlock()
}

func TestIPv4IdentityLeaseRejectsClosedAndIncompleteNamespaces(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.80")
	subnet := netip.MustParsePrefix("192.0.2.0/24")
	var nilNamespace *Namespace
	var nilLease IPv4IdentityLease
	if nilNamespace.TryApplyIPv4IdentityLocked(&nilLease, address, subnet) || nilLease.Active() {
		t.Fatal("nil namespace accepted identity")
	}

	closed := newDynamicIPv4Namespace(t, 80)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	var closedLease IPv4IdentityLease
	closed.Lock()
	beforeClosed := snapshotIPv4IdentityLocked(closed, &closedLease)
	acceptedClosed := closed.TryApplyIPv4IdentityLocked(&closedLease, address, subnet)
	afterClosed := snapshotIPv4IdentityLocked(closed, &closedLease)
	closed.Unlock()
	if acceptedClosed || afterClosed != beforeClosed {
		t.Fatalf("closed namespace result accepted=%v before=%+v after=%+v", acceptedClosed, beforeClosed, afterClosed)
	}

	incomplete := &Namespace{ipv4Address: netip.IPv4Unspecified(), ipv4Subnet: netip.PrefixFrom(netip.IPv4Unspecified(), 32), staticIPv4Address: netip.IPv4Unspecified()}
	var incompleteLease IPv4IdentityLease
	incomplete.Lock()
	beforeIncomplete := snapshotIPv4IdentityLocked(incomplete, &incompleteLease)
	acceptedIncomplete := incomplete.TryApplyIPv4IdentityLocked(&incompleteLease, address, subnet)
	afterIncomplete := snapshotIPv4IdentityLocked(incomplete, &incompleteLease)
	incomplete.Unlock()
	if acceptedIncomplete || afterIncomplete != beforeIncomplete {
		t.Fatalf("incomplete namespace result accepted=%v before=%+v after=%+v", acceptedIncomplete, beforeIncomplete, afterIncomplete)
	}
}

func newDynamicIPv4Namespace(t testing.TB, id byte) *Namespace {
	t.Helper()
	config := testConfig(id)
	config.IPv4Address = netip.IPv4Unspecified()
	ns, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func snapshotIPv4IdentityLocked(ns *Namespace, lease *IPv4IdentityLease) ipv4IdentitySnapshot {
	snapshot := ipv4IdentitySnapshot{
		address:     ns.ipv4Address,
		subnet:      ns.ipv4Subnet,
		current:     ns.ipv4IdentityLease,
		leaseOwner:  lease.owner,
		leaseActive: lease.active,
	}
	if ns.stack != nil {
		snapshot.stackPresent = true
		snapshot.stackAddress = ns.stack.Addr4()
	}
	return snapshot
}
