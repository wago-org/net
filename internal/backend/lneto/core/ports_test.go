package core

import "testing"

func TestUDPPortLeasesShareCollisionAndReleaseDomain(t *testing.T) {
	ns := newTestNamespace(t, 11)
	ns.Lock()
	first, ok := ns.TryLeaseUDPPortLocked(53000)
	if !ok || first.UDPPort() != 53000 {
		ns.Unlock()
		t.Fatalf("first lease = %#v, %v", first, ok)
	}
	if duplicate, ok := ns.TryLeaseUDPPortLocked(53000); ok || duplicate != nil {
		ns.Unlock()
		t.Fatalf("duplicate lease = %#v, %v", duplicate, ok)
	}
	second, next, ok := ns.TryLeaseUDPPortRangeLocked(53000, 53000, 2)
	if !ok || second.UDPPort() != 53001 || next != 53002 || ns.UDPPortLeaseCountLocked() != 2 {
		ns.Unlock()
		t.Fatalf("range lease = %#v, next=%d ok=%v count=%d", second, next, ok, ns.UDPPortLeaseCountLocked())
	}
	first.ReleaseLocked()
	first.ReleaseLocked()
	reused, ok := ns.TryLeaseUDPPortLocked(53000)
	if !ok || reused.UDPPort() != 53000 || ns.UDPPortLeaseCountLocked() != 2 {
		ns.Unlock()
		t.Fatalf("reused lease = %#v, %v count=%d", reused, ok, ns.UDPPortLeaseCountLocked())
	}
	reused.ReleaseLocked()
	second.ReleaseLocked()
	if ns.UDPPortLeaseCountLocked() != 0 {
		ns.Unlock()
		t.Fatalf("released count = %d", ns.UDPPortLeaseCountLocked())
	}
	ns.Unlock()
}

func TestUDPPortLeaseRangeExhaustionAndWrap(t *testing.T) {
	ns := newTestNamespace(t, 12)
	ns.Lock()
	last, ok := ns.TryLeaseUDPPortLocked(^uint16(0))
	if !ok {
		ns.Unlock()
		t.Fatal("last port lease failed")
	}
	first, ok := ns.TryLeaseUDPPortLocked(53000)
	if !ok {
		ns.Unlock()
		t.Fatal("first port lease failed")
	}
	if lease, _, ok := ns.TryLeaseUDPPortRangeLocked(^uint16(0), 53000, 2); ok || lease != nil {
		ns.Unlock()
		t.Fatalf("exhausted range lease = %#v, %v", lease, ok)
	}
	first.ReleaseLocked()
	lease, next, ok := ns.TryLeaseUDPPortRangeLocked(^uint16(0), 53000, 2)
	if !ok || lease.UDPPort() != 53000 || next != 53001 {
		ns.Unlock()
		t.Fatalf("wrapped range lease = %#v next=%d ok=%v", lease, next, ok)
	}
	lease.ReleaseLocked()
	last.ReleaseLocked()
	ns.Unlock()
}

func TestUDPPortLeasesInvalidateOnCoreClose(t *testing.T) {
	ns, err := New(testConfig(13))
	if err != nil {
		t.Fatal(err)
	}
	ns.Lock()
	lease, ok := ns.TryLeaseUDPPortLocked(53000)
	ns.Unlock()
	if !ok {
		t.Fatal("lease failed")
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if lease.UDPPort() != 0 {
		t.Fatalf("closed lease port = %d", lease.UDPPort())
	}
	ns.Lock()
	if got := ns.UDPPortLeaseCountLocked(); got != 0 {
		ns.Unlock()
		t.Fatalf("closed lease count = %d", got)
	}
	if lease, ok := ns.TryLeaseUDPPortLocked(53000); ok || lease != nil {
		ns.Unlock()
		t.Fatalf("closed namespace leased port: %#v, %v", lease, ok)
	}
	ns.Unlock()
}
