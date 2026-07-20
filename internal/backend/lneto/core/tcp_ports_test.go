package core

import "testing"

func TestTCPPortLeasesShareOwnersPreventStaleReleaseAndReuse(t *testing.T) {
	config := testConfig(71)
	config.MaxActiveTCPPorts = 4
	ns, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	ns.Lock()
	firstOwner := ns.NewTCPPortOwnerLocked()
	secondOwner := ns.NewTCPPortOwnerLocked()
	var first, duplicate, second, stale TCPPortLease
	if !ns.AcquireTCPPortIntoLocked(&first, firstOwner, FirstEphemeralTCPPort) {
		ns.Unlock()
		t.Fatal("first exact lease")
	}
	if ns.AcquireTCPPortIntoLocked(&duplicate, secondOwner, FirstEphemeralTCPPort) {
		ns.Unlock()
		t.Fatal("duplicate exact lease")
	}
	if !ns.AcquireTCPPortIntoLocked(&second, secondOwner, 0) || second.TCPPort() == first.TCPPort() {
		ns.Unlock()
		t.Fatalf("shared ephemeral lease = %d, first=%d", second.TCPPort(), first.TCPPort())
	}
	stale = first
	first.ReleaseLocked()
	if !ns.AcquireTCPPortIntoLocked(&duplicate, secondOwner, FirstEphemeralTCPPort) {
		ns.Unlock()
		t.Fatal("released exact port was not reusable")
	}
	stale.ReleaseLocked()
	if duplicate.TCPPort() != FirstEphemeralTCPPort || !ns.OwnsTCPPortLocked(FirstEphemeralTCPPort, secondOwner) {
		ns.Unlock()
		t.Fatal("stale copied lease released a new owner")
	}
	duplicate.ReleaseLocked()
	duplicate.ReleaseLocked()
	second.ReleaseLocked()
	if got := ns.TCPPortLeaseCountLocked(); got != 0 {
		ns.Unlock()
		t.Fatalf("lease count = %d", got)
	}
	ns.Unlock()
}

func TestTCPPortLeaseExhaustionWrapAndTeardown(t *testing.T) {
	config := testConfig(72)
	config.MaxActiveTCPPorts = 2
	ns, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ns.Lock()
	owner := ns.NewTCPPortOwnerLocked()
	ns.nextTCPPort = ^uint16(0)
	var last, wrapped, exhausted TCPPortLease
	if !ns.AcquireTCPPortIntoLocked(&last, owner, 0) || last.TCPPort() != ^uint16(0) {
		ns.Unlock()
		t.Fatalf("last lease = %d", last.TCPPort())
	}
	if !ns.AcquireTCPPortIntoLocked(&wrapped, owner, 0) || wrapped.TCPPort() != FirstEphemeralTCPPort {
		ns.Unlock()
		t.Fatalf("wrapped lease = %d", wrapped.TCPPort())
	}
	if ns.AcquireTCPPortIntoLocked(&exhausted, owner, 0) {
		ns.Unlock()
		t.Fatal("lease beyond namespace maximum")
	}
	ns.Unlock()
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if last.TCPPort() != 0 || wrapped.TCPPort() != 0 {
		t.Fatalf("teardown retained leases: last=%d wrapped=%d", last.TCPPort(), wrapped.TCPPort())
	}
	ns.Lock()
	if ns.NewTCPPortOwnerLocked() != nil || ns.AcquireTCPPortIntoLocked(&exhausted, owner, 0) || ns.TCPPortLeaseCountLocked() != 0 {
		ns.Unlock()
		t.Fatal("closed namespace accepted TCP ownership")
	}
	ns.Unlock()
}
