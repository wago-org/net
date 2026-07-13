package quota

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAccountExactLimitsAndProtocolTotals(t *testing.T) {
	account := NewAccount(Limits{Resources: 3, UDPResources: 2, TCPResources: 1})
	udp, err := account.ReserveResource(ResourceUDP, 2)
	if err != nil {
		t.Fatalf("reserve UDP: %v", err)
	}
	udpAllocation, ok := udp.Commit()
	if !ok {
		t.Fatal("commit UDP failed")
	}
	tcp, err := account.ReserveResource(ResourceTCP, 1)
	if err != nil {
		t.Fatalf("reserve TCP: %v", err)
	}
	tcpAllocation, ok := tcp.Commit()
	if !ok {
		t.Fatal("commit TCP failed")
	}
	if _, err := account.ReserveResource(ResourceOther, 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("reserve over total error = %v", err)
	}
	if _, err := account.ReserveResource(ResourceUDP, 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("reserve over UDP error = %v", err)
	}
	usage, closed := account.Snapshot()
	if closed || usage.Resources != 3 || usage.UDPResources != 2 || usage.TCPResources != 1 {
		t.Fatalf("usage = %+v closed=%v", usage, closed)
	}
	if !udpAllocation.Release() || !tcpAllocation.Release() {
		t.Fatal("release failed")
	}
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("usage after release = %+v", usage)
	}
}

func TestICMPv4ResourceWorkAndRetainedByteAccounting(t *testing.T) {
	account := NewAccount(Limits{Resources: 1, ICMPv4Resources: 1, QueuedBytes: 64, ICMPv4Work: 1})
	var retained, work Charge
	if err := account.AcquireResourceAndQueuedBytes(&retained, ResourceICMPv4, 1, 64); err != nil {
		t.Fatal(err)
	}
	if err := account.AcquireICMPv4Work(&work, 1); err != nil {
		t.Fatal(err)
	}
	if usage, closed := account.Snapshot(); closed || usage != (Usage{Resources: 1, ICMPv4Resources: 1, QueuedBytes: 64, ICMPv4Work: 1}) {
		t.Fatalf("ICMPv4 usage = %+v, closed=%v", usage, closed)
	}
	var denied Charge
	if err := account.AcquireResource(&denied, ResourceICMPv4, 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("ICMPv4 resource limit error = %v", err)
	}
	if err := account.AcquireICMPv4Work(&denied, 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("ICMPv4 work limit error = %v", err)
	}
	if !work.Release() || !retained.Release() {
		t.Fatal("ICMPv4 charges did not release")
	}
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("ICMPv4 release leaked usage: %+v", usage)
	}
}

func TestReservationRollbackAndFailureDoNotLeak(t *testing.T) {
	account := NewAccount(Limits{QueuedBytes: 8, DNSWork: 1, ServiceUnits: 2})
	bytes, err := account.ReserveQueuedBytes(8)
	if err != nil {
		t.Fatalf("reserve bytes: %v", err)
	}
	if _, err := account.ReserveQueuedBytes(1); !errors.Is(err, ErrLimit) {
		t.Fatalf("reserve over bytes error = %v", err)
	}
	if !bytes.Rollback() || bytes.Rollback() {
		t.Fatal("rollback was not exactly once")
	}
	if allocation, ok := bytes.Commit(); ok || allocation != nil {
		t.Fatal("rolled-back reservation committed")
	}
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("rollback leaked usage: %+v", usage)
	}

	for _, reserve := range []func() (*Reservation, error){
		func() (*Reservation, error) { return account.ReserveDNSWork(1) },
		func() (*Reservation, error) { return account.ReserveService(2) },
	} {
		reservation, err := reserve()
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		allocation, ok := reservation.Commit()
		if !ok {
			t.Fatal("commit failed")
		}
		if reservation.Rollback() {
			t.Fatal("rollback succeeded after commit")
		}
		if !allocation.Release() || allocation.Release() {
			t.Fatal("allocation release was not exactly once")
		}
	}
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("commit/release leaked usage: %+v", usage)
	}
}

func TestEmbeddedAllocationCompositeCharge(t *testing.T) {
	metadataOnly := NewAccount(Limits{Resources: 1, UDPResources: 1})
	var metadata Charge
	if err := metadataOnly.AcquireResourceAndQueuedBytes(&metadata, ResourceUDP, 1, 0); err != nil {
		t.Fatalf("acquire metadata-only resource: %v", err)
	}
	if usage, closed := metadataOnly.Snapshot(); closed || usage != (Usage{Resources: 1, UDPResources: 1}) {
		t.Fatalf("metadata-only usage = %+v, closed=%v", usage, closed)
	}
	if !metadata.Release() {
		t.Fatal("release metadata-only resource")
	}
	if usage, closed := metadataOnly.Snapshot(); closed || usage != (Usage{}) {
		t.Fatalf("metadata-only release usage = %+v, closed=%v", usage, closed)
	}

	account := NewAccount(Limits{Resources: 1, DNSResources: 1, QueuedBytes: 1024, DNSWork: 2})
	var retained Charge
	var work Charge
	if err := account.AcquireResourceAndQueuedBytes(&retained, ResourceDNS, 1, 1024); err != nil {
		t.Fatal(err)
	}
	if err := account.AcquireDNSWork(&work, 2); err != nil {
		t.Fatal(err)
	}
	if usage, closed := account.Snapshot(); closed || usage != (Usage{Resources: 1, DNSResources: 1, QueuedBytes: 1024, DNSWork: 2}) {
		t.Fatalf("embedded usage = %+v, closed=%v", usage, closed)
	}
	if err := account.AcquireDNSWork(&work, 1); !errors.Is(err, ErrInvalidUnits) {
		t.Fatalf("reused allocation error = %v", err)
	}
	if work.ResetReleased() {
		t.Fatal("active embedded allocation reset")
	}
	if !work.Release() || work.Release() || !work.ResetReleased() || work.ResetReleased() {
		t.Fatal("embedded work release/reset was not exactly once")
	}
	if err := account.AcquireDNSWork(&work, 1); err != nil {
		t.Fatalf("reacquire reset storage: %v", err)
	}
	if !work.Release() || !retained.Release() || retained.Release() {
		t.Fatal("embedded release was not exactly once")
	}
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("embedded release leaked usage: %+v", usage)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		var charge Charge
		if err := account.AcquireResourceAndQueuedBytes(&charge, ResourceDNS, 1, 1); err != nil {
			t.Fatal(err)
		}
		charge.Release()
	})
	if allocs != 0 {
		t.Fatalf("embedded allocation path allocated %v times", allocs)
	}
}

func TestWithServiceScopesChargeWithoutAllocatingTokens(t *testing.T) {
	account := NewAccount(Limits{ServiceUnits: 2})
	called := false
	if err := account.WithService(2, func() {
		called = true
		usage, closed := account.Snapshot()
		if closed || usage.ServiceUnits != 2 {
			t.Fatalf("scoped service usage = %+v, closed=%v", usage, closed)
		}
		if _, err := account.ReserveService(1); !errors.Is(err, ErrLimit) {
			t.Fatalf("scoped service limit error = %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("scoped service callback was not called")
	}
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("scoped service leaked usage: %+v", usage)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("scoped service panic was not propagated")
			}
		}()
		_ = account.WithService(1, func() { panic("test panic") })
	}()
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("panic cleanup leaked usage: %+v", usage)
	}

	var callErr error
	allocs := testing.AllocsPerRun(1000, func() {
		callErr = account.WithService(1, func() {})
	})
	if callErr != nil {
		t.Fatal(callErr)
	}
	if allocs != 0 {
		t.Fatalf("scoped service allocations = %v, want 0", allocs)
	}
}

func TestAccountRejectsInvalidZeroAndOverflowingUnits(t *testing.T) {
	account := NewAccount(Limits{Resources: ^uint64(0), UDPResources: ^uint64(0), QueuedBytes: ^uint64(0)})
	invalid := []func() error{
		func() error { _, err := account.ReserveResource(0, 1); return err },
		func() error { _, err := account.ReserveResource(ResourceUDP, 0); return err },
		func() error { _, err := account.ReserveQueuedBytes(0); return err },
		func() error { _, err := account.ReserveDNSWork(0); return err },
		func() error { _, err := account.ReserveService(0); return err },
		func() error { return account.WithService(0, func() {}) },
		func() error { return account.WithService(1, nil) },
	}
	for i, call := range invalid {
		if err := call(); !errors.Is(err, ErrInvalidUnits) {
			t.Fatalf("invalid call %d error = %v", i, err)
		}
	}
	reservation, err := account.ReserveQueuedBytes(^uint64(0))
	if err != nil {
		t.Fatalf("reserve max: %v", err)
	}
	if _, err := account.ReserveQueuedBytes(1); !errors.Is(err, ErrLimit) {
		t.Fatalf("overflowing reserve error = %v", err)
	}
	if !reservation.Rollback() {
		t.Fatal("rollback max reservation failed")
	}
}

func TestAccountConcurrentReservationNeverExceedsLimit(t *testing.T) {
	const limit = 64
	account := NewAccount(Limits{Resources: limit, UDPResources: limit})
	start := make(chan struct{})
	release := make(chan struct{})
	var successful atomic.Int32
	var attempted sync.WaitGroup
	var wait sync.WaitGroup
	attempted.Add(256)
	for range 256 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			reservation, err := account.ReserveResource(ResourceUDP, 1)
			if errors.Is(err, ErrLimit) {
				attempted.Done()
				return
			}
			if err != nil {
				t.Errorf("ReserveResource: %v", err)
				attempted.Done()
				return
			}
			allocation, ok := reservation.Commit()
			if !ok {
				t.Error("Commit failed")
				attempted.Done()
				return
			}
			successful.Add(1)
			attempted.Done()
			<-release
			allocation.Release()
		}()
	}
	close(start)
	attempted.Wait()
	usage, _ := account.Snapshot()
	if usage.Resources != limit || usage.UDPResources != limit {
		t.Fatalf("peak usage = %+v", usage)
	}
	close(release)
	wait.Wait()
	if successful.Load() != limit {
		t.Fatalf("successful reservations = %d, want %d", successful.Load(), limit)
	}
	if usage, _ := account.Snapshot(); usage != (Usage{}) {
		t.Fatalf("concurrent releases leaked usage: %+v", usage)
	}
}

func TestAccountCloseReleasesEverythingAndRejectsLateUse(t *testing.T) {
	account := NewAccount(Limits{QueuedBytes: 16, DNSWork: 1, ServiceUnits: 1})
	pending, err := account.ReserveQueuedBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	lateCommit, err := account.ReserveService(1)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := account.ReserveDNSWork(1)
	if err != nil {
		t.Fatal(err)
	}
	allocation, ok := committed.Commit()
	if !ok {
		t.Fatal("commit failed")
	}
	account.Close()
	account.Close()
	if usage, closed := account.Snapshot(); !closed || usage != (Usage{}) {
		t.Fatalf("closed snapshot = %+v, %v", usage, closed)
	}
	if _, err := account.ReserveService(1); !errors.Is(err, ErrClosed) {
		t.Fatalf("reserve after close error = %v", err)
	}
	if allocation, ok := lateCommit.Commit(); ok || allocation != nil {
		t.Fatal("pending reservation committed after close")
	}
	if allocation.Release() != true || allocation.Release() != false {
		t.Fatal("late allocation release was not locally exactly once")
	}
	if pending.Rollback() != true || pending.Rollback() != false {
		t.Fatal("late rollback was not locally exactly once")
	}
}
