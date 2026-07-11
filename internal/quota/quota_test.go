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

func TestAccountRejectsInvalidZeroAndOverflowingUnits(t *testing.T) {
	account := NewAccount(Limits{Resources: ^uint64(0), UDPResources: ^uint64(0), QueuedBytes: ^uint64(0)})
	invalid := []func() error{
		func() error { _, err := account.ReserveResource(0, 1); return err },
		func() error { _, err := account.ReserveResource(ResourceUDP, 0); return err },
		func() error { _, err := account.ReserveQueuedBytes(0); return err },
		func() error { _, err := account.ReserveDNSWork(0); return err },
		func() error { _, err := account.ReserveService(0); return err },
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
