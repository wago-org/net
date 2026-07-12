package quota

import "testing"

var (
	benchmarkUsage  Usage
	benchmarkClosed bool
	benchmarkErr    error
)

func BenchmarkReserveResourceRollback(b *testing.B) {
	account := NewAccount(Limits{Resources: 1, UDPResources: 1})
	b.ReportAllocs()
	for b.Loop() {
		reservation, err := account.ReserveResource(ResourceUDP, 1)
		if err != nil || !reservation.Rollback() {
			b.Fatalf("reserve/rollback: %v", err)
		}
	}
}

func BenchmarkReserveResourceCommitRelease(b *testing.B) {
	account := NewAccount(Limits{Resources: 1, TCPResources: 1})
	b.ReportAllocs()
	for b.Loop() {
		reservation, err := account.ReserveResource(ResourceTCP, 1)
		if err != nil {
			b.Fatal(err)
		}
		allocation, ok := reservation.Commit()
		if !ok || !allocation.Release() {
			b.Fatal("commit/release")
		}
	}
}

func BenchmarkAcquireResourceAndQueuedBytesRelease(b *testing.B) {
	account := NewAccount(Limits{Resources: 1, DNSResources: 1, QueuedBytes: 1024})
	b.ReportAllocs()
	for b.Loop() {
		var charge Charge
		if err := account.AcquireResourceAndQueuedBytes(&charge, ResourceDNS, 1, 1024); err != nil || !charge.Release() {
			b.Fatalf("acquire/release: %v", err)
		}
	}
}

func BenchmarkAcquireResourceParallel(b *testing.B) {
	account := NewAccount(Limits{Resources: ^uint64(0), TCPResources: ^uint64(0)})
	b.ReportAllocs()
	b.RunParallel(func(parallel *testing.PB) {
		var charge Charge
		for parallel.Next() {
			if err := account.AcquireResource(&charge, ResourceTCP, 1); err != nil {
				panic(err)
			}
			if !charge.Release() || !charge.ResetReleased() {
				panic("parallel release/reset")
			}
		}
	})
}

func BenchmarkWithService(b *testing.B) {
	account := NewAccount(Limits{ServiceUnits: 1})
	work := func() {}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkErr = account.WithService(1, work)
	}
}

func BenchmarkSnapshot(b *testing.B) {
	account := NewAccount(DefaultLimits())
	b.ReportAllocs()
	for b.Loop() {
		benchmarkUsage, benchmarkClosed = account.Snapshot()
	}
}
