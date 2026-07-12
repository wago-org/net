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
