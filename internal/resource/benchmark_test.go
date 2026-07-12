package resource

import "testing"

type benchmarkResourceValue struct{}

func (*benchmarkResourceValue) Close() error { return nil }

var (
	benchmarkHandle   Handle
	benchmarkResource Resource
	benchmarkErr      error
	benchmarkInt      int
	benchmarkTableID  uint32
	benchmarkGen      uint16
	benchmarkIndex    uint32
	benchmarkOK       bool
)

func BenchmarkNewTable(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		table, err := NewTable()
		if err != nil {
			b.Fatal(err)
		}
		if err := table.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTableAddCloseHandle(b *testing.B) {
	table := newTable(b)
	value := &benchmarkResourceValue{}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHandle, benchmarkErr = table.Add(KindUDPSocket, value)
		if benchmarkErr != nil {
			b.Fatal(benchmarkErr)
		}
		if err := table.CloseHandle(benchmarkHandle, KindUDPSocket); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTableLen(b *testing.B) {
	table := newTable(b)
	if _, err := table.Add(KindTCPStream, &benchmarkResourceValue{}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkInt = table.Len()
	}
}

func BenchmarkMakeHandle(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHandle = makeHandle(17, 3, 42)
	}
}

func BenchmarkSplitHandle(b *testing.B) {
	handle := makeHandle(17, 3, 42)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkTableID, benchmarkGen, benchmarkIndex, benchmarkOK = splitHandle(handle)
	}
}

func BenchmarkTableLookupBadHandle(b *testing.B) {
	table := newTable(b)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkResource, benchmarkErr = table.Lookup(Handle(1), KindTCPStream)
	}
}
