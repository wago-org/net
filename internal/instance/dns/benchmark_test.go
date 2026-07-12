package dns

import (
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/resource"
)

type benchmarkQuery struct{ record namespace.DNSRecord }

func (*benchmarkQuery) Close() error                   { return nil }
func (*benchmarkQuery) Cancel() error                  { return nil }
func (*benchmarkQuery) Readiness() namespace.Readiness { return namespace.ReadyDNSResult }
func (q *benchmarkQuery) TryNext() (namespace.DNSRecord, namespace.DNSNext, error) {
	return q.record, namespace.DNSNextReady, nil
}

var (
	benchmarkHandle   resource.Handle
	benchmarkProgress namespace.Progress
	benchmarkRecord   namespace.DNSRecord
	benchmarkNext     namespace.DNSNext
	benchmarkErr      error
)

func BenchmarkResolveClose(b *testing.B) {
	query := &benchmarkQuery{}
	state, manager, instance := attachState(b, &fakeNamespace{query: query}, 2)
	defer manager.Detach(instance)
	request := namespace.DNSRequest{Name: "service.api.example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHandle, benchmarkProgress, benchmarkErr = Resolve(state, state.NamespaceHandle(), request)
		if benchmarkErr != nil || benchmarkProgress != namespace.ProgressInProgress {
			b.Fatalf("resolve = %v, %v, %v", benchmarkHandle, benchmarkProgress, benchmarkErr)
		}
		if err := state.CloseHandle(benchmarkHandle, resource.KindDNSQuery); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNext(b *testing.B) {
	record := namespace.DNSRecord{Name: "service.api.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 60, Address: netip.MustParseAddr("2001:db8::1")}
	query := &benchmarkQuery{record: record}
	state, manager, instance := attachState(b, &fakeNamespace{query: query}, 2)
	defer manager.Detach(instance)
	handle, _, err := Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: record.Name, Types: namespace.DNSRecordsAAAA})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkRecord, benchmarkNext, benchmarkErr = Next(state, handle)
		if benchmarkErr != nil || benchmarkNext != namespace.DNSNextReady {
			b.Fatalf("next = %+v, %v, %v", benchmarkRecord, benchmarkNext, benchmarkErr)
		}
	}
}

func BenchmarkCancel(b *testing.B) {
	query := &benchmarkQuery{}
	state, manager, instance := attachState(b, &fakeNamespace{query: query}, 2)
	defer manager.Detach(instance)
	handle, _, err := Resolve(state, state.NamespaceHandle(), namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkErr = Cancel(state, handle)
		if benchmarkErr != nil {
			b.Fatal(benchmarkErr)
		}
	}
}
