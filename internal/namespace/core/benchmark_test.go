package core

import (
	"net/netip"
	"testing"
)

type benchmarkNamespace struct{}

func (*benchmarkNamespace) Close() error         { return nil }
func (*benchmarkNamespace) Readiness() Readiness { return ReadyReadable | ReadyWritable }
func (*benchmarkNamespace) TryService(ServiceBudget) (ServiceReport, Progress, error) {
	return ServiceReport{}, ProgressWouldBlock, nil
}

var (
	benchmarkBool    bool
	benchmarkService any
	benchmarkBase    Namespace
)

func BenchmarkEndpointValid(b *testing.B) {
	endpoint := Endpoint{Address: netip.MustParseAddr("2001:db8::1"), Port: 443}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = endpoint.Valid()
	}
}

func BenchmarkIOResultValid(b *testing.B) {
	result := IOResult{Bytes: 1024, State: IOReady}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = result.Valid(4096)
	}
}

func BenchmarkReadinessValid(b *testing.B) {
	ready := ReadyReadable | ReadyWritable | ReadyConnected
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = ready.Valid()
	}
}

func BenchmarkServiceReportValidResult(b *testing.B) {
	budget := ServiceBudget{Packets: 4, Bytes: 4096, Operations: 8}
	report := ServiceReport{Packets: 2, Bytes: 2048, Operations: 4}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = report.ValidResult(budget, ProgressDone)
	}
}

func BenchmarkResolveNamespaceService(b *testing.B) {
	base := &benchmarkNamespace{}
	composed, err := ComposeNamespace(base, Service{Key: "udp", Value: base})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkService = ResolveNamespaceService(composed, "udp")
	}
}

func BenchmarkResolveNamespaceBase(b *testing.B) {
	base := &benchmarkNamespace{}
	composed, err := ComposeNamespace(base, Service{Key: "udp", Value: base})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBase = ResolveNamespaceBase(composed)
	}
}
