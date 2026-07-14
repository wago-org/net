package lnetobackend

import (
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

var benchmarkDisabledNamespace *Namespace

func BenchmarkDisabledNamespaceNew(b *testing.B) {
	config := testConfig(91)
	b.ReportAllocs()
	for b.Loop() {
		ns, err := New(config)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkDisabledNamespace = ns
		if err := ns.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDisabledNamespaceIdleEgress(b *testing.B) {
	ns := newTestNamespace(b, testConfig(92))
	b.Cleanup(func() { _ = ns.Close() })
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	b.ReportAllocs()
	for b.Loop() {
		setNextIngress(ns, false)
		report, progress, err := ns.TryService(budget)
		if err != nil || progress != nscore.ProgressWouldBlock || report != (nscore.ServiceReport{}) {
			b.Fatalf("service = %+v, %v, %v", report, progress, err)
		}
	}
}
