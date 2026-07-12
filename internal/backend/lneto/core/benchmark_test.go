package core

import (
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
)

var (
	benchmarkServiceReport nscore.ServiceReport
	benchmarkProgress      nscore.Progress
	benchmarkErr           error
	benchmarkReadiness     nscore.Readiness
	benchmarkLease         *UDPPortLease
	benchmarkPort          uint16
	benchmarkOK            bool
)

func BenchmarkNamespaceReadiness(b *testing.B) {
	ns := newTestNamespace(b, 81)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkReadiness = ns.Readiness()
	}
}

func BenchmarkUDPPortLeaseAcquireRelease(b *testing.B) {
	ns := newTestNamespace(b, 80)
	b.ReportAllocs()
	for b.Loop() {
		ns.Lock()
		benchmarkLease, benchmarkOK = ns.TryLeaseUDPPortLocked(53000)
		if benchmarkOK {
			benchmarkLease.ReleaseLocked()
		}
		ns.Unlock()
		if !benchmarkOK {
			b.Fatal("lease")
		}
	}
}

func BenchmarkUDPPortLeaseRangeAcquireRelease(b *testing.B) {
	ns := newTestNamespace(b, 79)
	b.ReportAllocs()
	for b.Loop() {
		ns.Lock()
		benchmarkLease, benchmarkPort, benchmarkOK = ns.TryLeaseUDPPortRangeLocked(53000, 53000, 8)
		if benchmarkOK {
			benchmarkLease.ReleaseLocked()
		}
		ns.Unlock()
		if !benchmarkOK || benchmarkPort == 0 {
			b.Fatal("range lease")
		}
	}
}

func BenchmarkNamespaceTryServiceIdle(b *testing.B) {
	ns := newTestNamespace(b, 82)
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 2}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkServiceReport, benchmarkProgress, benchmarkErr = ns.TryService(budget)
		if benchmarkErr != nil || benchmarkProgress != nscore.ProgressWouldBlock {
			b.Fatalf("service = %+v, %v, %v", benchmarkServiceReport, benchmarkProgress, benchmarkErr)
		}
	}
}

func BenchmarkNamespaceTryServiceIngress(b *testing.B) {
	ns := newTestNamespace(b, 83)
	if err := ns.Install(Participant{Ingress: func([]byte) (bool, error) { return true, nil }}); err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, 64)
	budget := nscore.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1}
	b.SetBytes(64)
	b.ReportAllocs()
	for b.Loop() {
		if err := ns.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
			b.Fatal(err)
		}
		ns.Lock()
		ns.SetNextIngressLocked(true)
		ns.Unlock()
		benchmarkServiceReport, benchmarkProgress, benchmarkErr = ns.TryService(budget)
		if benchmarkErr != nil || benchmarkServiceReport.Packets != 1 {
			b.Fatalf("service = %+v, %v, %v", benchmarkServiceReport, benchmarkProgress, benchmarkErr)
		}
	}
}

func BenchmarkNamespaceTryServiceEgress(b *testing.B) {
	ns := newTestNamespace(b, 84)
	if err := ns.Install(Participant{
		HasEgress: func() bool { return true },
		Egress: func(dst []byte) (int, bool, error) {
			dst[0] = 1
			return 64, true, nil
		},
	}); err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, ns.Link().MaxFrameBytes())
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 1}
	b.SetBytes(64)
	b.ReportAllocs()
	for b.Loop() {
		ns.Lock()
		ns.SetNextIngressLocked(false)
		ns.Unlock()
		benchmarkServiceReport, benchmarkProgress, benchmarkErr = ns.TryService(budget)
		if benchmarkErr != nil || benchmarkServiceReport.Packets != 1 {
			b.Fatalf("service = %+v, %v, %v", benchmarkServiceReport, benchmarkProgress, benchmarkErr)
		}
		result, err := ns.Link().TryDequeue(packetlink.Egress, dst)
		if err != nil || !result.Ready {
			b.Fatalf("dequeue = %+v, %v", result, err)
		}
	}
}
