package core

import (
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
)

var (
	benchmarkServiceReport   nscore.ServiceReport
	benchmarkProgress        nscore.Progress
	benchmarkErr             error
	benchmarkReadiness       nscore.Readiness
	benchmarkLeaseStorage    UDPPortLease
	benchmarkTCPLeaseStorage TCPPortLease
	benchmarkPort            uint16
	benchmarkOK              bool
)

func BenchmarkNamespaceReadiness(b *testing.B) {
	ns := newTestNamespace(b, 81)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkReadiness = ns.Readiness()
	}
}

func BenchmarkTCPPortLeaseAcquireRelease(b *testing.B) {
	config := testConfig(78)
	config.MaxActiveTCPPorts = 16
	ns, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ns.Close() })
	ns.Lock()
	owner := ns.NewTCPPortOwnerLocked()
	ns.Unlock()
	b.ReportAllocs()
	for b.Loop() {
		ns.Lock()
		benchmarkOK = ns.AcquireTCPPortIntoLocked(&benchmarkTCPLeaseStorage, owner, 0)
		if benchmarkOK {
			benchmarkTCPLeaseStorage.ReleaseLocked()
		}
		ns.Unlock()
		if !benchmarkOK {
			b.Fatal("TCP lease")
		}
	}
}

func BenchmarkUDPPortLeaseAcquireRelease(b *testing.B) {
	ns := newTestNamespace(b, 80)
	b.ReportAllocs()
	for b.Loop() {
		ns.Lock()
		benchmarkOK = ns.TryLeaseUDPPortIntoLocked(&benchmarkLeaseStorage, 53000)
		if benchmarkOK {
			benchmarkLeaseStorage.ReleaseLocked()
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
		benchmarkPort, benchmarkOK = ns.TryLeaseUDPPortRangeIntoLocked(&benchmarkLeaseStorage, 53000, 53000, 8)
		if benchmarkOK {
			benchmarkLeaseStorage.ReleaseLocked()
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
