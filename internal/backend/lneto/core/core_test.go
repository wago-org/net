package core

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/soypat/lneto/ethernet"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
)

func TestParticipantOrderingAndDeterministicClose(t *testing.T) {
	ns := newTestNamespace(t, 1)
	var ingress []string
	var egress []string
	var closed []string
	if err := ns.Install(Participant{
		IngressOrder: 20,
		Ingress: func([]byte) (bool, error) {
			ingress = append(ingress, "udp")
			return true, nil
		},
		EgressOrder: 20,
		HasEgress:   func() bool { return true },
		Egress: func(dst []byte) (int, bool, error) {
			egress = append(egress, "udp")
			dst[0] = 2
			return 60, false, nil
		},
		CloseOrder: 30,
		Close:      func() { closed = append(closed, "udp") },
	}); err != nil {
		t.Fatal(err)
	}
	if err := ns.Install(Participant{
		IngressOrder: 10,
		Ingress: func([]byte) (bool, error) {
			ingress = append(ingress, "dns")
			return false, nil
		},
		EgressOrder: 10,
		HasEgress:   func() bool { return true },
		Egress: func(dst []byte) (int, bool, error) {
			egress = append(egress, "dns")
			dst[0] = 1
			return 60, false, nil
		},
		CloseOrder: 10,
		Close:      func() { closed = append(closed, "dns") },
	}); err != nil {
		t.Fatal(err)
	}
	if err := ns.Install(Participant{CloseOrder: 20, Close: func() { closed = append(closed, "tcp") }}); err != nil {
		t.Fatal(err)
	}

	if err := ns.Link().TryEnqueue(packetlink.Ingress, []byte{0}); err != nil {
		t.Fatal(err)
	}
	budget := nscore.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: 1, Operations: 1}) {
		t.Fatalf("ingress service = %+v, %v, %v", report, progress, err)
	}
	if want := []string{"dns", "udp"}; !reflect.DeepEqual(ingress, want) {
		t.Fatalf("ingress order = %v, want %v", ingress, want)
	}

	for i := 0; i < 3; i++ {
		ns.Lock()
		ns.SetNextIngressLocked(false)
		ns.Unlock()
		report, progress, err = ns.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 1})
		if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 || report.Bytes != 60 {
			t.Fatalf("egress service %d = %+v, %v, %v", i, report, progress, err)
		}
		buffer := make([]byte, 64)
		result, dequeueErr := ns.Link().TryDequeue(packetlink.Egress, buffer)
		if dequeueErr != nil || !result.Ready || result.FrameBytes != 60 {
			t.Fatalf("egress dequeue %d = %+v, %v", i, result, dequeueErr)
		}
	}
	if want := []string{"dns", "udp", "dns"}; !reflect.DeepEqual(egress, want) {
		t.Fatalf("egress order = %v, want %v", egress, want)
	}

	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"dns", "tcp", "udp"}; !reflect.DeepEqual(closed, want) {
		t.Fatalf("close order = %v, want %v", closed, want)
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if len(closed) != 3 {
		t.Fatalf("idempotent close repeated callbacks: %v", closed)
	}
}

func TestMaintenanceCountsAsBoundedOperationWithoutFrame(t *testing.T) {
	ns := newTestNamespace(t, 2)
	if err := ns.Install(Participant{
		EgressOrder: 10,
		HasEgress:   func() bool { return true },
		Egress: func([]byte) (int, bool, error) {
			ns.MarkMaintenanceLocked()
			return 0, true, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	ns.Lock()
	ns.SetNextIngressLocked(false)
	ns.Unlock()
	report, progress, err := ns.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Operations: 1}) {
		t.Fatalf("maintenance service = %+v, %v, %v", report, progress, err)
	}
	if snapshot := ns.Link().Snapshot(); snapshot.EgressFrames != 0 {
		t.Fatalf("maintenance emitted frame: %+v", snapshot)
	}
}

func TestShortEgressByteBudgetFailsClosedWithoutProbingOutput(t *testing.T) {
	ns := newTestNamespace(t, 3)
	called := 0
	if err := ns.Install(Participant{
		EgressOrder: 10,
		HasEgress:   func() bool { return true },
		Egress: func(dst []byte) (int, bool, error) {
			called++
			dst[0] = 1
			return 60, true, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	ns.Lock()
	ns.SetNextIngressLocked(false)
	ns.Unlock()
	short := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes() - 1), Operations: 1}
	report, progress, err := ns.TryService(short)
	if err != nil || progress != nscore.ProgressWouldBlock || report != (nscore.ServiceReport{}) {
		t.Fatalf("short budget service = %+v, %v, %v", report, progress, err)
	}
	if called != 0 {
		t.Fatalf("short budget probed egress producer %d times", called)
	}
	if snapshot := ns.Link().Snapshot(); snapshot.EgressFrames != 0 {
		t.Fatalf("short budget emitted frame: %+v", snapshot)
	}

	setNext := func(next bool) {
		ns.Lock()
		ns.SetNextIngressLocked(next)
		ns.Unlock()
	}
	setNext(false)
	exact := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 1}
	report, progress, err = ns.TryService(exact)
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: 60, Operations: 1}) {
		t.Fatalf("exact budget service = %+v, %v, %v", report, progress, err)
	}
	if called != 1 {
		t.Fatalf("exact budget probe count = %d, want 1", called)
	}
}

func TestSharedOwnerValidationAndClose(t *testing.T) {
	config := testConfig(3)
	config.Link.MaxFrameBytes--
	if _, err := New(config); err == nil {
		t.Fatal("undersized frame storage accepted")
	}
	ns := newTestNamespace(t, 4)
	link := ns.Link()
	if ns.Readiness() != nscore.ReadyWritable {
		t.Fatalf("initial readiness = %v", ns.Readiness())
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	if ns.Readiness() != nscore.ReadyClosed {
		t.Fatalf("closed readiness = %v", ns.Readiness())
	}
	if snapshot := link.Snapshot(); !snapshot.Closed || snapshot.IngressFrames != 0 || snapshot.EgressFrames != 0 {
		t.Fatalf("closed link snapshot = %+v", snapshot)
	}
}

func newTestNamespace(t testing.TB, id byte) *Namespace {
	t.Helper()
	ns, err := New(testConfig(id))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func testConfig(id byte) Config {
	mtu := uint16(ethernet.MaxMTU)
	return Config{
		Hostname:               "core",
		RandSeed:               int64(id) + 1,
		HardwareAddress:        [6]byte{0x02, 0, 0, 0, 0, id},
		GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 1, id},
		IPv4Address:            netip.AddrFrom4([4]byte{192, 0, 2, id}),
		MTU:                    mtu,
		Link: packetlink.Config{
			MaxFrameBytes: int(mtu) + 14,
			IngressFrames: 4,
			EgressFrames:  4,
		},
	}
}
