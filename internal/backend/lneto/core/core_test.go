package core

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/soypat/lneto/ethernet"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
)

func TestIPv6ConfigurationRequiresUsableStaticIdentityAndMTU(t *testing.T) {
	base := Config{
		Hostname: "core6", RandSeed: 6, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 6},
		IPv4Address: netip.MustParseAddr("192.0.2.6"), IPv6Address: netip.MustParseAddr("2001:db8::6"), IPv6PrefixBits: 64,
		MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1},
	}
	if err := ValidateConfig(base); err != nil {
		t.Fatalf("valid IPv6 core config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"small mtu":          func(c *Config) { c.MTU = 1279; c.Link.MaxFrameBytes = 1293 },
		"mapped":             func(c *Config) { c.IPv6Address = netip.MustParseAddr("::ffff:192.0.2.6") },
		"global scope":       func(c *Config) { c.IPv6ScopeID = 1 },
		"link scope missing": func(c *Config) { c.IPv6Address = netip.MustParseAddr("fe80::6") },
		"partial":            func(c *Config) { c.IPv6Address = netip.Addr{} },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := base
			mutate(&invalid)
			if err := ValidateConfig(invalid); err == nil {
				t.Fatalf("accepted invalid IPv6 core config: %+v", invalid)
			}
		})
	}
}

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

func TestMalformedEgressResultFailsClosedAsIO(t *testing.T) {
	for name, written := range map[string]int{
		"negative": -1,
		"oversize": int(ethernet.MaxMTU) + 15,
	} {
		t.Run(name, func(t *testing.T) {
			ns := newTestNamespace(t, byte(20+len(name)))
			calls := 0
			if err := ns.Install(Participant{
				EgressOrder: 10,
				HasEgress:   func() bool { return true },
				Egress: func(dst []byte) (int, bool, error) {
					calls++
					dst[0] = 0xff
					return written, false, nil
				},
			}); err != nil {
				t.Fatal(err)
			}
			ns.Lock()
			ns.SetNextIngressLocked(false)
			ns.Unlock()
			budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 1}
			report, progress, err := ns.TryService(budget)
			failure, ok := nscore.FailureOf(err)
			if !ok || failure != nscore.FailureIO || report != (nscore.ServiceReport{}) || progress != nscore.ProgressWouldBlock || calls != 1 {
				t.Fatalf("malformed egress = %+v, %v, %v, calls=%d", report, progress, err, calls)
			}
			if snapshot := ns.Link().Snapshot(); snapshot.EgressFrames != 0 || snapshot.EgressBytes != 0 {
				t.Fatalf("malformed egress committed output: %+v", snapshot)
			}
			if ready := ns.Readiness(); ready != nscore.ReadyWritable {
				t.Fatalf("readiness after rollback = %v", ready)
			}
		})
	}
}

func TestPacketServiceBudgetEdgesPreserveQueuedWorkAndAlternate(t *testing.T) {
	t.Run("queue full egress falls through to ingress", func(t *testing.T) {
		ns := newTestNamespace(t, 31)
		producerCalls := 0
		ingressCalls := 0
		if err := ns.Install(Participant{
			Ingress: func(frame []byte) (bool, error) {
				ingressCalls++
				return len(frame) == 1 && frame[0] == 0x31, nil
			},
			HasEgress: func() bool { return true },
			Egress: func([]byte) (int, bool, error) {
				producerCalls++
				return 0, true, nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < testConfig(31).Link.EgressFrames; i++ {
			if err := ns.Link().TryEnqueue(packetlink.Egress, []byte{byte(i)}); err != nil {
				t.Fatal(err)
			}
		}
		if err := ns.Link().TryEnqueue(packetlink.Ingress, []byte{0x31}); err != nil {
			t.Fatal(err)
		}
		ns.Lock()
		ns.SetNextIngressLocked(false)
		ns.Unlock()
		budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 2}
		report, progress, err := ns.TryService(budget)
		if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: 1, Operations: 1}) {
			t.Fatalf("service = %+v, %v, %v", report, progress, err)
		}
		if producerCalls != 0 || ingressCalls != 1 {
			t.Fatalf("callback calls = producer %d, ingress %d", producerCalls, ingressCalls)
		}
		if snapshot := ns.Link().Snapshot(); snapshot.EgressFrames != snapshot.EgressCapacity || snapshot.IngressFrames != 0 {
			t.Fatalf("queue snapshot = %+v", snapshot)
		}
	})

	t.Run("remaining byte budget leaves next ingress frame queued", func(t *testing.T) {
		ns := newTestNamespace(t, 32)
		ingressCalls := 0
		if err := ns.Install(Participant{Ingress: func([]byte) (bool, error) {
			ingressCalls++
			return true, nil
		}}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := ns.Link().TryEnqueue(packetlink.Ingress, make([]byte, 40)); err != nil {
				t.Fatal(err)
			}
		}
		ns.Lock()
		ns.SetNextIngressLocked(true)
		ns.Unlock()
		budget := nscore.ServiceBudget{Packets: 2, Bytes: 79, Operations: 3}
		report, progress, err := ns.TryService(budget)
		if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: 40, Operations: 1}) {
			t.Fatalf("service = %+v, %v, %v", report, progress, err)
		}
		if ingressCalls != 1 {
			t.Fatalf("ingress calls = %d, want 1", ingressCalls)
		}
		if snapshot := ns.Link().Snapshot(); snapshot.IngressFrames != 1 || snapshot.IngressBytes != 40 || snapshot.EgressFrames != 0 {
			t.Fatalf("queue snapshot = %+v", snapshot)
		}
	})

	t.Run("maintenance is charged without packet bytes", func(t *testing.T) {
		ns := newTestNamespace(t, 33)
		maintenance := 0
		if err := ns.Install(Participant{
			HasEgress: func() bool { return true },
			Egress: func([]byte) (int, bool, error) {
				maintenance++
				ns.MarkMaintenanceLocked()
				return 0, true, nil
			},
		}); err != nil {
			t.Fatal(err)
		}
		ns.Lock()
		ns.SetNextIngressLocked(false)
		required := ns.RequiredFrameBytesLocked()
		ns.Unlock()
		budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 3}
		report, progress, err := ns.TryService(budget)
		if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Operations: 2}) {
			t.Fatalf("service = %+v, %v, %v", report, progress, err)
		}
		if maintenance != 2 {
			t.Fatalf("maintenance calls = %d, want 2", maintenance)
		}
		if snapshot := ns.Link().Snapshot(); snapshot.EgressFrames != 0 || snapshot.EgressBytes != 0 {
			t.Fatalf("maintenance committed output: %+v", snapshot)
		}
	})
}

func TestPacketServiceReadinessTracksCommittedQueues(t *testing.T) {
	ns := newTestNamespace(t, 30)
	if ready := ns.Readiness(); ready != nscore.ReadyWritable {
		t.Fatalf("initial readiness = %v", ready)
	}
	for i := 0; i < 4; i++ {
		if err := ns.Link().TryEnqueue(packetlink.Ingress, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if ready := ns.Readiness(); ready != 0 {
		t.Fatalf("full ingress readiness = %v", ready)
	}
	if err := ns.Install(Participant{
		IngressOrder: 10,
		Ingress: func([]byte) (bool, error) {
			return true, nil
		},
		EgressOrder: 10,
		HasEgress:   func() bool { return true },
		Egress: func(dst []byte) (int, bool, error) {
			clear(dst[:60])
			return 60, false, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	ns.Lock()
	ns.SetNextIngressLocked(false)
	ns.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 1}
	if report, progress, err := ns.TryService(budget); err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: 60, Operations: 1}) {
		t.Fatalf("egress service = %+v, %v, %v", report, progress, err)
	}
	if ready := ns.Readiness(); ready != nscore.ReadyReadable {
		t.Fatalf("queued egress readiness = %v", ready)
	}
	if _, err := ns.Link().TryDequeue(packetlink.Egress, make([]byte, 60)); err != nil {
		t.Fatal(err)
	}
	if ready := ns.Readiness(); ready != 0 {
		t.Fatalf("drained egress readiness = %v", ready)
	}
	ns.Lock()
	ns.SetNextIngressLocked(true)
	ns.Unlock()
	if report, progress, err := ns.TryService(budget); err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("ingress service = %+v, %v, %v", report, progress, err)
	}
	if ready := ns.Readiness(); ready != nscore.ReadyWritable {
		t.Fatalf("released ingress readiness = %v", ready)
	}
	if err := ns.Link().Close(); err != nil {
		t.Fatal(err)
	}
	if ready := ns.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("closed link readiness = %v", ready)
	}
	if report, progress, err := ns.TryService(budget); report != (nscore.ServiceReport{}) || progress != nscore.ProgressWouldBlock || !errors.Is(err, packetlink.ErrClosed) {
		t.Fatalf("closed link service = %+v, %v, %v", report, progress, err)
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
