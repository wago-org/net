package core

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/soypat/lneto/ethernet"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
)

func TestConfigurationRequiresUnicastHardwareIdentity(t *testing.T) {
	base := testConfig(1)
	if err := ValidateConfig(base); err != nil {
		t.Fatalf("valid hardware identity: %v", err)
	}
	for name, hardware := range map[string][6]byte{
		"zero":      {},
		"broadcast": ethernet.BroadcastAddr(),
		"multicast": {0x01, 0, 0, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := base
			invalid.HardwareAddress = hardware
			if err := ValidateConfig(invalid); err == nil {
				t.Fatalf("accepted invalid hardware identity %v", hardware)
			}
		})
	}
}

func TestConfigurationRejectsNonHostIPv4Identity(t *testing.T) {
	base := testConfig(2)
	unspecified := base
	unspecified.IPv4Address = netip.IPv4Unspecified()
	if err := ValidateConfig(unspecified); err != nil {
		t.Fatalf("dynamic unspecified IPv4 identity rejected: %v", err)
	}
	for name, address := range map[string]netip.Addr{
		"loopback":          netip.MustParseAddr("127.0.0.1"),
		"multicast":         netip.MustParseAddr("224.0.0.1"),
		"limited broadcast": netip.AddrFrom4([4]byte{255, 255, 255, 255}),
	} {
		t.Run(name, func(t *testing.T) {
			invalid := base
			invalid.IPv4Address = address
			if err := ValidateConfig(invalid); err == nil {
				t.Fatalf("accepted non-host IPv4 identity %v", address)
			}
		})
	}
}

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

func TestEgressRoundRobinBoundsParticipantsAndSharedStack(t *testing.T) {
	ns := newTestNamespace(t, 34)
	active := [...]bool{true, true, true, true}
	for i := range active {
		index := i
		if err := ns.Install(Participant{
			EgressOrder: index,
			HasEgress:   func() bool { return active[index] },
			Egress: func(dst []byte) (int, bool, error) {
				dst[0] = byte(index + 1)
				return 60, false, nil
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	ns.Lock()
	if err := ns.StackLocked().StartResolveHardwareAddress6(netip.MustParseAddr("192.0.2.200")); err != nil {
		ns.Unlock()
		t.Fatal(err)
	}
	ns.SetNextIngressLocked(false)
	ns.Unlock()

	var schedule []byte
	buffer := make([]byte, ns.Link().MaxFrameBytes())
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(len(buffer)), Operations: 1}
	for range 6 {
		ns.Lock()
		ns.SetNextIngressLocked(false)
		ns.Unlock()
		report, progress, err := ns.TryService(budget)
		if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
			t.Fatalf("service = %+v, %v, %v", report, progress, err)
		}
		result, err := ns.Link().TryDequeue(packetlink.Egress, buffer)
		if err != nil || !result.Ready {
			t.Fatalf("dequeue = %+v, %v", result, err)
		}
		if result.FrameBytes >= 14 && binary.BigEndian.Uint16(buffer[12:14]) == uint16(ethernet.TypeARP) {
			schedule = append(schedule, 0)
		} else {
			schedule = append(schedule, buffer[0])
		}
	}
	if want := []byte{1, 2, 3, 4, 0, 1}; !reflect.DeepEqual(schedule, want) {
		t.Fatalf("egress schedule = %v, want %v", schedule, want)
	}

	active[1] = false
	active[2] = false
	for range 2 {
		ns.Lock()
		ns.SetNextIngressLocked(false)
		ns.Unlock()
		if report, progress, err := ns.TryService(budget); err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
			t.Fatalf("dynamic service = %+v, %v, %v", report, progress, err)
		}
		result, err := ns.Link().TryDequeue(packetlink.Egress, buffer)
		if err != nil || !result.Ready {
			t.Fatalf("dynamic dequeue = %+v, %v", result, err)
		}
		schedule = append(schedule, buffer[0])
	}
	if got := schedule[len(schedule)-2:]; !reflect.DeepEqual(got, []byte{4, 1}) {
		t.Fatalf("dynamic egress schedule = %v", got)
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

func TestEgressErrorsPreserveSourceCursorForRetry(t *testing.T) {
	for _, test := range []struct {
		name  string
		first func(dst []byte, call int) (int, bool, error)
	}{
		{name: "backend error", first: func([]byte, int) (int, bool, error) {
			return 0, false, errors.New("egress failed")
		}},
		{name: "invalid length", first: func(dst []byte, call int) (int, bool, error) {
			if call == 1 {
				dst[0] = 0xff
				return len(dst) + 1, false, nil
			}
			dst[0] = 1
			return 1, true, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ns := newTestNamespace(t, byte(40+len(test.name)))
			firstCalls, secondCalls := 0, 0
			if err := ns.Install(Participant{
				EgressOrder: 10, HasEgress: func() bool { return true },
				Egress: func(dst []byte) (int, bool, error) {
					firstCalls++
					if test.name == "backend error" && firstCalls > 1 {
						dst[0] = 1
						return 1, true, nil
					}
					return test.first(dst, firstCalls)
				},
			}); err != nil {
				t.Fatal(err)
			}
			if err := ns.Install(Participant{
				EgressOrder: 20, HasEgress: func() bool { return true },
				Egress: func(dst []byte) (int, bool, error) {
					secondCalls++
					dst[0] = 2
					return 1, true, nil
				},
			}); err != nil {
				t.Fatal(err)
			}
			ns.Lock()
			ns.SetNextIngressLocked(false)
			ns.Unlock()
			budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(ns.Link().MaxFrameBytes()), Operations: 1}
			if report, progress, err := ns.TryService(budget); failureOf(err) != nscore.FailureIO || report != (nscore.ServiceReport{}) || progress != nscore.ProgressWouldBlock {
				t.Fatalf("failed egress = %+v, %v, %v", report, progress, err)
			}
			ns.Lock()
			ns.SetNextIngressLocked(false)
			ns.Unlock()
			if report, progress, err := ns.TryService(budget); err != nil || report != (nscore.ServiceReport{Packets: 1, Bytes: 1, Operations: 1}) || progress != nscore.ProgressDone {
				t.Fatalf("retry egress = %+v, %v, %v", report, progress, err)
			}
			var frame [1]byte
			if result, err := ns.Link().TryDequeue(packetlink.Egress, frame[:]); err != nil || !result.Ready || frame[0] != 1 {
				t.Fatalf("retry frame = %+v, %v, data=%v", result, err, frame)
			}
			if firstCalls != 2 || secondCalls != 0 {
				t.Fatalf("source calls after retry = %d/%d", firstCalls, secondCalls)
			}
		})
	}
}

func TestQueueFullEgressPreservesExactSourceCursorForRetry(t *testing.T) {
	ns := newTestNamespace(t, 45)
	calls := [2]int{}
	for i := range calls {
		index := i
		if err := ns.Install(Participant{
			EgressOrder: index,
			HasEgress:   func() bool { return true },
			Egress: func(dst []byte) (int, bool, error) {
				calls[index]++
				dst[0] = byte(index + 1)
				return 1, true, nil
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	link := ns.Link()
	for i := 0; i < testConfig(45).Link.EgressFrames; i++ {
		if err := link.TryEnqueue(packetlink.Egress, []byte{0xa5}); err != nil {
			t.Fatal(err)
		}
	}
	ns.Lock()
	ns.nextEgress = 1
	ns.SetNextIngressLocked(false)
	ns.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(link.MaxFrameBytes()), Operations: 1}
	if report, progress, err := ns.TryService(budget); err != nil || progress != nscore.ProgressWouldBlock || report != (nscore.ServiceReport{}) {
		t.Fatalf("queue-full service = %+v, %v, %v", report, progress, err)
	}
	if calls != [2]int{} {
		t.Fatalf("queue-full service probed producers: %v", calls)
	}
	ns.Lock()
	nextEgress := ns.nextEgress
	ns.Unlock()
	if nextEgress != 1 {
		t.Fatalf("queue-full source cursor = %d, want 1", nextEgress)
	}

	var frame [1]byte
	for i := 0; i < testConfig(45).Link.EgressFrames; i++ {
		if result, err := link.TryDequeue(packetlink.Egress, frame[:]); err != nil || !result.Ready || frame[0] != 0xa5 {
			t.Fatalf("drain %d = %+v, %v, data=%v", i, result, err, frame)
		}
	}
	ns.Lock()
	ns.SetNextIngressLocked(false)
	ns.Unlock()
	if report, progress, err := ns.TryService(budget); err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: 1, Operations: 1}) {
		t.Fatalf("retry service = %+v, %v, %v", report, progress, err)
	}
	if calls != [2]int{0, 1} {
		t.Fatalf("retry producer calls = %v", calls)
	}
	if result, err := link.TryDequeue(packetlink.Egress, frame[:]); err != nil || !result.Ready || result.FrameBytes != 1 || frame[0] != 2 {
		t.Fatalf("retry frame = %+v, %v, data=%v", result, err, frame)
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

func TestMaximumByteBudgetServicesIngressPortably(t *testing.T) {
	ns := newTestNamespace(t, 30)
	calls := 0
	if err := ns.Install(Participant{Ingress: func(frame []byte) (bool, error) {
		calls++
		return len(frame) == 1 && frame[0] == 0x30, nil
	}}); err != nil {
		t.Fatal(err)
	}
	if err := ns.Link().TryEnqueue(packetlink.Ingress, []byte{0x30}); err != nil {
		t.Fatal(err)
	}
	ns.Lock()
	ns.SetNextIngressLocked(true)
	ns.Unlock()

	budget := nscore.ServiceBudget{Packets: 1, Bytes: ^uint32(0), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: 1, Operations: 1}) || calls != 1 {
		t.Fatalf("maximum byte budget service = %+v, %v, %v, calls=%d", report, progress, err, calls)
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

func TestZeroLengthIngressFrameCountsAsPacketAndReleasesReadiness(t *testing.T) {
	ns := newTestNamespace(t, 35)
	calls := 0
	if err := ns.Install(Participant{Ingress: func(frame []byte) (bool, error) {
		calls++
		if len(frame) != 0 {
			t.Fatalf("ingress frame length = %d, want 0", len(frame))
		}
		return true, nil
	}}); err != nil {
		t.Fatal(err)
	}
	if err := ns.Link().TryEnqueue(packetlink.Ingress, nil); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < testConfig(35).Link.IngressFrames; i++ {
		if err := ns.Link().TryEnqueue(packetlink.Ingress, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if ready := ns.Readiness(); ready != 0 {
		t.Fatalf("full ingress readiness = %v", ready)
	}
	ns.Lock()
	ns.SetNextIngressLocked(true)
	ns.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: 1, Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Operations: 1}) || !report.ValidResult(budget, progress) {
		t.Fatalf("zero-frame service = %+v, %v, %v", report, progress, err)
	}
	if calls != 1 {
		t.Fatalf("ingress calls = %d, want 1", calls)
	}
	if ready := ns.Readiness(); ready != nscore.ReadyWritable {
		t.Fatalf("released ingress readiness = %v", ready)
	}
	if snapshot := ns.Link().Snapshot(); snapshot.IngressFrames != 3 || snapshot.IngressBytes != 3 {
		t.Fatalf("remaining ingress = %+v", snapshot)
	}
	var next [1]byte
	result, err := ns.Link().TryDequeue(packetlink.Ingress, next[:])
	if err != nil || !result.Ready || result.FrameBytes != 1 || next[0] != 1 {
		t.Fatalf("next ingress = %+v, %v, data=%v", result, err, next)
	}
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

func TestPacketServiceReadinessAndDirectLinkCloseRace(t *testing.T) {
	ns := newTestNamespace(t, 31)
	link := ns.Link()
	var participantCloses atomic.Uint32
	if err := ns.Install(Participant{
		Ingress:   func([]byte) (bool, error) { return true, nil },
		HasEgress: func() bool { return true },
		Egress: func(dst []byte) (int, bool, error) {
			clear(dst[:60])
			return 60, true, nil
		},
		Close: func() { participantCloses.Add(1) },
	}); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	unexpected := make(chan error, 1)
	record := func(err error) {
		select {
		case unexpected <- err:
		default:
		}
	}
	var workers sync.WaitGroup
	workers.Add(4)
	go func() {
		defer workers.Done()
		<-start
		for range 1000 {
			if ready := ns.Readiness(); !ready.Valid() {
				record(errors.New("invalid readiness snapshot"))
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(link.MaxFrameBytes()), Operations: 2}
		for range 1000 {
			report, progress, err := ns.TryService(budget)
			if err == nil {
				if !report.ValidResult(budget, progress) {
					record(errors.New("invalid service result"))
					return
				}
				continue
			}
			if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureClosed {
				record(err)
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		frame := make([]byte, link.MaxFrameBytes())
		for range 1000 {
			if err := link.TryEnqueue(packetlink.Ingress, frame[:60]); err != nil && !errors.Is(err, packetlink.ErrQueueFull) && !errors.Is(err, packetlink.ErrClosed) {
				record(err)
				return
			}
			if _, err := link.TryDequeue(packetlink.Egress, frame); err != nil && !errors.Is(err, packetlink.ErrClosed) {
				record(err)
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		if err := link.Close(); err != nil {
			record(err)
			return
		}
		if err := ns.Close(); err != nil {
			record(err)
		}
	}()
	close(start)
	workers.Wait()
	select {
	case err := <-unexpected:
		t.Fatal(err)
	default:
	}
	if got := participantCloses.Load(); got != 1 {
		t.Fatalf("participant closes = %d, want 1", got)
	}
	if ready := ns.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("terminal readiness = %v", ready)
	}
	if snapshot := link.Snapshot(); !snapshot.Closed || snapshot.IngressFrames != 0 || snapshot.IngressBytes != 0 || snapshot.EgressFrames != 0 || snapshot.EgressBytes != 0 {
		t.Fatalf("terminal link snapshot = %+v", snapshot)
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

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
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
