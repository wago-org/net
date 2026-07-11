package net

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

func TestGuestUDPPollBoundsLevelsServiceAndQuotaRelease(t *testing.T) {
	extension, _, instance, host := newGuestUDPInstance(t, 31, 32)
	defer instance.Close()
	state, _ := extension.instanceManager().ForInstance(instance)
	namespaceHandle := guestNamespaceFromExtension(t, extension, host)
	socket := guestBind(t, extension, host, namespaceHandle, endpointFor(31, 4431), 48)

	writePollBudget(host.memory, 0, 2, 2, 0, 0, 0, 0)
	if got := callUDP(t, extension, "poll", host, 64, 2, 0, 128); got != StatusOK {
		t.Fatalf("initial poll = %v", got)
	}
	report := decodePollResult(host.memory, 128)
	if report != [6]uint32{2, 2, 0, 0, 0, 0} {
		t.Fatalf("initial poll report = %v", report)
	}
	events := decodePollEvents(host.memory, 64, report[0])
	if len(events) != 2 || !hasPollEvent(events, namespaceHandle, namespace.ReadyWritable) || !hasPollEvent(events, socket, namespace.ReadyWritable) {
		t.Fatalf("initial poll events = %+v", events)
	}

	copy(host.memory[256:], []byte("one"))
	encodeGuestEndpoint(t, host.memory, 32, endpointFor(32, 4432))
	if got := callUDP(t, extension, "send", host, uint64(socket), 256, 3, 32); got != StatusOK {
		t.Fatalf("first queued send = %v", got)
	}
	if got := callUDP(t, extension, "send", host, uint64(socket), 256, 3, 32); got != StatusOK {
		t.Fatalf("second queued send = %v", got)
	}
	writePollBudget(host.memory, 0, 2, 2, 0, 0, 0, 0)
	if got := callUDP(t, extension, "poll", host, 64, 2, 0, 128); got != StatusOK {
		t.Fatalf("full-socket poll = %v", got)
	}
	report = decodePollResult(host.memory, 128)
	events = decodePollEvents(host.memory, 64, report[0])
	if report[0] != 1 || !hasPollEvent(events, namespaceHandle, namespace.ReadyWritable) || hasPollHandle(events, socket) {
		t.Fatalf("full-socket report/events = %v %+v", report, events)
	}

	writePollBudget(host.memory, 0, 2, 2, 2, 1, 1514, 2)
	if got := callUDP(t, extension, "poll", host, 64, 2, 0, 128); got != StatusOK {
		t.Fatalf("servicing poll = %v", got)
	}
	report = decodePollResult(host.memory, 128)
	events = decodePollEvents(host.memory, 64, report[0])
	if report[1] > 2 || report[0] > 2 || report[2] != 1 || report[3] != 1 || !hasPollEvent(events, socket, namespace.ReadyWritable) {
		t.Fatalf("servicing poll report/events = %v %+v", report, events)
	}
	if snapshot := concreteNamespace(t, state).Link().Snapshot(); snapshot.EgressFrames != 1 {
		t.Fatalf("bounded service egress = %+v", snapshot)
	}
	if usage, closed := state.Quotas().Snapshot(); closed || usage.ServiceUnits != 0 {
		t.Fatalf("poll service quota leaked = %+v, closed=%v", usage, closed)
	}

	writePollBudget(host.memory, 0, 31, 1, 1, 1, 1514, 2)
	before := append([]byte(nil), host.memory...)
	if got := callUDP(t, extension, "poll", host, 64, 1, 0, 128); got != StatusResourceLimit {
		t.Fatalf("service quota limit = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("quota-denied poll mutated outputs")
	}
}

func TestGuestUDPPollRejectsMemoryBeforeWorkAndRemovesStale(t *testing.T) {
	extension, _, instance, host := newGuestUDPInstance(t, 41, 42)
	defer instance.Close()
	state, _ := extension.instanceManager().ForInstance(instance)
	namespaceHandle := guestNamespaceFromExtension(t, extension, host)
	socket := guestBind(t, extension, host, namespaceHandle, endpointFor(41, 4541), 48)

	writePollBudget(host.memory, 0, 2, 2, 0, 0, 0, 0)
	before := append([]byte(nil), host.memory...)
	if got := callUDP(t, extension, "poll", host, 64, 1, 0, 128); got != StatusInvalidArgument {
		t.Fatalf("event capacity underflow = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("invalid event capacity mutated memory")
	}
	if got := callUDP(t, extension, "poll", host, 64, 2, 0, 72); got != StatusInvalidArgument {
		t.Fatalf("overlapping poll outputs = %v", got)
	}
	if !bytes.Equal(host.memory, before) {
		t.Fatal("overlapping outputs mutated memory")
	}

	if err := state.Resources().CloseHandle(socket, resource.KindUDPSocket); err != nil {
		t.Fatalf("create stale registration: %v", err)
	}
	if got := callUDP(t, extension, "poll", host, 64, 2, 0, 128); got != StatusOK {
		t.Fatalf("stale-removal poll = %v", got)
	}
	report := decodePollResult(host.memory, 128)
	if report[4] != 1 || report[1] > 2 {
		t.Fatalf("stale-removal report = %v", report)
	}
	if snapshot := state.Readiness().Snapshot(); snapshot.Registrations != 1 {
		t.Fatalf("stale registration retained = %+v", snapshot)
	}
	if got := callUDP(t, extension, "close", host, uint64(socket)); got != StatusBadHandle {
		t.Fatalf("stale guest close = %v", got)
	}
}

func TestGuestUDPPollConcurrentInstanceClose(t *testing.T) {
	extension, _, instance, host := newGuestUDPInstance(t, 51, 52)
	writePollBudget(host.memory, 0, 2, 2, 0, 0, 0, 0)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				memory := make([]byte, len(host.memory))
				copy(memory, host.memory)
				localHost := udpHostModule{instance: instance, memory: memory}
				status := callUDP(t, extension, "poll", localHost, 64, 2, 0, 128)
				if status != StatusAgain && status != StatusOK && status != StatusInvalidState {
					t.Errorf("concurrent poll status = %v", status)
					return
				}
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		_ = instance.Close()
	}()
	wait.Wait()
	if got := callUDP(t, extension, "poll", host, 64, 2, 0, 128); got != StatusInvalidState {
		t.Fatalf("poll after close = %v", got)
	}
}

func FuzzGuestUDPPollMemory(f *testing.F) {
	extension, _, instance, baseHost := newGuestUDPInstance(f, 61, 62)
	f.Cleanup(func() { _ = instance.Close() })
	f.Add(make([]byte, 256), uint32(0), uint32(1), uint32(32), uint32(128))
	f.Add([]byte{1, 2, 3}, ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, eventsPtr, capacity, budgetPtr, resultPtr uint32) {
		host := udpHostModule{instance: baseHost.instance, memory: append([]byte(nil), memory...)}
		status := callUDP(t, extension, "poll", host, uint64(eventsPtr), uint64(capacity), uint64(budgetPtr), uint64(resultPtr))
		if status < StatusOK || status > StatusOther {
			t.Fatalf("invalid poll status = %d", status)
		}
	})
}

func BenchmarkGuestUDPPoll(b *testing.B) {
	extension, _, instance, host := newGuestUDPInstance(b, 71, 72)
	defer instance.Close()
	writePollBudget(host.memory, 0, 2, 2, 0, 0, 0, 0)
	var poll wago.HostFunc
	for _, binding := range extension.udpBindings() {
		if binding.name == "poll" {
			poll = binding.fn
			break
		}
	}
	if poll == nil {
		b.Fatal("poll binding missing")
	}
	params := []uint64{64, 2, 0, 128}
	results := []uint64{0}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		poll(host, params, results)
		if status := Status(wago.AsI32(results[0])); status != StatusOK {
			b.Fatalf("poll status = %v", status)
		}
	}
}

func writePollBudget(memory []byte, ptr uint32, scans, events, attempts, packets, bytes, operations uint32) {
	values := [...]uint32{scans, events, attempts, packets, bytes, operations}
	for i, value := range values {
		binary.LittleEndian.PutUint32(memory[int(ptr)+i*4:], value)
	}
}

func decodePollResult(memory []byte, ptr uint32) [6]uint32 {
	var result [6]uint32
	for i := range result {
		result[i] = binary.LittleEndian.Uint32(memory[int(ptr)+i*4:])
	}
	return result
}

type decodedPollEvent struct {
	handle    resource.Handle
	readiness namespace.Readiness
}

func decodePollEvents(memory []byte, ptr, count uint32) []decodedPollEvent {
	events := make([]decodedPollEvent, count)
	for i := range events {
		offset := int(ptr) + i*int(PollEventV1Size)
		events[i] = decodedPollEvent{
			handle:    resource.Handle(binary.LittleEndian.Uint64(memory[offset : offset+8])),
			readiness: namespace.Readiness(binary.LittleEndian.Uint32(memory[offset+8 : offset+12])),
		}
	}
	return events
}

func hasPollEvent(events []decodedPollEvent, handle resource.Handle, readiness namespace.Readiness) bool {
	for _, event := range events {
		if event.handle == handle && event.readiness&readiness == readiness {
			return true
		}
	}
	return false
}

func hasPollHandle(events []decodedPollEvent, handle resource.Handle) bool {
	for _, event := range events {
		if event.handle == handle {
			return true
		}
	}
	return false
}
