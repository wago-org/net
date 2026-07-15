package core

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
)

func TestV1LayoutConstants(t *testing.T) {
	if AddressV1Size != 32 || HandleV1Size != 8 || PollBudgetV1Size != 24 || PollEventV1Size != 16 || PollResultV1Size != 24 {
		t.Fatalf("layout sizes = address %d handle %d budget %d event %d result %d", AddressV1Size, HandleV1Size, PollBudgetV1Size, PollEventV1Size, PollResultV1Size)
	}
}

func TestCheckRangesAndElements(t *testing.T) {
	memory := make([]byte, 32)
	if !CheckRanges(memory, true, Range{Ptr: 0, Length: 8}, Range{Ptr: 8, Length: 8}, Range{Ptr: 32, Length: 0}) {
		t.Fatal("valid disjoint ranges rejected")
	}
	if CheckRanges(memory, true, Range{Ptr: 4, Length: 8}, Range{Ptr: 8, Length: 8}) {
		t.Fatal("overlap accepted")
	}
	if CheckRanges(memory, false, Range{Ptr: 31, Length: 2}) {
		t.Fatal("out-of-bounds range accepted")
	}
	if got, ok := Elements(memory, 0, 4, 8); !ok || len(got) != 32 {
		t.Fatalf("Elements = %d, %v", len(got), ok)
	}
	if _, ok := Elements(memory, 0, ^uint32(0), 16); ok {
		t.Fatal("overflowing Elements accepted")
	}
}

func TestEndpointV1RoundTrip(t *testing.T) {
	for _, endpoint := range []namespace.Endpoint{
		{Address: netip.MustParseAddr("192.0.2.1"), Port: 4100},
		{Address: netip.MustParseAddr("fe80::1"), Port: 53, ScopeID: 7, FlowInfo: 9},
	} {
		memory := make([]byte, AddressV1Size)
		if !EncodeEndpointV1(memory, 0, endpoint) {
			t.Fatalf("EncodeEndpointV1(%+v)", endpoint)
		}
		got, ok := DecodeEndpointV1(memory, 0)
		if !ok || got != endpoint {
			t.Fatalf("DecodeEndpointV1 = %+v, %v; want %+v", got, ok, endpoint)
		}
	}
}

func TestPollV1Codecs(t *testing.T) {
	memory := make([]byte, 128)
	binary.LittleEndian.PutUint32(memory[0:4], 4)
	binary.LittleEndian.PutUint32(memory[4:8], 2)
	binary.LittleEndian.PutUint32(memory[8:12], 1)
	binary.LittleEndian.PutUint32(memory[12:16], 3)
	binary.LittleEndian.PutUint32(memory[16:20], 1514)
	binary.LittleEndian.PutUint32(memory[20:24], 5)
	budget, ok := DecodePollBudgetV1(memory, 0)
	if !ok || budget != (readiness.Budget{Scans: 4, Events: 2, ServiceAttempts: 1, Service: namespace.ServiceBudget{Packets: 3, Bytes: 1514, Operations: 5}}) {
		t.Fatalf("DecodePollBudgetV1 = %+v, %v", budget, ok)
	}

	events := []readiness.Event{
		{Handle: resource.Handle(0x0102030405060708), Readiness: namespace.ReadyReadable},
		{Handle: resource.Handle(0x1112131415161718), Readiness: namespace.ReadyWritable | namespace.ReadyClosed},
	}
	if !EncodePollEventsV1(memory, 32, events) {
		t.Fatal("EncodePollEventsV1 failed")
	}
	if got := binary.LittleEndian.Uint64(memory[32:40]); got != uint64(events[0].Handle) {
		t.Fatalf("first event handle = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(memory[40:44]); got != uint32(events[0].Readiness) {
		t.Fatalf("first readiness = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(memory[44:48]); got != 0 {
		t.Fatalf("first reserved = %#x", got)
	}

	report := readiness.Report{Scanned: 4, Events: 2, ServiceAttempts: 1, ServiceCompleted: 1, StaleRegistrations: 1}
	if !EncodePollResultV1(memory, 80, report, budget) {
		t.Fatal("EncodePollResultV1 failed")
	}
	want := []uint32{2, 4, 1, 1, 1, 0}
	for i, value := range want {
		if got := binary.LittleEndian.Uint32(memory[80+i*4:]); got != value {
			t.Fatalf("poll result[%d] = %d, want %d", i, got, value)
		}
	}
}

func TestPollV1RejectedEncodingDoesNotMutate(t *testing.T) {
	memory := bytes.Repeat([]byte{0x5a}, 64)
	before := append([]byte(nil), memory...)
	if EncodePollEventsV1(memory, 0, []readiness.Event{{Handle: 0, Readiness: namespace.ReadyReadable}}) {
		t.Fatal("invalid event encoded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("invalid event partially mutated memory")
	}
	budget := readiness.Budget{Scans: 2, Events: 2, ServiceAttempts: 1, Service: namespace.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1}}
	for _, report := range []readiness.Report{
		{Scanned: 2, Events: 3},
		{Scanned: 1, Events: 2},
		{Scanned: 1, Events: 1, StaleRegistrations: 1},
		{Scanned: 1, ServiceAttempts: 1, StaleRegistrations: 1},
	} {
		if EncodePollResultV1(memory, 32, report, budget) {
			t.Fatalf("invalid report encoded: %+v", report)
		}
		if !bytes.Equal(memory, before) {
			t.Fatalf("invalid report partially mutated memory: %+v", report)
		}
	}
}

func FuzzPollEventV1EncodingAtomic(f *testing.F) {
	f.Add(uint32(8), uint64(0xf102030405060708), uint32(namespace.ReadyReadable|namespace.ReadyClosed))
	f.Add(^uint32(0), uint64(1), uint32(namespace.ReadyWritable))
	f.Add(uint32(0), uint64(0), uint32(namespace.ReadyReadable))
	f.Add(uint32(16), uint64(1), uint32(1<<31))
	f.Fuzz(func(t *testing.T, ptr uint32, handle uint64, ready uint32) {
		memory := bytes.Repeat([]byte{0xa5}, 64)
		before := append([]byte(nil), memory...)
		event := readiness.Event{Handle: resource.Handle(handle), Readiness: namespace.Readiness(ready)}
		encoded := EncodePollEventsV1(memory, ptr, []readiness.Event{event})
		want := event.Valid() && uint64(ptr)+uint64(PollEventV1Size) <= uint64(len(memory))
		if encoded != want {
			t.Fatalf("EncodePollEventsV1 ptr=%d event=%+v = %v, want %v", ptr, event, encoded, want)
		}
		if !encoded {
			if !bytes.Equal(memory, before) {
				t.Fatal("failed event encode mutated memory")
			}
			return
		}
		output := memory[ptr : ptr+PollEventV1Size]
		if binary.LittleEndian.Uint64(output[0:8]) != handle || binary.LittleEndian.Uint32(output[8:12]) != ready || binary.LittleEndian.Uint32(output[12:16]) != 0 {
			t.Fatalf("encoded event = %x", output)
		}
		if !bytes.Equal(memory[:ptr], before[:ptr]) || !bytes.Equal(memory[ptr+PollEventV1Size:], before[ptr+PollEventV1Size:]) {
			t.Fatal("event encode mutated bytes outside output")
		}
	})
}

func FuzzPollResultV1EncodingAtomic(f *testing.F) {
	f.Add(uint32(8), uint32(2), uint32(4), uint32(1), uint32(1), uint32(1))
	f.Add(^uint32(0), uint32(0), uint32(0), uint32(0), uint32(0), uint32(0))
	f.Add(uint32(0), uint32(2), uint32(1), uint32(0), uint32(0), uint32(0))
	f.Fuzz(func(t *testing.T, ptr, events, scanned, attempts, completed, stale uint32) {
		budget := readiness.Budget{
			Scans: 4, Events: 2, ServiceAttempts: 2,
			Service: namespace.ServiceBudget{Packets: 2, Bytes: 64, Operations: 2},
		}
		report := readiness.Report{Events: events, Scanned: scanned, ServiceAttempts: attempts, ServiceCompleted: completed, StaleRegistrations: stale}
		memory := bytes.Repeat([]byte{0x5a}, 64)
		before := append([]byte(nil), memory...)
		encoded := EncodePollResultV1(memory, ptr, report, budget)
		want := report.ValidFor(budget) && uint64(ptr)+uint64(PollResultV1Size) <= uint64(len(memory))
		if encoded != want {
			t.Fatalf("EncodePollResultV1 ptr=%d report=%+v = %v, want %v", ptr, report, encoded, want)
		}
		if !encoded {
			if !bytes.Equal(memory, before) {
				t.Fatal("failed result encode mutated memory")
			}
			return
		}
		output := memory[ptr : ptr+PollResultV1Size]
		got := [6]uint32{
			binary.LittleEndian.Uint32(output[0:4]),
			binary.LittleEndian.Uint32(output[4:8]),
			binary.LittleEndian.Uint32(output[8:12]),
			binary.LittleEndian.Uint32(output[12:16]),
			binary.LittleEndian.Uint32(output[16:20]),
			binary.LittleEndian.Uint32(output[20:24]),
		}
		if want := [6]uint32{events, scanned, attempts, completed, stale, 0}; got != want {
			t.Fatalf("encoded result = %v, want %v", got, want)
		}
		if !bytes.Equal(memory[:ptr], before[:ptr]) || !bytes.Equal(memory[ptr+PollResultV1Size:], before[ptr+PollResultV1Size:]) {
			t.Fatal("result encode mutated bytes outside output")
		}
	})
}

func FuzzV1Layouts(f *testing.F) {
	f.Add(make([]byte, 64), uint32(0), uint32(0), uint32(0))
	f.Add([]byte{1, 2, 3}, ^uint32(0), ^uint32(0), uint32(16))
	f.Fuzz(func(t *testing.T, memory []byte, ptr, count, size uint32) {
		_, elementsOK := Elements(memory, ptr, count, size)
		length := uint64(count) * uint64(size)
		want := length <= uint64(^uint32(0)) && uint64(ptr)+length <= uint64(len(memory))
		if elementsOK != want {
			t.Fatalf("Elements len=%d ptr=%d count=%d size=%d = %v, want %v", len(memory), ptr, count, size, elementsOK, want)
		}
		_, _ = DecodeEndpointV1(memory, ptr)
		_, _ = DecodePollBudgetV1(memory, ptr)
	})
}
