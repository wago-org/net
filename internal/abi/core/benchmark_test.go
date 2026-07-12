package core

import (
	"encoding/binary"
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/readiness"
	"github.com/wago-org/net/internal/resource"
)

var (
	benchmarkBytes  []byte
	benchmarkBool   bool
	benchmarkUint32 uint32
	benchmarkAddr   Address
	benchmarkEP     nscore.Endpoint
	benchmarkBudget readiness.Budget
)

func BenchmarkSlice(b *testing.B) {
	memory := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBytes, benchmarkBool = Slice(memory, 128, 1024)
	}
}

func BenchmarkWrite(b *testing.B) {
	memory := make([]byte, 4096)
	source := make([]byte, 1024)
	b.SetBytes(int64(len(source)))
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = Write(memory, 128, source)
	}
}

func BenchmarkZero(b *testing.B) {
	memory := make([]byte, 4096)
	b.SetBytes(1024)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = Zero(memory, 128, 1024)
	}
}

func BenchmarkReadUint32LE(b *testing.B) {
	memory := make([]byte, 8)
	binary.LittleEndian.PutUint32(memory[2:], 0x11223344)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkUint32, benchmarkBool = ReadUint32LE(memory, 2)
	}
}

func BenchmarkWriteUint32LE(b *testing.B) {
	memory := make([]byte, 8)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = WriteUint32LE(memory, 2, 0x11223344)
	}
}

func BenchmarkCheckRanges(b *testing.B) {
	memory := make([]byte, 4096)
	ranges := []Range{{Ptr: 0, Length: 32}, {Ptr: 64, Length: 1024}, {Ptr: 2048, Length: 16}, {Ptr: 4096, Length: 0}}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = CheckRanges(memory, true, ranges...)
	}
}

func BenchmarkElements(b *testing.B) {
	memory := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBytes, benchmarkBool = Elements(memory, 128, 64, 16)
	}
}

func BenchmarkEncodeAddressV1(b *testing.B) {
	memory := make([]byte, AddressV1Size)
	address := Address{Family: AddressFamilyIPv6, Port: 443, Address: netip.MustParseAddr("2001:db8::1").As16()}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeAddressV1(memory, 0, address)
	}
}

func BenchmarkDecodeAddressV1(b *testing.B) {
	memory := make([]byte, AddressV1Size)
	address := Address{Family: AddressFamilyIPv6, Port: 443, Address: netip.MustParseAddr("2001:db8::1").As16()}
	if !EncodeAddressV1(memory, 0, address) {
		b.Fatal("encode address")
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkAddr, benchmarkBool = DecodeAddressV1(memory, 0)
	}
}

func BenchmarkEncodeEndpointV1(b *testing.B) {
	memory := make([]byte, AddressV1Size)
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("2001:db8::1"), Port: 443}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeEndpointV1(memory, 0, endpoint)
	}
}

func BenchmarkDecodeEndpointV1(b *testing.B) {
	memory := make([]byte, AddressV1Size)
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("2001:db8::1"), Port: 443}
	if !EncodeEndpointV1(memory, 0, endpoint) {
		b.Fatal("encode endpoint")
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkEP, benchmarkBool = DecodeEndpointV1(memory, 0)
	}
}

func BenchmarkEncodeHandleV1(b *testing.B) {
	memory := make([]byte, HandleV1Size)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodeHandleV1(memory, 0, resource.Handle(0x0102030405060708))
	}
}

func BenchmarkDecodePollBudgetV1(b *testing.B) {
	memory := make([]byte, PollBudgetV1Size)
	for i, value := range []uint32{16, 8, 2, 4, 1514, 8} {
		binary.LittleEndian.PutUint32(memory[i*4:], value)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBudget, benchmarkBool = DecodePollBudgetV1(memory, 0)
	}
}

func BenchmarkEncodePollEventsV1(b *testing.B) {
	for _, count := range []int{1, 16, 256} {
		b.Run(fmtCount(count), func(b *testing.B) {
			memory := make([]byte, count*int(PollEventV1Size))
			events := make([]readiness.Event, count)
			for i := range events {
				events[i] = readiness.Event{Handle: resource.Handle(i + 1), Readiness: nscore.ReadyReadable | nscore.ReadyWritable}
			}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkBool = EncodePollEventsV1(memory, 0, events)
			}
		})
	}
}

func BenchmarkEncodePollResultV1(b *testing.B) {
	memory := make([]byte, PollResultV1Size)
	budget := readiness.Budget{Scans: 16, Events: 8, ServiceAttempts: 2, Service: nscore.ServiceBudget{Packets: 4, Bytes: 1514, Operations: 8}}
	report := readiness.Report{Scanned: 16, Events: 8, ServiceAttempts: 2, ServiceCompleted: 1, StaleRegistrations: 1}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkBool = EncodePollResultV1(memory, 0, report, budget)
	}
}

func fmtCount(count int) string {
	switch count {
	case 1:
		return "events=1"
	case 16:
		return "events=16"
	default:
		return "events=256"
	}
}
