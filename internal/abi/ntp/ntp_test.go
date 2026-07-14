package ntp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	ntpns "github.com/wago-org/net/internal/namespace/ntp"
)

func TestSampleV1RejectsMalformedFixedFields(t *testing.T) {
	memory := make([]byte, SampleV1Size)
	sample := ntpns.Sample{
		Server: netip.MustParseAddr("192.0.2.123"), CorrectedTime: time.Date(2026, 7, 13, 22, 0, 0, 123456789, time.UTC),
		Offset: -250 * time.Millisecond, RoundTripDelay: 20 * time.Millisecond,
		Stratum: 2, Leap: 0, Version: 4, ReferenceID: [4]byte{'G', 'P', 'S', 0},
	}
	if !EncodeSampleV1(memory, 0, sample) {
		t.Fatal("encode sample")
	}
	for name, mutate := range map[string]func([]byte){
		"unknown family": func(encoded []byte) { encoded[0] = 0xff },
		"address flags":  func(encoded []byte) { encoded[1] = 1 },
		"port":           func(encoded []byte) { binary.LittleEndian.PutUint16(encoded[2:4], 123) },
		"scope":          func(encoded []byte) { binary.LittleEndian.PutUint32(encoded[4:8], 1) },
		"corrected nanos": func(encoded []byte) {
			binary.LittleEndian.PutUint32(encoded[correctedNanosOffset:correctedNanosOffset+4], uint32(time.Second))
		},
		"zero stratum":    func(encoded []byte) { encoded[stratumOffset] = 0 },
		"invalid leap":    func(encoded []byte) { encoded[leapOffset] = 3 },
		"invalid version": func(encoded []byte) { encoded[versionOffset] = 3 },
		"flags reserved":  func(encoded []byte) { encoded[flagsReservedOffset] = 1 },
		"negative roundtrip": func(encoded []byte) {
			binary.LittleEndian.PutUint64(encoded[roundTripNanosOffset:roundTripNanosOffset+8], ^uint64(0))
		},
		"tail reserved": func(encoded []byte) { encoded[reservedOffset] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			malformed := append([]byte(nil), memory...)
			mutate(malformed)
			if _, ok := DecodeSampleV1(malformed, 0); ok {
				t.Fatal("malformed sample accepted")
			}
		})
	}
	if CheckSyncV1(memory, ^uint32(0)) || CheckResultV1(memory, ^uint32(0)-SampleV1Size+2) {
		t.Fatal("overflowing fixed range accepted")
	}
}

func TestSampleV1AtomicRoundTripAndCheckedRanges(t *testing.T) {
	memory := bytes.Repeat([]byte{0xa5}, 160)
	sample := ntpns.Sample{
		Server: netip.MustParseAddr("192.0.2.123"), CorrectedTime: time.Date(2026, 7, 13, 22, 0, 0, 123456789, time.UTC),
		Offset: -250 * time.Millisecond, RoundTripDelay: 20 * time.Millisecond,
		Stratum: 2, Leap: 0, Version: 4, ReferenceID: [4]byte{'G', 'P', 'S', 0},
	}
	if !CheckSyncV1(memory, 0) || !CheckResultV1(memory, 32) {
		t.Fatal("valid output ranges rejected")
	}
	if CheckResultV1(memory, 100) {
		t.Fatal("truncated sample output accepted")
	}
	if !EncodeSampleV1(memory, 32, sample) {
		t.Fatal("encode sample")
	}
	decoded, ok := DecodeSampleV1(memory, 32)
	if !ok || decoded != sample {
		t.Fatalf("decoded sample = %+v, %v", decoded, ok)
	}
	if got := int64(binary.LittleEndian.Uint64(memory[80:88])); got != int64(sample.Offset) {
		t.Fatalf("offset nanos = %d", got)
	}
	before := append([]byte(nil), memory...)
	invalid := sample
	invalid.RoundTripDelay = -1
	if EncodeSampleV1(memory, 32, invalid) {
		t.Fatal("invalid sample encoded")
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("invalid sample mutated memory")
	}
	memory[79] = 1
	if _, ok := DecodeSampleV1(memory, 32); ok {
		t.Fatal("nonzero reserved flags accepted")
	}
}

func FuzzNTPV1SampleLayout(f *testing.F) {
	valid := make([]byte, 160)
	sample := ntpns.Sample{
		Server: netip.MustParseAddr("192.0.2.123"), CorrectedTime: time.Date(2026, 7, 13, 22, 0, 0, 123456789, time.UTC),
		Offset: -250 * time.Millisecond, RoundTripDelay: 20 * time.Millisecond,
		Stratum: 2, Leap: 0, Version: 4, ReferenceID: [4]byte{'G', 'P', 'S', 0},
	}
	if !EncodeSampleV1(valid, 32, sample) {
		f.Fatal("seed sample")
	}
	f.Add(valid, uint32(32), uint32(80))
	f.Add([]byte{0xff, 1, 2, 3}, ^uint32(0), ^uint32(0))
	f.Fuzz(func(t *testing.T, memory []byte, inputPtr, outputPtr uint32) {
		if len(memory) > 4096 {
			t.Skip()
		}
		before := append([]byte(nil), memory...)
		decoded, ok := DecodeSampleV1(memory, inputPtr)
		_ = CheckSyncV1(memory, outputPtr)
		_ = CheckResultV1(memory, outputPtr)
		if !bytes.Equal(memory, before) {
			t.Fatal("sample validation mutated memory")
		}
		if ok {
			if !decoded.Valid() {
				t.Fatal("decoded invalid sample")
			}
			canonical := make([]byte, SampleV1Size)
			if !EncodeSampleV1(canonical, 0, decoded) {
				t.Fatal("decoded sample did not re-encode")
			}
			if roundTrip, roundTripOK := DecodeSampleV1(canonical, 0); !roundTripOK || roundTrip != decoded {
				t.Fatalf("sample round trip = %+v, %v", roundTrip, roundTripOK)
			}
		}

		encoded := append([]byte(nil), memory...)
		encodedBefore := append([]byte(nil), encoded...)
		if !EncodeSampleV1(encoded, outputPtr, sample) && !bytes.Equal(encoded, encodedBefore) {
			t.Fatal("failed sample encode mutated memory")
		}
	})
}
