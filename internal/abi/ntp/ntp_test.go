package ntp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	ntpns "github.com/wago-org/net/internal/namespace/ntp"
)

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
