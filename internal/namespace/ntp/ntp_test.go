package ntp

import (
	"net/netip"
	"testing"
	"time"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

var (
	_ Namespace = (*fakeNamespace)(nil)
	_ Sync      = (*fakeSync)(nil)
	_ Clock     = ClockFunc(nil)
)

type fakeNamespace struct{ sync nscore.Resource }

func (n *fakeNamespace) TrySync() (nscore.Resource, nscore.Progress, error) {
	return n.sync, nscore.ProgressInProgress, nil
}

type fakeSync struct{ sample Sample }

func (*fakeSync) Close() error                { return nil }
func (*fakeSync) Cancel() error               { return nil }
func (*fakeSync) Readiness() nscore.Readiness { return nscore.ReadyNTPResult }
func (s *fakeSync) TryResult() (Sample, Next, error) {
	return s.sample, NextReady, nil
}

func TestNarrowNTPFacetExplicitClockAndSampleValidation(t *testing.T) {
	now := time.Date(2026, 7, 13, 22, 0, 0, 123, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	if got := clock.Now(); !got.Equal(now) {
		t.Fatalf("clock = %v, want %v", got, now)
	}
	sample := Sample{
		Server: netip.MustParseAddr("192.0.2.123"), CorrectedTime: now,
		Offset: 500 * time.Millisecond, RoundTripDelay: 20 * time.Millisecond,
		Stratum: 2, Leap: 0, Version: 4, ReferenceID: [4]byte{'G', 'P', 'S', 0},
	}
	if !sample.Valid() {
		t.Fatal("valid sample rejected")
	}
	backend := &fakeNamespace{sync: &fakeSync{sample: sample}}
	resource, progress, err := backend.TrySync()
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TrySync = %T, %v, %v", resource, progress, err)
	}
	sync, ok := resource.(Sync)
	if !ok {
		t.Fatalf("sync resource type = %T", resource)
	}
	got, next, err := sync.TryResult()
	if err != nil || next != NextReady || got != sample {
		t.Fatalf("TryResult = %+v, %v, %v", got, next, err)
	}
	for _, invalid := range []Sample{
		{},
		{Server: netip.IPv4Unspecified(), CorrectedTime: now, RoundTripDelay: time.Millisecond, Stratum: 1, Version: 4},
		{Server: netip.MustParseAddr("127.0.0.1"), CorrectedTime: now, RoundTripDelay: time.Millisecond, Stratum: 1, Version: 4},
		{Server: netip.MustParseAddr("224.0.1.1"), CorrectedTime: now, RoundTripDelay: time.Millisecond, Stratum: 1, Version: 4},
		{Server: netip.MustParseAddr("255.255.255.255"), CorrectedTime: now, RoundTripDelay: time.Millisecond, Stratum: 1, Version: 4},
		{Server: netip.MustParseAddr("::1"), CorrectedTime: now, RoundTripDelay: time.Millisecond, Stratum: 1, Version: 4},
		{Server: sample.Server, CorrectedTime: now.In(time.FixedZone("host", 0)), RoundTripDelay: time.Millisecond, Stratum: 1, Version: 4},
		{Server: sample.Server, CorrectedTime: now, RoundTripDelay: -1, Stratum: 1, Version: 4},
		{Server: sample.Server, CorrectedTime: now, RoundTripDelay: 1, Stratum: 16, Version: 4},
		{Server: sample.Server, CorrectedTime: now, RoundTripDelay: 1, Stratum: 1, Leap: 3, Version: 4},
		{Server: sample.Server, CorrectedTime: now, RoundTripDelay: 1, Stratum: 1, Version: 3},
	} {
		if invalid.Valid() {
			t.Fatalf("invalid sample accepted: %+v", invalid)
		}
	}
}
