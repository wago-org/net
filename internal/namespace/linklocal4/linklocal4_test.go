package linklocal4

import (
	"net/netip"
	"testing"
	"time"
)

func TestRequestAndResultValidation(t *testing.T) {
	if !(Request{}).Valid() {
		t.Fatal("empty first candidate rejected")
	}
	valid := netip.MustParseAddr("169.254.42.7")
	if !(Request{FirstCandidate: valid}).Valid() {
		t.Fatal("usable first candidate rejected")
	}
	for _, value := range []string{"169.254.0.7", "169.254.255.7", "192.0.2.1", "::1"} {
		if (Request{FirstCandidate: netip.MustParseAddr(value)}).Valid() {
			t.Fatalf("invalid first candidate %s accepted", value)
		}
	}
	result := Result{Address: valid, Subnet: Prefix, Conflicts: 2, Applied: true}
	if !result.Valid() {
		t.Fatalf("valid result rejected: %+v", result)
	}
	result.Applied = false
	if result.Valid() {
		t.Fatal("unapplied result accepted")
	}
}

func TestClockFuncIsExplicit(t *testing.T) {
	want := time.Unix(123, 456).UTC()
	clock := ClockFunc(func() time.Time { return want })
	if got := clock.Now(); got != want {
		t.Fatalf("Now = %v, want %v", got, want)
	}
}
