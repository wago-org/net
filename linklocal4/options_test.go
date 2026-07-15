package linklocal4

import (
	"net/netip"
	"testing"
	"time"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/policy"
)

func TestOptionsPreserveOrderCopyAuthorityAndSuppressDefaults(t *testing.T) {
	firstClock := ClockFunc(func() time.Time { return time.Unix(1, 0) })
	secondClock := ClockFunc(func() time.Time { return time.Unix(2, 0) })
	config := registration{defaultAuthority: true}
	prefixes := []netip.Prefix{netip.MustParsePrefix("169.254.40.0/24")}
	for _, option := range []Option{
		WithConfig(DefaultConfig(1, firstClock)), WithSeed(2), WithClock(secondClock),
		AllowCandidates(prefixes...), WithPolicy(wagonet.PolicyConfig{}), WithoutDefaultAuthority(),
	} {
		if err := option.applyLinkLocal4(&config); err != nil {
			t.Fatal(err)
		}
	}
	prefixes[0] = netip.MustParsePrefix("169.254.50.0/24")
	resolved, err := config.finalConfig()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Seed != 2 || resolved.Clock.Now() != time.Unix(2, 0) {
		t.Fatalf("resolved config = %+v now=%v", resolved, resolved.Clock.Now())
	}
	compiled, err := policy.Compile(config.authority(resolved))
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckAddress(policy.OperationLinkLocal4Claim, netip.MustParseAddr("169.254.40.7")) {
		t.Fatal("copied candidate authority was not retained")
	}
	if compiled.CheckAddress(policy.OperationLinkLocal4Claim, netip.MustParseAddr("169.254.50.7")) {
		t.Fatal("candidate input mutation changed authority")
	}
	if compiled.CheckAddress(policy.OperationLinkLocal4Claim, netip.MustParseAddr("169.254.1.1")) {
		t.Fatal("default link-local authority survived suppression")
	}
}

func TestAllowCandidatesRejectsInvalidPrefixes(t *testing.T) {
	for _, prefixes := range [][]netip.Prefix{nil, {netip.MustParsePrefix("2001:db8::/64")}} {
		if err := AllowCandidates(prefixes...).applyLinkLocal4(&registration{}); err != ErrInvalidOption {
			t.Fatalf("AllowCandidates(%v) = %v", prefixes, err)
		}
	}
}
