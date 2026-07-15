package ntp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/wago-org/net/internal/policy"
)

func TestOptionsRespectOrderAndExplicitAuthoritySuppression(t *testing.T) {
	firstClock := ClockFunc(func() time.Time { return time.Unix(1, 0) })
	secondClock := ClockFunc(func() time.Time { return time.Unix(2, 0) })
	config := registration{defaultAuthority: true}
	for _, option := range []Option{
		WithConfig(DefaultConfig(netip.MustParseAddr("192.0.2.1"), firstClock)),
		Server("192.0.2.2"), WithClock(secondClock), AllowAll(), WithoutDefaultAuthority(),
	} {
		if err := option.applyNTP(&config); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := config.finalConfig()
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Server != netip.MustParseAddr("192.0.2.2") || resolved.Clock.Now() != time.Unix(2, 0) {
		t.Fatalf("resolved config = %+v now=%v", resolved, resolved.Clock.Now())
	}
	compiled, err := policy.Compile(config.authority(resolved))
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckEndpoint(policy.OperationNTPSync, netip.MustParseAddr("198.51.100.9"), 123) {
		t.Fatal("AllowAll did not grant NTP port 123")
	}
	if !compiled.CheckEndpoint(policy.OperationNTPSync, netip.MustParseAddr("127.0.0.1"), 123) {
		t.Fatal("AllowAll did not grant loopback NTP authority")
	}
	if compiled.CheckEndpoint(policy.OperationNTPSync, netip.MustParseAddr("198.51.100.9"), 124) {
		t.Fatal("AllowAll widened NTP authority beyond port 123")
	}
}
