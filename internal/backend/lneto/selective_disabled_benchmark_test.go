package lnetobackend

import (
	"testing"

	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	dhcpv4backend "github.com/wago-org/net/internal/backend/lneto/dhcpv4"
	dhcpv6backend "github.com/wago-org/net/internal/backend/lneto/dhcpv6"
	icmpv4backend "github.com/wago-org/net/internal/backend/lneto/icmpv4"
	icmpv6backend "github.com/wago-org/net/internal/backend/lneto/icmpv6"
	mdnsbackend "github.com/wago-org/net/internal/backend/lneto/mdns"
	ntpbackend "github.com/wago-org/net/internal/backend/lneto/ntp"
)

var benchmarkDisabledSelectiveAdapters [6]any

func BenchmarkDisabledSelectiveAdaptersNew(b *testing.B) {
	config := testConfig(93)
	b.ReportAllocs()
	for b.Loop() {
		common, err := lnetocore.New(coreConfig(config))
		if err != nil {
			b.Fatal(err)
		}
		adapters := [6]any{}
		if adapters[0], err = icmpv4backend.New(common, icmpv4backend.Config{}); err == nil {
			adapters[1], err = ntpbackend.New(common, ntpbackend.Config{})
		}
		if err == nil {
			adapters[2], err = dhcpv4backend.New(common, dhcpv4backend.Config{})
		}
		if err == nil {
			adapters[3], err = mdnsbackend.New(common, mdnsbackend.Config{})
		}
		if err == nil {
			adapters[4], err = dhcpv6backend.New(common, dhcpv6backend.Config{})
		}
		if err == nil {
			adapters[5], err = icmpv6backend.New(common, icmpv6backend.Config{})
		}
		if err != nil {
			_ = common.Close()
			b.Fatal(err)
		}
		benchmarkDisabledSelectiveAdapters = adapters
		if err := common.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
