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
	dhcpv6ns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var (
	benchmarkDisabledSelectiveAdapters       [6]any
	benchmarkInoperableIPv6SelectiveAdapters [2]any
)

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

func BenchmarkInoperableIPv6SelectiveAdaptersNew(b *testing.B) {
	compiled, err := policy.Compile(policy.Config{})
	if err != nil {
		b.Fatal(err)
	}
	icmpConfig := icmpv6backend.Config{MaxEchoes: 4, MaxPayloadBytes: 256, MaxNeighbors: 8, MaxResolutions: 4, MaxQueuedResponses: 4, MaxAttempts: 2, RetryServiceAttempts: 2}
	dhcpConfig := dhcpv6backend.Config{
		MaxLeases: 1, MaxPacketBytes: 1024, MaxAttempts: 2, ResponseServiceAttempts: 2,
		MaxServerDUIDBytes: dhcpv6ns.MaxServerDUIDBytes, MaxDNSServers: dhcpv6ns.MaxDNSServers,
		MaxDomainSearch: dhcpv6ns.MaxDomainSearch, MaxNTPServers: dhcpv6ns.MaxNTPServers,
		MaxNTPMulticastServers: dhcpv6ns.MaxNTPMulticastServers, MaxNTPServerNames: dhcpv6ns.MaxNTPServerNames,
		MaxDelegatedPrefixes: dhcpv6ns.MaxDelegatedPrefixes,
	}
	config := testConfig(94)
	config.Policy = compiled
	b.ReportAllocs()
	for b.Loop() {
		config.Quotas = quota.NewAccount(quota.DefaultLimits())
		common, err := lnetocore.New(coreConfig(config))
		if err != nil {
			b.Fatal(err)
		}
		adapters := [2]any{}
		if adapters[0], err = icmpv6backend.New(common, icmpConfig); err == nil {
			adapters[1], err = dhcpv6backend.New(common, dhcpConfig)
		}
		if err != nil {
			_ = common.Close()
			b.Fatal(err)
		}
		benchmarkInoperableIPv6SelectiveAdapters = adapters
		if err := common.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
