package ipv6

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestAdapterOwnsExactQuotaAndConfiguration(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::1")
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 1, IPv6Resources: 1})
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "ipv6", RandSeed: 1,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 2},
		IPv4Address: netip.MustParseAddr("192.0.2.1"), IPv6Address: address, IPv6PrefixBits: 64,
		MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1},
		Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(common, Config{Address: address, PrefixBits: 64})
	if err != nil {
		t.Fatal(err)
	}
	if got := adapter.Configuration(); !got.Valid() || got.Address != address || got.PrefixBits != 64 || got.MTU != 1500 {
		t.Fatalf("configuration = %+v", got)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, IPv6Resources: 1}) {
		t.Fatalf("quota = %+v closed=%v", usage, closed)
	}
	if err := common.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("close leaked quota: %+v", usage)
	}
	if got := adapter.Configuration(); got.Valid() {
		t.Fatalf("closed adapter retained configuration: %+v", got)
	}
}

func TestAdapterCallerDenyWins(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::7")
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}},
		{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportIPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 1, IPv6Resources: 1})
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "ipv6-deny", RandSeed: 7, HardwareAddress: [6]byte{2, 0, 0, 0, 0, 7},
		IPv4Address: netip.MustParseAddr("192.0.2.7"), IPv6Address: address, IPv6PrefixBits: 64,
		MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close()
	if _, err := New(common, Config{Address: address, PrefixBits: 64}); err == nil {
		t.Fatal("caller deny did not prevent IPv6 service installation")
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("denied install charged quota: %+v", usage)
	}
}

func TestValidateIngressFrameRejectsExtensionsAndMalformedAddresses(t *testing.T) {
	frame := make([]byte, 14+40+8)
	ethernetFrame, _ := ethernet.NewFrame(frame)
	ethernetFrame.SetEtherType(ethernet.TypeIPv6)
	ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
	ipFrame.SetVersionTrafficAndFlow(6, 0, 0)
	ipFrame.SetPayloadLength(8)
	ipFrame.SetNextHeader(17)
	*ipFrame.SourceAddr() = netip.MustParseAddr("2001:db8::1").As16()
	*ipFrame.DestinationAddr() = netip.MustParseAddr("2001:db8::2").As16()
	if relevant, valid := ValidateIngressFrame(frame); !relevant || !valid {
		t.Fatalf("valid base frame = relevant %v valid %v", relevant, valid)
	}
	ipFrame.SetNextHeader(44)
	if _, valid := ValidateIngressFrame(frame); valid {
		t.Fatal("fragment extension header accepted")
	}
	ipFrame.SetNextHeader(17)
	*ipFrame.SourceAddr() = [16]byte{}
	if _, valid := ValidateIngressFrame(frame); valid {
		t.Fatal("unspecified source accepted")
	}
	ipFrame.SetVersionTrafficAndFlow(4, 0, 0)
	if _, valid := ValidateIngressFrame(frame); valid {
		t.Fatal("wrong IP version accepted")
	}
}

func TestValidateIngressFrameAcceptsTrafficClassAndFlowLabel(t *testing.T) {
	frame := make([]byte, 14+40+8)
	ethernetFrame, _ := ethernet.NewFrame(frame)
	ethernetFrame.SetEtherType(ethernet.TypeIPv6)
	ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
	ipFrame.SetPayloadLength(8)
	ipFrame.SetNextHeader(17)
	*ipFrame.SourceAddr() = netip.MustParseAddr("2001:db8::1").As16()
	*ipFrame.DestinationAddr() = netip.MustParseAddr("2001:db8::2").As16()

	for _, test := range []struct {
		name    string
		traffic lnetoipv6.ToS
		flow    uint32
	}{
		{name: "traffic class", traffic: 0xa5},
		{name: "flow label", flow: 0xabcde},
		{name: "traffic class and flow label", traffic: 0x5a, flow: 0x54321},
	} {
		t.Run(test.name, func(t *testing.T) {
			ipFrame.SetVersionTrafficAndFlow(6, test.traffic, test.flow)
			if relevant, valid := ValidateIngressFrame(frame); !relevant || !valid {
				t.Fatalf("labeled base frame = relevant %v valid %v", relevant, valid)
			}
		})
	}
}
