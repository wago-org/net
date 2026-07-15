package ipv6

import (
	"net/netip"
	"runtime"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
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

func TestConfigurationIsSerializedWithNamespaceClose(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::8")
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 1, IPv6Resources: 1})
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "ipv6-close", RandSeed: 8,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 8}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 2},
		IPv4Address: netip.MustParseAddr("192.0.2.8"), IPv6Address: address, IPv6PrefixBits: 64,
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

	stop := make(chan struct{})
	started := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			started <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
					configuration := adapter.Configuration()
					if configuration.Valid() && configuration.Address != address {
						panic("IPv6 configuration changed before close")
					}
					runtime.Gosched()
				}
			}
		}()
	}
	for range 4 {
		<-started
	}
	runtime.Gosched()
	if err := common.Close(); err != nil {
		t.Fatal(err)
	}
	close(stop)
	readers.Wait()
	if got := adapter.Configuration(); got != (ipv6ns.Configuration{}) {
		t.Fatalf("configuration after close = %+v", got)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("close leaked quota: %+v", usage)
	}
}

func TestValidConfigRequiresExactStaticIdentityAndAuthority(t *testing.T) {
	global := Config{Address: netip.MustParseAddr("2001:db8::9"), PrefixBits: 64}
	linkLocal := Config{Address: netip.MustParseAddr("fe80::9"), PrefixBits: 64, ScopeID: 9}
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(global.Address, 128)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.DefaultLimits())
	if !ValidConfig(Config{}, 0, nil, nil, true) {
		t.Fatal("disabled IPv6 config rejected")
	}
	if !ValidConfig(global, 1280, compiled, account, true) || !ValidConfig(linkLocal, 1280, nil, nil, false) {
		t.Fatal("valid IPv6 config rejected")
	}
	if ValidConfig(global, 1280, nil, account, true) || ValidConfig(global, 1280, compiled, nil, true) {
		t.Fatal("authority-required validation accepted incomplete authority")
	}
	for name, config := range map[string]Config{
		"unspecified":       {Address: netip.IPv6Unspecified(), PrefixBits: 64},
		"loopback":          {Address: netip.IPv6Loopback(), PrefixBits: 128},
		"multicast":         {Address: netip.MustParseAddr("ff02::1"), PrefixBits: 64, ScopeID: 9},
		"mapped":            {Address: netip.MustParseAddr("::ffff:192.0.2.9"), PrefixBits: 64},
		"zoned":             {Address: netip.MustParseAddr("fe80::9%eth0"), PrefixBits: 64, ScopeID: 9},
		"global scope":      {Address: global.Address, PrefixBits: 64, ScopeID: 9},
		"link scope absent": {Address: linkLocal.Address, PrefixBits: 64},
		"zero prefix":       {Address: global.Address},
		"large prefix":      {Address: global.Address, PrefixBits: 129},
	} {
		t.Run(name, func(t *testing.T) {
			if ValidConfig(config, 1280, nil, nil, false) {
				t.Fatalf("accepted invalid config: %+v", config)
			}
		})
	}
	if ValidConfig(global, 1279, nil, nil, false) {
		t.Fatal("accepted IPv6 MTU below 1280")
	}
}

func TestNewRejectsMismatchedOrClosedCoreWithoutMutation(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::10")
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		config Config
		close  bool
	}{
		{name: "address", config: Config{Address: netip.MustParseAddr("2001:db8::11"), PrefixBits: 64}},
		{name: "prefix", config: Config{Address: address, PrefixBits: 96}},
		{name: "scope", config: Config{Address: address, PrefixBits: 64, ScopeID: 1}},
		{name: "closed", config: Config{Address: address, PrefixBits: 64}, close: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			account := quota.NewAccount(quota.Limits{Resources: 1, IPv6Resources: 1})
			common, err := lnetocore.New(lnetocore.Config{
				Hostname: "ipv6-mismatch", RandSeed: 10,
				HardwareAddress: [6]byte{2, 0, 0, 0, 0, 10}, IPv4Address: netip.MustParseAddr("192.0.2.10"),
				IPv6Address: address, IPv6PrefixBits: 64, MTU: 1500,
				Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1}, Policy: compiled, Quotas: account,
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.close {
				if err := common.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				defer common.Close()
			}
			if adapter, err := New(common, test.config); err == nil || adapter != nil {
				t.Fatalf("New = %T, %v", adapter, err)
			}
			if usage, closed := account.Snapshot(); usage != (quota.Usage{}) || closed {
				t.Fatalf("rejected install changed quota: %+v closed=%v", usage, closed)
			}
			common.Lock()
			gotAddress, gotPrefix, gotScope := common.IPv6AddressLocked(), common.IPv6PrefixBitsLocked(), common.IPv6ScopeIDLocked()
			common.Unlock()
			if gotAddress != address || gotPrefix != 64 || gotScope != 0 {
				t.Fatalf("rejected install mutated core identity: %v/%d%%%d", gotAddress, gotPrefix, gotScope)
			}
		})
	}
}

func TestNewFailsClosedWithoutCompleteAuthority(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::12")
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		policy  *policy.Policy
		account *quota.Account
	}{
		{name: "missing policy", account: quota.NewAccount(quota.Limits{Resources: 1, IPv6Resources: 1})},
		{name: "missing quotas", policy: compiled},
	} {
		t.Run(test.name, func(t *testing.T) {
			common, err := lnetocore.New(lnetocore.Config{
				Hostname: "ipv6-authority", RandSeed: 12,
				HardwareAddress: [6]byte{2, 0, 0, 0, 0, 12}, IPv4Address: netip.MustParseAddr("192.0.2.12"),
				IPv6Address: address, IPv6PrefixBits: 64, MTU: 1500,
				Link:   packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1},
				Policy: test.policy, Quotas: test.account,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer common.Close()
			adapter, err := New(common, Config{Address: address, PrefixBits: 64})
			failure, ok := nscore.FailureOf(err)
			if adapter != nil || !ok || failure != nscore.FailureInvalidArgument {
				t.Fatalf("New = %T, %v", adapter, err)
			}
			if test.account != nil {
				if usage, closed := test.account.Snapshot(); usage != (quota.Usage{}) || closed {
					t.Fatalf("rejected authority changed quota: %+v closed=%v", usage, closed)
				}
			}
		})
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
	if adapter, err := New(common, Config{Address: address, PrefixBits: 64}); adapter != nil || ipv6FailureOf(t, err) != nscore.FailureAccessDenied {
		t.Fatalf("caller deny installation = %T, %v", adapter, err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("denied install charged quota: %+v", usage)
	}
}

func TestNewReleasesNoStateWhenIPv6QuotaIsUnavailable(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::13")
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{})
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "ipv6-quota", RandSeed: 13,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 13}, IPv4Address: netip.MustParseAddr("192.0.2.13"),
		IPv6Address: address, IPv6PrefixBits: 64, MTU: 1500,
		Link:   packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 1, EgressFrames: 1},
		Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close()
	if adapter, err := New(common, Config{Address: address, PrefixBits: 64}); adapter != nil || ipv6FailureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("quota-limited installation = %T, %v", adapter, err)
	}
	if usage, closed := account.Snapshot(); usage != (quota.Usage{}) || closed {
		t.Fatalf("quota-limited install changed account: %+v closed=%v", usage, closed)
	}
}

func TestIngressParticipantDropsOnlyRejectedIPv6Frames(t *testing.T) {
	valid := ipv6IngressFrame(t, 17)
	extension := ipv6IngressFrame(t, 44)
	nonIPv6 := append([]byte(nil), valid...)
	ethernetFrame, err := ethernet.NewFrame(nonIPv6)
	if err != nil {
		t.Fatal(err)
	}
	ethernetFrame.SetEtherType(ethernet.TypeIPv4)

	adapter := new(Adapter)
	for _, test := range []struct {
		name        string
		frame       []byte
		wantHandled bool
	}{
		{name: "short non-frame", frame: []byte{0}},
		{name: "other EtherType", frame: nonIPv6},
		{name: "valid base header", frame: valid},
		{name: "extension header", frame: extension, wantHandled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handled, err := adapter.ingressLocked(test.frame)
			if err != nil || handled != test.wantHandled {
				t.Fatalf("ingress = handled:%v err:%v", handled, err)
			}
		})
	}
}

func TestIPv6IngressValidationSteadyStateDoesNotAllocate(t *testing.T) {
	if runtime.Compiler == "tinygo" {
		return
	}
	adapter := new(Adapter)
	for _, test := range []struct {
		name  string
		frame []byte
	}{
		{name: "accepted", frame: ipv6IngressFrame(t, 17)},
		{name: "dropped", frame: ipv6IngressFrame(t, 44)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var handled bool
			var err error
			allocs := testing.AllocsPerRun(1000, func() {
				handled, err = adapter.ingressLocked(test.frame)
			})
			if allocs != 0 {
				t.Fatalf("ingress allocations = %v, want 0", allocs)
			}
			if err != nil || handled != (test.name == "dropped") {
				t.Fatalf("ingress = handled:%v err:%v", handled, err)
			}
		})
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

func TestValidateIngressFrameRejectsLoopbackAddresses(t *testing.T) {
	frame := make([]byte, 14+40+8)
	ethernetFrame, _ := ethernet.NewFrame(frame)
	ethernetFrame.SetEtherType(ethernet.TypeIPv6)
	ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
	ipFrame.SetVersionTrafficAndFlow(6, 0, 0)
	ipFrame.SetPayloadLength(8)
	ipFrame.SetNextHeader(17)
	validSource := netip.MustParseAddr("2001:db8::1").As16()
	validDestination := netip.MustParseAddr("2001:db8::2").As16()

	for _, test := range []struct {
		name        string
		source      [16]byte
		destination [16]byte
	}{
		{name: "source", source: netip.IPv6Loopback().As16(), destination: validDestination},
		{name: "destination", source: validSource, destination: netip.IPv6Loopback().As16()},
	} {
		t.Run(test.name, func(t *testing.T) {
			*ipFrame.SourceAddr() = test.source
			*ipFrame.DestinationAddr() = test.destination
			if relevant, valid := ValidateIngressFrame(frame); !relevant || valid {
				t.Fatalf("loopback frame = relevant %v valid %v", relevant, valid)
			}
		})
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

func BenchmarkIngressLocked(b *testing.B) {
	adapter := new(Adapter)
	for _, test := range []struct {
		name  string
		frame []byte
	}{
		{name: "accepted", frame: ipv6IngressFrame(b, 17)},
		{name: "dropped", frame: ipv6IngressFrame(b, 44)},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := adapter.ingressLocked(test.frame); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func ipv6IngressFrame(t testing.TB, nextHeader lneto.IPProto) []byte {
	t.Helper()
	frame := make([]byte, 14+40+8)
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ethernetFrame.SetEtherType(ethernet.TypeIPv6)
	ipFrame, err := lnetoipv6.NewFrame(ethernetFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	ipFrame.SetVersionTrafficAndFlow(6, 0, 0)
	ipFrame.SetPayloadLength(8)
	ipFrame.SetNextHeader(nextHeader)
	*ipFrame.SourceAddr() = netip.MustParseAddr("2001:db8::1").As16()
	*ipFrame.DestinationAddr() = netip.MustParseAddr("2001:db8::2").As16()
	return frame
}

func ipv6FailureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}
