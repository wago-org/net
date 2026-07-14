package icmpv6

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetoicmp "github.com/soypat/lneto/ipv6/icmpv6"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestEchoAndNDPExchange(t *testing.T) {
	coreA, a := newTestAdapter(t, 1, "2001:db8::1")
	coreB, b := newTestAdapter(t, 2, "2001:db8::2")
	defer coreA.Close()
	defer coreB.Close()

	neighborResource, progress, err := a.TryResolve(icmpns.NeighborRequest{Address: b.address})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryResolve = %T %v %v", neighborResource, progress, err)
	}
	resolved := neighborResource.(*resolution)
	var frame [1514]byte
	n, worked, err := a.egressLocked(frame[:])
	if err != nil || !worked || n != 14+40+ndpSize {
		t.Fatalf("NS egress = %d %v %v", n, worked, err)
	}
	assertNDPFrame(t, frame[:n], lnetoicmp.TypeNeighborSolicitation, 255, solicitedNodeMAC(b.address))
	if handled, err := b.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("NS ingress = %v %v", handled, err)
	}
	n, worked, err = b.egressLocked(frame[:])
	if err != nil || !worked || n != 14+40+ndpSize {
		t.Fatalf("NA egress = %d %v %v", n, worked, err)
	}
	assertNDPFrame(t, frame[:n], lnetoicmp.TypeNeighborAdvertisement, 255, a.hardwareAddress)
	if handled, err := a.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("NA ingress = %v %v", handled, err)
	}
	neighbor, next, err := resolved.TryResult()
	if err != nil || next != icmpns.NextReady || neighbor.Address != b.address || neighbor.MAC != b.hardwareAddress || resolved.Readiness() != nscore.ReadyICMPv6Neighbor {
		t.Fatalf("neighbor result = %+v %v %v readiness=%v", neighbor, next, err, resolved.Readiness())
	}

	echoResource, progress, err := a.TryEcho(icmpns.EchoRequest{Destination: b.address, Payload: []byte("bounded ping6")})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryEcho = %T %v %v", echoResource, progress, err)
	}
	echo := echoResource.(*echo)
	n, worked, err = a.egressLocked(frame[:])
	if err != nil || !worked || n == 0 || [6]byte(frame[0:6]) != b.hardwareAddress {
		t.Fatalf("echo egress = %d %v %v dst=%x", n, worked, err, frame[:6])
	}
	if handled, err := b.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("echo request ingress = %v %v", handled, err)
	}
	n, worked, err = b.egressLocked(frame[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo response egress = %d %v %v", n, worked, err)
	}
	if handled, err := a.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("echo reply ingress = %v %v", handled, err)
	}
	var copied [7]byte
	result, next, err := echo.TryResult(copied[:])
	if err != nil || next != icmpns.NextReady || result.Source != b.address || result.Copied != len(copied) || result.PayloadBytes != len("bounded ping6") || string(copied[:]) != "bounded" || echo.Readiness() != nscore.ReadyICMPv6Reply {
		t.Fatalf("echo result = %+v %v %v payload=%q readiness=%v", result, next, err, copied[:], echo.Readiness())
	}
}

func TestStrictNDPValidationAndTimeoutCancellation(t *testing.T) {
	coreA, a := newTestAdapter(t, 3, "fe80::3")
	coreB, b := newTestAdapter(t, 4, "fe80::4")
	defer coreA.Close()
	defer coreB.Close()
	request := icmpns.NeighborRequest{Address: b.address, ScopeID: a.scopeID}
	resource, _, err := a.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	resolved := resource.(*resolution)
	var frame [1514]byte
	n, _, err := a.egressLocked(frame[:])
	if err != nil {
		t.Fatal(err)
	}
	ipFrame, _ := lnetoipv6.NewFrame(frame[14:n])
	ipFrame.SetHopLimit(64)
	if handled, err := b.ingressLocked(frame[:n]); err != nil || !handled || len(b.responses) != 0 {
		t.Fatalf("bad hop limit accepted: handled=%v err=%v responses=%d", handled, err, len(b.responses))
	}
	if err := resolved.Cancel(); err != nil {
		t.Fatal(err)
	}
	if resolved.Readiness() != nscore.ReadyError {
		t.Fatalf("canceled readiness = %v", resolved.Readiness())
	}
	if _, _, err := resolved.TryResult(); err == nil {
		t.Fatal("canceled resolution returned no error")
	}
	if _, ok, err := a.LookupNeighbor(request); err != nil || ok {
		t.Fatalf("canceled cache lookup = %v %v", ok, err)
	}

	resource, _, err = a.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	resolved = resource.(*resolution)
	for i := 0; i < int(a.config.MaxAttempts)*int(a.config.RetryServiceAttempts)+int(a.config.MaxAttempts)+2; i++ {
		_, _, _ = a.egressLocked(frame[:])
	}
	if _, _, err := resolved.TryResult(); err == nil || !errors.Is(err, resolved.failure) {
		t.Fatalf("timeout result = %v", err)
	}
}

func TestSeedLookupRemoveAndQuotaCleanup(t *testing.T) {
	core, adapter := newTestAdapter(t, 5, "2001:db8::5")
	neighbor := icmpns.Neighbor{Address: netip.MustParseAddr("2001:db8::55"), MAC: [6]byte{0x02, 5, 5, 5, 5, 5}}
	if err := adapter.SeedNeighbor(neighbor); err != nil {
		t.Fatal(err)
	}
	got, ok, err := adapter.LookupNeighbor(icmpns.NeighborRequest{Address: neighbor.Address})
	if err != nil || !ok || got != neighbor {
		t.Fatalf("lookup = %+v %v %v", got, ok, err)
	}
	if err := adapter.RemoveNeighbor(icmpns.NeighborRequest{Address: neighbor.Address}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := adapter.LookupNeighbor(icmpns.NeighborRequest{Address: neighbor.Address}); err != nil || ok {
		t.Fatalf("post-remove lookup = %v %v", ok, err)
	}
	account := adapter.quotas
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{}) {
		t.Fatalf("close usage = %+v closed=%v", usage, closed)
	}
}

func TestConfigRejectsUnrepresentableEchoPayload(t *testing.T) {
	config := testConfig()
	config.MaxPayloadBytes = icmpns.MaxEchoPayloadBytes + 1
	if ValidConfig(config, config.MaxPayloadBytes+40+icmpHeader, nil, nil, false) {
		t.Fatal("unrepresentable ICMPv6 payload config accepted")
	}
}

func TestZeroConfigRetainsTruthfulServiceSemantics(t *testing.T) {
	core, _ := newTestAdapter(t, 8, "2001:db8::8")
	adapter, err := New(core, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if operations := adapter.Operations(); operations != 0 {
		t.Fatalf("disabled operations = %v", operations)
	}
	if _, _, err := adapter.TryEcho(icmpns.EchoRequest{}); nscoreFailure(err) != nscore.FailureNotSupported {
		t.Fatalf("disabled echo = %v", err)
	}
	if _, _, err := adapter.TryResolve(icmpns.NeighborRequest{}); nscoreFailure(err) != nscore.FailureNotSupported {
		t.Fatalf("disabled resolve = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TryEcho(icmpns.EchoRequest{}); nscoreFailure(err) != nscore.FailureClosed {
		t.Fatalf("closed disabled echo = %v", err)
	}
}

func TestUnconfiguredIPv6IsTruthfullyUnsupported(t *testing.T) {
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportICMPv6}, Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound}}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.DefaultLimits())
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "icmp6-disabled", RandSeed: 9, HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 9}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 10},
		IPv4Address: netip.MustParseAddr("192.0.2.9"), MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	adapter, err := New(core, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TryEcho(icmpns.EchoRequest{Destination: netip.MustParseAddr("2001:db8::1"), Payload: []byte{1}}); err == nil {
		t.Fatal("disabled echo unexpectedly succeeded")
	} else if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureNotSupported {
		t.Fatalf("disabled echo = %v", err)
	}
}

func nscoreFailure(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func newTestAdapter(t testing.TB, id byte, addressText string) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	address := netip.MustParseAddr(addressText)
	scopeID := uint32(0)
	if address.IsLinkLocalUnicast() {
		scopeID = 7
	}
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportICMPv6}, Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("::/0")}}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 128, ICMPv6Resources: 128, ICMPv6Work: 32, QueuedBytes: 1 << 16, IPv6Resources: 1, ServiceUnits: 128})
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "icmp6", RandSeed: int64(id) + 1,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 1},
		IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), IPv6Address: address, IPv6PrefixBits: 64, IPv6ScopeID: scopeID,
		MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core, testConfig())
	if err != nil {
		core.Close()
		t.Fatal(err)
	}
	return core, adapter
}

func testConfig() Config {
	return Config{MaxEchoes: 4, MaxPayloadBytes: 256, MaxNeighbors: 8, MaxResolutions: 4, MaxQueuedResponses: 4, MaxAttempts: 2, RetryServiceAttempts: 2}
}

func assertNDPFrame(t testing.TB, frame []byte, typ lnetoicmp.Type, hop uint8, destinationMAC [6]byte) {
	t.Helper()
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || *ethernetFrame.DestinationHardwareAddr() != destinationMAC {
		t.Fatalf("ethernet frame = %v dst=%x", err, *ethernetFrame.DestinationHardwareAddr())
	}
	ipFrame, err := lnetoipv6.NewFrame(ethernetFrame.Payload())
	if err != nil || ipFrame.HopLimit() != hop {
		t.Fatalf("IPv6 frame = %v hop=%d", err, ipFrame.HopLimit())
	}
	icmpFrame, err := lnetoicmp.NewFrame(ipFrame.Payload())
	if err != nil || icmpFrame.Type() != typ || icmpFrame.Code() != 0 {
		t.Fatalf("ICMPv6 frame = %v type=%v code=%d", err, icmpFrame.Type(), icmpFrame.Code())
	}
}
