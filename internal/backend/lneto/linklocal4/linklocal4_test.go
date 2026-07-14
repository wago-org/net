package linklocal4

import (
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	lnetolinklocal "github.com/soypat/lneto/ipv4/linklocal4"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func TestClaimDefendReconfigureAndReleaseIdentity(t *testing.T) {
	core, adapter, account, clock := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 4, MaxServiceAttempts: 64, Seed: 0xc0ffee})
	resource, progress, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryClaim = %T, %v, %v", resource, progress, err)
	}
	claim := resource.(*claimResource)
	first := driveBound(t, core, claim, clock)
	if first.Address != netip.MustParseAddr("169.254.42.7") || claim.Readiness() != nscore.ReadyLinkLocal4Result {
		t.Fatalf("first result = %+v readiness=%v", first, claim.Readiness())
	}
	core.Lock()
	if got := core.IPv4AddressLocked(); got != first.Address {
		core.Unlock()
		t.Fatalf("dynamic identity = %v", got)
	}
	var competing lnetocore.IPv4IdentityLease
	if core.TryApplyIPv4IdentityLocked(&competing, netip.MustParseAddr("192.0.2.9"), netip.MustParsePrefix("192.0.2.0/24")) {
		core.Unlock()
		t.Fatal("competing DHCP-style identity replaced link-local")
	}
	core.Unlock()

	conflict := makeConflict(t, first.Address, [6]byte{2, 0, 0, 0, 0, 2})
	serviceIngress(t, core, conflict)
	_ = nextEgress(t, core, clock)
	if result, state, err := claim.TryResult(); err != nil || state != linklocalns.ResultReady || result.Address != first.Address {
		t.Fatalf("defended result = %+v, %v, %v", result, state, err)
	}
	serviceIngress(t, core, conflict)
	if _, state, err := claim.TryResult(); err != nil || state != linklocalns.ResultWouldBlock {
		t.Fatalf("reconfiguring result = %v, %v", state, err)
	}
	core.Lock()
	if got := core.IPv4AddressLocked(); !got.IsUnspecified() {
		core.Unlock()
		t.Fatalf("abandoned identity not rolled back: %v", got)
	}
	core.Unlock()
	second := driveBound(t, core, claim, clock)
	if second.Address == first.Address || second.Conflicts != 1 {
		t.Fatalf("replacement result = %+v, first=%v", second, first.Address)
	}
	if err := claim.Release(); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	if got := core.IPv4AddressLocked(); !got.IsUnspecified() {
		core.Unlock()
		t.Fatalf("release identity = %v", got)
	}
	core.Unlock()
	if usage, _ := account.Snapshot(); usage.LinkLocal4Resources != 1 || usage.LinkLocal4Work != 0 {
		t.Fatalf("released quota = %+v", usage)
	}
	if err := claim.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed quota = %+v", usage)
	}
}

func TestConflictDuringAnnouncementQueuesBoundDefense(t *testing.T) {
	core, adapter, _, clock := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 2, MaxServiceAttempts: 32, Seed: 13})
	resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.33.9")})
	if err != nil {
		t.Fatal(err)
	}
	claim := resource.(*claimResource)
	for i := 0; i < 4; i++ {
		if frame := nextEgress(t, core, clock); len(frame) != arpFrameSize {
			t.Fatalf("claim frame %d length = %d", i, len(frame))
		}
	}
	if claim.handler.State() != lnetolinklocal.StateAnnouncing {
		t.Fatalf("state before announcing conflict = %v", claim.handler.State())
	}
	serviceIngress(t, core, makeConflict(t, netip.MustParseAddr("169.254.33.9"), [6]byte{2, 0, 0, 0, 0, 2}))
	if frame := nextEgress(t, core, clock); len(frame) != arpFrameSize {
		t.Fatalf("final announcement length = %d", len(frame))
	}
	if frame := nextEgress(t, core, clock); len(frame) != arpFrameSize {
		t.Fatalf("queued defense length = %d", len(frame))
	}
	if _, state, err := claim.TryResult(); err != nil || state != linklocalns.ResultReady {
		t.Fatalf("result after queued defense = %v, %v", state, err)
	}
}

func TestIdentityContentionPolicyCancelAndTimeoutFailClosed(t *testing.T) {
	core, adapter, _, clock := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 2, MaxServiceAttempts: 32, Seed: 7})
	resource, _, err := adapter.TryClaim(linklocalns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	claim := resource.(*claimResource)
	var foreign lnetocore.IPv4IdentityLease
	core.Lock()
	if !core.TryApplyIPv4IdentityLocked(&foreign, netip.MustParseAddr("192.0.2.20"), netip.MustParsePrefix("192.0.2.0/24")) {
		core.Unlock()
		t.Fatal("failed to install competing identity")
	}
	core.Unlock()
	for i := 0; i < 20 && claim.Readiness() != nscore.ReadyError; i++ {
		_ = nextEgress(t, core, clock)
	}
	if _, _, err := claim.TryResult(); failureOf(t, err) != nscore.FailureInvalidState {
		t.Fatalf("identity contention result = %v", err)
	}
	core.Lock()
	if got := core.IPv4AddressLocked(); got != netip.MustParseAddr("192.0.2.20") || !foreign.ReleaseLocked() {
		core.Unlock()
		t.Fatalf("foreign identity mutated or failed release: %v", got)
	}
	core.Unlock()
	_ = claim.Close()

	resource, _, err = adapter.TryClaim(linklocalns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	claim = resource.(*claimResource)
	if err := claim.Cancel(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := claim.TryResult(); failureOf(t, err) != nscore.FailureCanceled {
		t.Fatalf("cancel result = %v", err)
	}
	_ = claim.Close()

	_, denied, _, _ := newAdapterWithPolicy(t, Config{MaxClaims: 1, MaxConflicts: 1, MaxServiceAttempts: 1, Seed: 9}, netip.MustParsePrefix("169.254.1.0/24"), netip.MustParsePrefix("169.254.1.1/32"))
	if _, _, err := denied.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.1.1")}); failureOf(t, err) != nscore.FailureAccessDenied {
		t.Fatalf("deny-wins claim = %v", err)
	}

	timeoutCore, timeoutAdapter, _, _ := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 1, MaxServiceAttempts: 1, Seed: 11})
	resource, _, err = timeoutAdapter.TryClaim(linklocalns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	timed := resource.(*claimResource)
	serviceOnce(t, timeoutCore)
	serviceOnce(t, timeoutCore)
	serviceOnce(t, timeoutCore)
	serviceOnce(t, timeoutCore)
	if _, _, err := timed.TryResult(); failureOf(t, err) != nscore.FailureTimedOut {
		t.Fatalf("bounded timeout = %v", err)
	}
}

func TestConfigIsFiniteExplicitClockAndZeroDisabled(t *testing.T) {
	if !ValidConfig(Config{}, nil, nil, false) {
		t.Fatal("zero disabled config rejected")
	}
	clock := &fakeClock{now: time.Unix(1, 0)}
	valid := Config{MaxClaims: 1, MaxConflicts: 1, MaxServiceAttempts: 1, Seed: 1, Clock: clock}
	if !ValidConfig(valid, nil, nil, false) {
		t.Fatal("finite config rejected")
	}
	for _, invalid := range []Config{
		{MaxClaims: 2, MaxConflicts: 1, MaxServiceAttempts: 1, Seed: 1, Clock: clock},
		{MaxClaims: 1, MaxServiceAttempts: 1, Seed: 1, Clock: clock},
		{MaxClaims: 1, MaxConflicts: 1, Seed: 1, Clock: clock},
		{MaxClaims: 1, MaxConflicts: 1, MaxServiceAttempts: 1, Clock: clock},
		{MaxClaims: 1, MaxConflicts: 1, MaxServiceAttempts: 1, Seed: 1},
	} {
		if ValidConfig(invalid, nil, nil, false) {
			t.Fatalf("invalid config accepted: %+v", invalid)
		}
	}
}

func newTestAdapter(t testing.TB, config Config) (*lnetocore.Namespace, *Adapter, *quota.Account, *fakeClock) {
	t.Helper()
	return newAdapterWithPolicy(t, config, netip.MustParsePrefix("169.254.0.0/16"), netip.Prefix{})
}

func newAdapterWithPolicy(t testing.TB, config Config, allow, deny netip.Prefix) (*lnetocore.Namespace, *Adapter, *quota.Account, *fakeClock) {
	t.Helper()
	rules := []policy.Rule{{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportLinkLocal4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{allow}}}
	if deny.IsValid() {
		rules = append(rules, policy.Rule{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportLinkLocal4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{deny}})
	}
	compiled, err := policy.Compile(policy.Config{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 4, LinkLocal4Resources: 4, LinkLocal4Work: 4, ServiceUnits: 128})
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "linklocal4", RandSeed: 9,
		HardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 9},
		IPv4Address: netip.IPv4Unspecified(), MTU: 1500,
		Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	clock := &fakeClock{now: time.Unix(1000, 0)}
	config.Clock = clock
	adapter, err := New(core, config)
	if err != nil {
		t.Fatal(err)
	}
	return core, adapter, account, clock
}

func driveBound(t testing.TB, core *lnetocore.Namespace, claim *claimResource, clock *fakeClock) linklocalns.Result {
	t.Helper()
	for i := 0; i < 24; i++ {
		_ = nextEgress(t, core, clock)
		result, state, err := claim.TryResult()
		if err != nil {
			t.Fatal(err)
		}
		if state == linklocalns.ResultReady {
			return result
		}
	}
	t.Fatal("claim did not become bound")
	return linklocalns.Result{}
}

func nextEgress(t testing.TB, core *lnetocore.Namespace, clock *fakeClock) []byte {
	t.Helper()
	clock.advance(3 * time.Second)
	for i := 0; i < 4; i++ {
		serviceOnce(t, core)
		frame := make([]byte, 1514)
		result, err := core.Link().TryDequeue(packetlink.Egress, frame)
		if err != nil {
			t.Fatal(err)
		}
		if result.Ready {
			return frame[:result.FrameBytes]
		}
	}
	return nil
}

func serviceOnce(t testing.TB, core *lnetocore.Namespace) {
	t.Helper()
	report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || !report.ValidResult(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1}, progress) {
		t.Fatalf("service = %+v, %v, %v", report, progress, err)
	}
}

func serviceIngress(t testing.TB, core *lnetocore.Namespace, frame []byte) {
	t.Helper()
	if err := core.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4 && core.Link().Snapshot().IngressFrames != 0; i++ {
		serviceOnce(t, core)
	}
	if core.Link().Snapshot().IngressFrames != 0 {
		t.Fatal("ingress was not consumed")
	}
}

func makeConflict(t testing.TB, candidate netip.Addr, other [6]byte) []byte {
	t.Helper()
	frame := make([]byte, arpFrameSize)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	*eth.DestinationHardwareAddr() = ethernet.BroadcastAddr()
	*eth.SourceHardwareAddr() = other
	eth.SetEtherType(ethernet.TypeARP)
	aframe, err := arp.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	aframe.SetHardware(1, 6)
	aframe.SetProtocol(ethernet.TypeIPv4, 4)
	aframe.SetOperation(arp.OpRequest)
	shw, sender := aframe.Sender4()
	*shw = other
	*sender = candidate.As4()
	_, target := aframe.Target4()
	*target = [4]byte{169, 254, 1, 1}
	return frame
}

func failureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("uncategorized error: %v", err)
	}
	return failure
}
