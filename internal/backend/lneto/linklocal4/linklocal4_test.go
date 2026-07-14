package linklocal4

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	lneto "github.com/soypat/lneto"
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

func TestEgressShortBufferPreservesClaimLifecycleAndServiceBudget(t *testing.T) {
	core, adapter, account, clock := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 2, MaxServiceAttempts: 1, Seed: 31})
	resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")})
	if err != nil {
		t.Fatal(err)
	}
	claim := resource.(*claimResource)
	stateBefore := claim.handler.State()
	candidateBefore := claim.handler.Candidate()
	conflictsBefore := claim.handler.Conflicts()
	readyBefore := claim.Readiness()
	usageBefore, _ := account.Snapshot()
	short := bytes.Repeat([]byte{0xa5}, arpFrameSize-1)

	core.Lock()
	written, worked, err := adapter.egressLocked(short)
	core.Unlock()
	if written != 0 || worked || !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short claim egress = %d, %v, %v", written, worked, err)
	}
	if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
		t.Fatalf("short claim egress mutated destination = %x", short)
	}
	if claim.state != stateActive || claim.failure != nil || claim.serviceAttempts != 0 || claim.defensePending || claim.handler.State() != stateBefore || claim.handler.Candidate() != candidateBefore || claim.handler.Conflicts() != conflictsBefore {
		t.Fatalf("short claim egress mutated lifecycle: state=%v handler=%v attempts=%d defense=%v failure=%v", claim.state, claim.handler.State(), claim.serviceAttempts, claim.defensePending, claim.failure)
	}
	if claim.Readiness() != readyBefore {
		t.Fatalf("short claim egress changed readiness = %v, want %v", claim.Readiness(), readyBefore)
	}
	if usage, _ := account.Snapshot(); usage != usageBefore {
		t.Fatalf("short claim egress changed quota = %+v, want %+v", usage, usageBefore)
	}

	clock.advance(3 * time.Second)
	frame := make([]byte, arpFrameSize)
	core.Lock()
	written, worked, err = adapter.egressLocked(frame)
	core.Unlock()
	if err != nil || !worked || written != arpFrameSize || claim.state != stateActive || claim.failure != nil || claim.serviceAttempts != 1 {
		t.Fatalf("claim retry = %d, %v, %v state=%v attempts=%d failure=%v", written, worked, err, claim.state, claim.serviceAttempts, claim.failure)
	}
	eth, err := ethernet.NewFrame(frame[:written])
	if err != nil {
		t.Fatal(err)
	}
	if eth.EtherTypeOrSize() != ethernet.TypeARP || *eth.SourceHardwareAddr() != ([6]byte{2, 0, 0, 0, 0, 1}) {
		t.Fatalf("claim retry frame = etherType=%v source=%v", eth.EtherTypeOrSize(), *eth.SourceHardwareAddr())
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

func TestClaimQuotaFailureRollsBackOnlyAttemptedOwnership(t *testing.T) {
	baseLimits := quota.Limits{Resources: 4, LinkLocal4Resources: 4, LinkLocal4Work: 4, ServiceUnits: 128}
	for _, test := range []struct {
		name   string
		limits quota.Limits
	}{
		{name: "retained resource denied", limits: func() quota.Limits { limits := baseLimits; limits.LinkLocal4Resources = 0; return limits }()},
		{name: "work denied after retained acquisition", limits: func() quota.Limits { limits := baseLimits; limits.LinkLocal4Work = 0; return limits }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, adapter, account, _ := newAdapterWithPolicyLimits(t, Config{MaxClaims: 1, MaxConflicts: 2, MaxServiceAttempts: 16, Seed: 37}, netip.MustParsePrefix("169.254.0.0/16"), netip.Prefix{}, test.limits)
			if resource, progress, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}); resource != nil || progress != 0 || failureOf(t, err) != nscore.FailureResourceLimit {
				t.Fatalf("TryClaim = %T %v %v", resource, progress, err)
			}
			if adapter.claim != nil {
				t.Fatalf("failed claim published resource %p", adapter.claim)
			}
			if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
				t.Fatalf("failed claim retained quota = %+v", usage)
			}
			core.Lock()
			address := core.IPv4AddressLocked()
			core.Unlock()
			if !address.IsUnspecified() {
				t.Fatalf("failed claim changed IPv4 identity = %v", address)
			}
		})
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
	return newAdapterWithPolicyLimits(t, config, allow, deny, quota.Limits{Resources: 4, LinkLocal4Resources: 4, LinkLocal4Work: 4, ServiceUnits: 128})
}

func newAdapterWithPolicyLimits(t testing.TB, config Config, allow, deny netip.Prefix, limits quota.Limits) (*lnetocore.Namespace, *Adapter, *quota.Account, *fakeClock) {
	t.Helper()
	rules := []policy.Rule{{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportLinkLocal4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{allow}}}
	if deny.IsValid() {
		rules = append(rules, policy.Rule{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportLinkLocal4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{deny}})
	}
	compiled, err := policy.Compile(policy.Config{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(limits)
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

func TestIngressDropsMalformedARPSenderIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		ethernet [6]byte
		arp      [6]byte
	}{
		{name: "multicast source", ethernet: [6]byte{1, 0, 0, 0, 0, 2}, arp: [6]byte{1, 0, 0, 0, 0, 2}},
		{name: "sender mismatch", ethernet: [6]byte{2, 0, 0, 0, 0, 3}, arp: [6]byte{2, 0, 0, 0, 0, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, adapter, _, _ := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 4, MaxServiceAttempts: 16, Seed: 17})
			resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")})
			if err != nil {
				t.Fatal(err)
			}
			claim := resource.(*claimResource)
			frame := makeConflict(t, netip.MustParseAddr("169.254.42.7"), test.arp)
			eth, err := ethernet.NewFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			*eth.SourceHardwareAddr() = test.ethernet

			core.Lock()
			beforeCandidate, beforeConflicts := claim.handler.Candidate(), claim.handler.Conflicts()
			handled, ingressErr := adapter.ingressLocked(frame)
			afterCandidate, afterConflicts := claim.handler.Candidate(), claim.handler.Conflicts()
			core.Unlock()
			if ingressErr != nil || !handled {
				t.Fatalf("ingress = handled %v, err %v", handled, ingressErr)
			}
			if afterCandidate != beforeCandidate || afterConflicts != beforeConflicts || claim.state != stateActive {
				t.Fatalf("malformed ARP mutated claim: candidate %v -> %v, conflicts %d -> %d, state %v", beforeCandidate, afterCandidate, beforeConflicts, afterConflicts, claim.state)
			}
		})
	}
}

func TestConflictExhaustionIsTerminalAndLateARPIsolatedFromFreshClaim(t *testing.T) {
	core, adapter, account, _ := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 1, MaxServiceAttempts: 32, Seed: 19})
	resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")})
	if err != nil {
		t.Fatal(err)
	}
	stale := resource.(*claimResource)
	for i := 0; i < 2; i++ {
		core.Lock()
		candidate := netip.AddrFrom4(stale.handler.Candidate())
		core.Unlock()
		serviceIngress(t, core, makeConflict(t, candidate, [6]byte{2, 0, 0, 0, 0, byte(i + 2)}))
	}
	if stale.Readiness() != nscore.ReadyError {
		t.Fatalf("conflict exhaustion readiness = %v", stale.Readiness())
	}
	if _, _, err := stale.TryResult(); failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("conflict exhaustion result = %v", err)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, LinkLocal4Resources: 1}) {
		t.Fatalf("terminal quota = %+v, closed=%v", usage, closed)
	}
	core.Lock()
	failedCandidate, failedConflicts := stale.handler.Candidate(), stale.handler.Conflicts()
	core.Unlock()
	serviceIngress(t, core, makeConflict(t, netip.AddrFrom4(failedCandidate), [6]byte{2, 0, 0, 0, 0, 9}))
	core.Lock()
	if stale.handler.Candidate() != failedCandidate || stale.handler.Conflicts() != failedConflicts {
		core.Unlock()
		t.Fatal("late ARP mutated terminal claim")
	}
	core.Unlock()
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}

	freshResource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.55.8")})
	if err != nil {
		t.Fatal(err)
	}
	fresh := freshResource.(*claimResource)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	ownerClaim, freshState, freshCandidate := adapter.claim, fresh.state, fresh.handler.Candidate()
	core.Unlock()
	if ownerClaim != fresh || freshState != stateActive || netip.AddrFrom4(freshCandidate) != netip.MustParseAddr("169.254.55.8") {
		t.Fatalf("stale close mutated fresh claim: owner=%p fresh=%p state=%v candidate=%v", ownerClaim, fresh, freshState, netip.AddrFrom4(freshCandidate))
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, LinkLocal4Resources: 1, LinkLocal4Work: 1}) {
		t.Fatalf("fresh quota = %+v", usage)
	}
}

func TestBoundCloseAndNamespaceCloseRollbackIdentityAndQuota(t *testing.T) {
	core, adapter, account, clock := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 2, MaxServiceAttempts: 64, Seed: 23})
	resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.60.7")})
	if err != nil {
		t.Fatal(err)
	}
	closed := resource.(*claimResource)
	first := driveBound(t, core, closed, clock)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	address, ownerClaim := core.IPv4AddressLocked(), adapter.claim
	core.Unlock()
	if !address.IsUnspecified() || ownerClaim != nil || closed.Readiness() != nscore.ReadyClosed {
		t.Fatalf("direct close state: address=%v owner=%p readiness=%v", address, ownerClaim, closed.Readiness())
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("direct close quota = %+v", usage)
	}

	resource, _, err = adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.61.8")})
	if err != nil {
		t.Fatal(err)
	}
	fresh := resource.(*claimResource)
	second := driveBound(t, core, fresh, clock)
	if second.Address == first.Address {
		t.Fatalf("fresh claim reused requested identity unexpectedly: first=%v second=%v", first.Address, second.Address)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	address, ownerClaim = core.IPv4AddressLocked(), adapter.claim
	core.Unlock()
	if address != second.Address || ownerClaim != fresh || fresh.Readiness() != nscore.ReadyLinkLocal4Result {
		t.Fatalf("stale close changed bound fresh claim: address=%v owner=%p fresh=%p readiness=%v", address, ownerClaim, fresh, fresh.Readiness())
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if fresh.Readiness() != nscore.ReadyClosed {
		t.Fatalf("namespace close readiness = %v", fresh.Readiness())
	}
	if _, _, err := fresh.TryResult(); failureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("namespace close result = %v", err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close quota = %+v", usage)
	}
	if adapter.claim != nil || fresh.identity.Active() || fresh.handler.State() != 0 || fresh.handler.Candidate() != ([4]byte{}) || fresh.handler.Conflicts() != 0 {
		t.Fatalf("namespace close retained claim state: owner=%p identity=%v handler=%+v", adapter.claim, fresh.identity.Active(), fresh.handler)
	}
}

func TestIngressRelevanceConsumesMalformedLocalARPAndLeavesForeignUnhandled(t *testing.T) {
	core, adapter, _, _ := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 4, MaxServiceAttempts: 16, Seed: 29})
	resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")})
	if err != nil {
		t.Fatal(err)
	}
	claim := resource.(*claimResource)
	base := makeConflict(t, netip.MustParseAddr("169.254.42.7"), [6]byte{2, 0, 0, 0, 0, 2})
	for _, test := range []struct {
		name        string
		wantHandled bool
		mutate      func([]byte) []byte
	}{
		{name: "foreign Ethernet destination", mutate: func(frame []byte) []byte {
			eth, _ := ethernet.NewFrame(frame)
			*eth.DestinationHardwareAddr() = [6]byte{2, 0, 0, 0, 0, 99}
			return frame
		}},
		{name: "foreign candidate", mutate: func(frame []byte) []byte {
			eth, _ := ethernet.NewFrame(frame)
			aframe, _ := arp.NewFrame(eth.Payload())
			_, sender := aframe.Sender4()
			*sender = [4]byte{169, 254, 99, 9}
			return frame
		}},
		{name: "truncated local ARP", wantHandled: true, mutate: func(frame []byte) []byte { return frame[:20] }},
		{name: "local sender identity mismatch", wantHandled: true, mutate: func(frame []byte) []byte {
			eth, _ := ethernet.NewFrame(frame)
			aframe, _ := arp.NewFrame(eth.Payload())
			sender, _ := aframe.Sender4()
			*sender = [6]byte{2, 0, 0, 0, 0, 3}
			return frame
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := test.mutate(append([]byte(nil), base...))
			core.Lock()
			beforeCandidate, beforeConflicts := claim.handler.Candidate(), claim.handler.Conflicts()
			handled, ingressErr := adapter.ingressLocked(frame)
			afterCandidate, afterConflicts, state := claim.handler.Candidate(), claim.handler.Conflicts(), claim.state
			core.Unlock()
			if ingressErr != nil || handled != test.wantHandled {
				t.Fatalf("ingress = handled %v, err %v; want handled %v", handled, ingressErr, test.wantHandled)
			}
			if afterCandidate != beforeCandidate || afterConflicts != beforeConflicts || state != stateActive {
				t.Fatalf("malformed or foreign ARP mutated claim: candidate %v -> %v conflicts %d -> %d state=%v", beforeCandidate, afterCandidate, beforeConflicts, afterConflicts, state)
			}
		})
	}
}

func TestUnsupportedARPOperationPreservesClaimAndValidRetry(t *testing.T) {
	core, adapter, account, _ := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 4, MaxServiceAttempts: 16, Seed: 30})
	resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")})
	if err != nil {
		t.Fatal(err)
	}
	claim := resource.(*claimResource)
	candidate := netip.AddrFrom4(claim.handler.Candidate())
	malformed := makeConflict(t, candidate, [6]byte{2, 0, 0, 0, 0, 2})
	eth, err := ethernet.NewFrame(malformed)
	if err != nil {
		t.Fatal(err)
	}
	aframe, err := arp.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	aframe.SetOperation(3)
	usageBefore, _ := account.Snapshot()
	core.Lock()
	beforeState, beforeCandidate, beforeConflicts := claim.handler.State(), claim.handler.Candidate(), claim.handler.Conflicts()
	handled, ingressErr := adapter.ingressLocked(malformed)
	afterState, afterCandidate, afterConflicts := claim.handler.State(), claim.handler.Candidate(), claim.handler.Conflicts()
	core.Unlock()
	if ingressErr != nil || !handled {
		t.Fatalf("unsupported operation ingress = handled %v, err %v", handled, ingressErr)
	}
	if afterState != beforeState || afterCandidate != beforeCandidate || afterConflicts != beforeConflicts || claim.state != stateActive || claim.failure != nil {
		t.Fatalf("unsupported operation mutated claim: state %v -> %v candidate %v -> %v conflicts %d -> %d resource=%v failure=%v", beforeState, afterState, beforeCandidate, afterCandidate, beforeConflicts, afterConflicts, claim.state, claim.failure)
	}
	if usage, _ := account.Snapshot(); usage != usageBefore {
		t.Fatalf("unsupported operation changed quota = %+v, want %+v", usage, usageBefore)
	}

	foreign := makeConflict(t, netip.MustParseAddr("169.254.99.9"), [6]byte{2, 0, 0, 0, 0, 3})
	foreignEthernet, err := ethernet.NewFrame(foreign)
	if err != nil {
		t.Fatal(err)
	}
	foreignARP, err := arp.NewFrame(foreignEthernet.Payload())
	if err != nil {
		t.Fatal(err)
	}
	foreignARP.SetOperation(3)
	core.Lock()
	foreignHandled, foreignErr := adapter.ingressLocked(foreign)
	foreignState, foreignCandidate, foreignConflicts := claim.handler.State(), claim.handler.Candidate(), claim.handler.Conflicts()
	core.Unlock()
	if foreignErr != nil || foreignHandled {
		t.Fatalf("foreign unsupported operation ingress = handled %v, err %v", foreignHandled, foreignErr)
	}
	if foreignState != beforeState || foreignCandidate != beforeCandidate || foreignConflicts != beforeConflicts || claim.state != stateActive || claim.failure != nil {
		t.Fatalf("foreign unsupported operation mutated claim: state=%v candidate=%v conflicts=%d resource=%v failure=%v", foreignState, foreignCandidate, foreignConflicts, claim.state, claim.failure)
	}

	serviceIngress(t, core, makeConflict(t, candidate, [6]byte{2, 0, 0, 0, 0, 2}))
	core.Lock()
	retryCandidate, retryConflicts := claim.handler.Candidate(), claim.handler.Conflicts()
	core.Unlock()
	if retryConflicts != beforeConflicts+1 || retryCandidate == beforeCandidate || claim.state != stateActive || claim.failure != nil {
		t.Fatalf("valid conflict after malformed operation = candidate %v -> %v conflicts %d -> %d state=%v failure=%v", beforeCandidate, retryCandidate, beforeConflicts, retryConflicts, claim.state, claim.failure)
	}
}

func TestConflictMutationFallsThroughToOrdinaryARPProcessing(t *testing.T) {
	core, adapter, _, _ := newTestAdapter(t, Config{MaxClaims: 1, MaxConflicts: 4, MaxServiceAttempts: 16, Seed: 31})
	resource, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")})
	if err != nil {
		t.Fatal(err)
	}
	claim := resource.(*claimResource)
	ordinaryARPCalls := 0
	if err := core.Install(lnetocore.Participant{
		IngressOrder: serviceOrder + 1,
		Ingress: func(frame []byte) (bool, error) {
			eth, err := ethernet.NewFrame(frame)
			if err != nil || eth.EtherTypeOrSize() != ethernet.TypeARP {
				t.Fatalf("ordinary ARP ingress = %v, %v", eth.EtherTypeOrSize(), err)
			}
			ordinaryARPCalls++
			return true, nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	core.Lock()
	beforeCandidate, beforeConflicts := claim.handler.Candidate(), claim.handler.Conflicts()
	core.Unlock()
	serviceIngress(t, core, makeConflict(t, netip.AddrFrom4(beforeCandidate), [6]byte{2, 0, 0, 0, 0, 2}))
	core.Lock()
	afterCandidate, afterConflicts, state := claim.handler.Candidate(), claim.handler.Conflicts(), claim.state
	core.Unlock()
	if afterConflicts != beforeConflicts+1 || afterCandidate == beforeCandidate || state != stateActive {
		t.Fatalf("conflict state = candidate %v -> %v conflicts %d -> %d state=%v", beforeCandidate, afterCandidate, beforeConflicts, afterConflicts, state)
	}
	if ordinaryARPCalls != 1 {
		t.Fatalf("ordinary ARP calls = %d, want 1", ordinaryARPCalls)
	}
}

func BenchmarkIngressUnrelatedARP(b *testing.B) {
	core, adapter, _, _ := newTestAdapter(b, Config{MaxClaims: 1, MaxConflicts: 4, MaxServiceAttempts: 16, Seed: 17})
	if _, _, err := adapter.TryClaim(linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}); err != nil {
		b.Fatal(err)
	}
	frame := makeConflict(b, netip.MustParseAddr("169.254.99.9"), [6]byte{2, 0, 0, 0, 0, 2})
	core.Lock()
	defer core.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = adapter.ingressLocked(frame)
	}
}
