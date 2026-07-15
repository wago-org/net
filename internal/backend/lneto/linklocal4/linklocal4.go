// Package linklocal4 implements bounded immediate RFC 3927 IPv4 link-local
// claiming and defense over one shared lneto core.
package linklocal4

import (
	"errors"
	"net"
	"net/netip"
	"reflect"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/ethernet"
	lnetolinklocal "github.com/soypat/lneto/ipv4/linklocal4"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ linklocalns.Resource = (*claimResource)(nil)

const (
	serviceOrder = 1
	closeOrder   = 8
	arpFrameSize = 14 + 28
)

var (
	errPolicyDenied = errors.New("net: IPv4 link-local policy denied operation")
	errCanceled     = errors.New("IPv4 link-local claim canceled")
	errServiceLimit = errors.New("IPv4 link-local service-attempt limit reached")
)

// Config bounds every live claim, conflict sequence, and service attempt. The
// zero value truthfully disables the adapter. One exact claim is currently the
// maximum because all dynamic IPv4 contributors share one identity domain.
type Config struct {
	MaxClaims          uint16
	MaxConflicts       uint8
	MaxServiceAttempts uint16
	Seed               uint64
	Clock              linklocalns.Clock
}

type Adapter struct {
	core   *lnetocore.Namespace
	config Config
	policy *policy.Policy
	quotas *quota.Account
	claim  *claimResource
}

type resourceState uint8

const (
	stateActive resourceState = iota + 1
	stateFailed
	stateReleased
	stateClosed
)

type claimResource struct {
	owner           *Adapter
	handler         lnetolinklocal.Handler
	state           resourceState
	failure         error
	identity        lnetocore.IPv4IdentityLease
	serviceAttempts uint16
	defensePending  bool
	retained        quota.Charge
	work            quota.Charge
}

func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || !ValidConfig(config, common.PolicyLocked(), common.QuotasLocked(), true) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	a := &Adapter{core: common, config: config, policy: common.PolicyLocked(), quotas: common.QuotasLocked()}
	common.Unlock()
	if config.MaxClaims == 0 {
		return a, nil
	}
	if err := common.Install(lnetocore.Participant{
		IngressOrder: serviceOrder, Ingress: a.ingressLocked,
		EgressOrder: serviceOrder, HasEgress: a.hasWorkLocked, Egress: a.egressLocked,
		CloseOrder: closeOrder, Close: a.CloseLocked,
	}); err != nil {
		return nil, err
	}
	return a, nil
}

func ValidConfig(config Config, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxClaims == 0 {
		return config.MaxConflicts == 0 && config.MaxServiceAttempts == 0 && config.Seed == 0 && config.Clock == nil
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	return config.MaxClaims == 1 && config.MaxConflicts > 0 && config.MaxServiceAttempts > 0 && config.Seed != 0 && usableClock(config.Clock)
}

func usableClock(clock linklocalns.Clock) bool {
	if clock == nil {
		return false
	}
	value := reflect.ValueOf(clock)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

func (a *Adapter) TryClaim(request linklocalns.Request) (nscore.Resource, nscore.Progress, error) {
	if a == nil || a.core == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if a.config.MaxClaims == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !request.Valid() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	if a.claim != nil {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	if !a.core.IPv4AddressLocked().IsUnspecified() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	r := &claimResource{owner: a, state: stateActive}
	var first [4]byte
	if request.FirstCandidate.IsValid() {
		first = request.FirstCandidate.As4()
	}
	if err := r.handler.Reset(lnetolinklocal.Config{
		HardwareAddr: a.core.HardwareAddressLocked(), Now: a.config.Clock.Now,
		Seed: a.config.Seed, FirstCandidate: first,
	}); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if !a.authorizedLocked(policy.OperationLinkLocal4Claim, r.handler.Candidate()) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if err := a.quotas.AcquireResource(&r.retained, quota.ResourceLinkLocal4, 1); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireLinkLocal4Work(&r.work, 1); err != nil {
		r.retained.Release()
		r.retained.ResetReleased()
		return nil, 0, lnetocore.MapError(err)
	}
	a.claim = r
	return r, nscore.ProgressInProgress, nil
}

func (r *claimResource) Readiness() nscore.Readiness {
	if r == nil || r.owner == nil || r.owner.core == nil {
		return nscore.ReadyClosed
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == stateClosed || r.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if r.state == stateFailed {
		return nscore.ReadyError
	}
	if r.state == stateActive && r.handler.State().IsBound() && r.identity.Active() {
		return nscore.ReadyLinkLocal4Result
	}
	return 0
}

func (r *claimResource) TryResult() (linklocalns.Result, linklocalns.ResultState, error) {
	if r == nil || r.owner == nil || r.owner.core == nil {
		return linklocalns.Result{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	switch r.state {
	case stateFailed:
		return linklocalns.Result{}, 0, r.failure
	case stateReleased:
		return linklocalns.Result{}, 0, nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	case stateClosed:
		return linklocalns.Result{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	address, bound := r.handler.Addr()
	if !bound || !r.identity.Active() {
		return linklocalns.Result{}, linklocalns.ResultWouldBlock, nil
	}
	result := linklocalns.Result{Address: netip.AddrFrom4(address), Subnet: linklocalns.Prefix, Conflicts: uint16(r.handler.Conflicts()), Applied: true}
	if !result.Valid() {
		return linklocalns.Result{}, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	return result, linklocalns.ResultReady, nil
}

func (r *claimResource) Cancel() error {
	if r == nil || r.owner == nil || r.owner.core == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == stateClosed {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if r.state != stateActive || r.handler.State().IsBound() {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	r.failLocked(nscore.FailureCanceled, errCanceled)
	return nil
}

func (r *claimResource) Release() error {
	if r == nil || r.owner == nil || r.owner.core == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == stateReleased {
		return nil
	}
	if r.state != stateActive || !r.handler.State().IsBound() || !r.identity.Active() {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	if !r.identity.ReleaseLocked() {
		return nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	r.state = stateReleased
	r.handler = lnetolinklocal.Handler{}
	r.defensePending = false
	r.releaseWorkLocked()
	return nil
}

func (r *claimResource) Close() error {
	if r == nil || r.owner == nil || r.owner.core == nil {
		return nil
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	return r.closeLocked()
}

func (r *claimResource) closeLocked() error {
	if r.state == stateClosed {
		return nil
	}
	if r.identity.Active() {
		_ = r.identity.ReleaseLocked()
	}
	r.state = stateClosed
	r.handler = lnetolinklocal.Handler{}
	r.failure = nil
	r.defensePending = false
	r.serviceAttempts = 0
	r.releaseWorkLocked()
	r.retained.Release()
	r.retained.ResetReleased()
	if r.owner != nil && r.owner.claim == r {
		r.owner.claim = nil
	}
	return nil
}

func (r *claimResource) failLocked(failure nscore.Failure, cause error) {
	if r.state != stateActive {
		return
	}
	if r.identity.Active() {
		_ = r.identity.ReleaseLocked()
	}
	r.state = stateFailed
	r.failure = nscore.Fail(failure, cause)
	r.defensePending = false
	r.releaseWorkLocked()
}

func (r *claimResource) releaseWorkLocked() {
	r.work.Release()
	r.work.ResetReleased()
}

func (a *Adapter) authorizedLocked(operation policy.Operation, candidate [4]byte) bool {
	return a.policy.CheckAddress(operation, netip.AddrFrom4(candidate))
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ethernet.BroadcastAddr() && mac[0]&1 == 0
}

func (a *Adapter) hasWorkLocked() bool {
	r := a.claim
	return r != nil && r.state == stateActive && (!r.handler.State().IsBound() || r.defensePending)
}

func (a *Adapter) egressLocked(dst []byte) (int, bool, error) {
	r := a.claim
	if r == nil || r.state != stateActive {
		return 0, false, nil
	}
	if r.serviceAttempts >= a.config.MaxServiceAttempts {
		r.failLocked(nscore.FailureTimedOut, errServiceLimit)
		return 0, true, nil
	}
	operation := policy.OperationLinkLocal4Claim
	if r.handler.State().IsBound() {
		operation = policy.OperationLinkLocal4Defend
	}
	if !a.authorizedLocked(operation, r.handler.Candidate()) {
		r.failLocked(nscore.FailureAccessDenied, errPolicyDenied)
		return 0, true, nil
	}
	if len(dst) < arpFrameSize {
		return 0, false, lneto.ErrShortBuffer
	}
	r.serviceAttempts++
	frame := dst[:arpFrameSize]
	clear(frame)
	before := r.handler.State()
	n, err := r.handler.Encapsulate(frame, 0, 14)
	if err != nil {
		return 0, true, err
	}
	if n == 0 {
		return 0, true, nil
	}
	eth, _ := ethernet.NewFrame(frame)
	*eth.SourceHardwareAddr() = a.core.HardwareAddressLocked()
	eth.SetEtherType(ethernet.TypeARP)
	if before.IsBound() {
		r.defensePending = false
	}
	if r.handler.State().IsBound() && !r.identity.Active() {
		candidate := netip.AddrFrom4(r.handler.Candidate())
		if !a.core.TryApplyIPv4IdentityLocked(&r.identity, candidate, linklocalns.Prefix) {
			clear(frame)
			r.failLocked(nscore.FailureInvalidState, lneto.ErrBadState)
			return 0, true, nil
		}
		r.serviceAttempts = 0
	}
	return arpFrameSize, true, nil
}

func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	r := a.claim
	if r == nil || r.state != stateActive {
		return false, nil
	}
	eth, err := ethernet.NewFrame(frame)
	if err != nil || eth.EtherTypeOrSize() != ethernet.TypeARP {
		return false, err
	}
	destination := *eth.DestinationHardwareAddr()
	if destination != ethernet.BroadcastAddr() && destination != a.core.HardwareAddressLocked() {
		return false, nil
	}
	aframe, err := arp.NewFrame(eth.Payload())
	if err != nil {
		return false, nil
	}
	var validator lneto.Validator
	aframe.ValidateSize(&validator)
	if validator.ErrPop() != nil {
		return false, nil
	}
	hardwareType, hardwareLength := aframe.Hardware()
	protocolType, protocolLength := aframe.Protocol()
	if hardwareType != 1 || hardwareLength != 6 || protocolType != ethernet.TypeIPv4 || protocolLength != 4 {
		return false, nil
	}
	senderHW, senderProto := aframe.Sender4()
	_, targetProto := aframe.Target4()
	candidate := r.handler.Candidate()
	relevant := *senderProto == candidate || *targetProto == candidate
	source := *eth.SourceHardwareAddr()
	if !validUnicastMAC(source) || *senderHW != source {
		return relevant, nil
	}
	operation := aframe.Operation()
	if operation != arp.OpRequest && operation != arp.OpReply {
		return relevant, nil
	}
	beforeState := r.handler.State()
	beforeCandidate := r.handler.Candidate()
	defenseConflict := false
	if beforeState == lnetolinklocal.StateAnnouncing || beforeState == lnetolinklocal.StateBound {
		defenseConflict = *senderProto == beforeCandidate && *senderHW != a.core.HardwareAddressLocked()
	}
	if err := r.handler.Demux(frame, 14); err != nil {
		return true, nil
	}
	if r.handler.Conflicts() > int(a.config.MaxConflicts) {
		r.failLocked(nscore.FailureResourceLimit, lneto.ErrExhausted)
		return true, nil
	}
	if r.identity.Active() && !r.handler.State().IsBound() {
		if !r.identity.ReleaseLocked() {
			r.failLocked(nscore.FailureIO, lneto.ErrBadState)
			return true, nil
		}
		r.serviceAttempts = 0
	}
	if r.state == stateActive && !a.authorizedLocked(policy.OperationLinkLocal4Claim, r.handler.Candidate()) {
		r.failLocked(nscore.FailureAccessDenied, errPolicyDenied)
		return true, nil
	}
	if defenseConflict && (r.handler.State() == lnetolinklocal.StateAnnouncing || r.handler.State().IsBound()) {
		r.defensePending = true
	}
	// Conflict detection does not replace ordinary ARP processing. Let the
	// shared ARP layer observe every structurally valid frame after the claim
	// state has been updated; malformed claim-local frames are consumed above.
	return false, nil
}

func (a *Adapter) CloseLocked() {
	if a == nil {
		return
	}
	if a.claim != nil {
		_ = a.claim.closeLocked()
	}
}
