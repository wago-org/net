// Package icmpv6 implements bounded immediate ICMPv6 echo and Neighbor
// Discovery over one shared lneto namespace. It uses only exported frame codecs;
// no blocking, deadline, retry/backoff, sleep, goroutine, or retained guest-slice
// API enters this path.
package icmpv6

import (
	"bytes"
	"errors"
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetoicmp "github.com/soypat/lneto/ipv6/icmpv6"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

const (
	serviceOrder = -90
	closeOrder   = 6
	icmpHeader   = 8
	ndpSize      = 32
)

var (
	errPolicyDenied     = errors.New("net: ICMPv6 policy denied operation")
	errEchoCanceled     = errors.New("ICMPv6 echo canceled")
	errNeighborCanceled = errors.New("ICMPv6 neighbor resolution canceled")
	errNeighborLimit    = errors.New("ICMPv6 neighbor service-attempt limit reached")
	errEchoLimit        = errors.New("ICMPv6 echo service-attempt limit reached")
)

// Config fixes every retained cache, response, payload, retry, and active-work
// dimension. The complete zero value disables ICMPv6 truthfully.
type Config struct {
	MaxEchoes            uint16
	MaxPayloadBytes      int
	MaxNeighbors         uint16
	MaxResolutions       uint16
	MaxQueuedResponses   uint16
	MaxAttempts          uint16
	RetryServiceAttempts uint16
}

// Adapter owns one exact ICMPv6/NDP participant and finite cache.
type Adapter struct {
	core                   *lnetocore.Namespace
	config                 Config
	policy                 *policy.Policy
	quotas                 *quota.Account
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte
	address                netip.Addr
	scopeID                uint32
	echoes                 []*echo
	byIdentity             map[uint32]*echo
	resolutions            []*resolution
	byTarget               map[netip.Addr]*resolution
	neighbors              map[netip.Addr]*neighborEntry
	responses              []*response
	nextIdentifier         uint16
	nextSequence           uint16
	cursor                 int
	closed                 bool
}

var _ icmpns.Namespace = (*Adapter)(nil)

type state uint8

const (
	statePending state = iota + 1
	stateWaiting
	stateDone
	stateFailed
	stateClosed
)

type echo struct {
	owner       *Adapter
	destination netip.Addr
	scopeID     uint32
	payload     []byte
	identifier  uint16
	sequence    uint16
	attempts    uint16
	retry       uint16
	state       state
	failure     error
	retained    quota.Charge
	work        quota.Charge
}

var _ icmpns.Echo = (*echo)(nil)

type resolution struct {
	owner    *Adapter
	entry    *neighborEntry
	attempts uint16
	retry    uint16
	state    state
	failure  error
	retained quota.Charge
	work     quota.Charge
}

var _ icmpns.Resolution = (*resolution)(nil)

type neighborEntry struct {
	address  netip.Addr
	scopeID  uint32
	mac      [6]byte
	complete bool
	retained quota.Charge
}

type responseKind uint8

const (
	responseEcho responseKind = iota + 1
	responseAdvertisement
)

type response struct {
	kind        responseKind
	destination netip.Addr
	dstMAC      [6]byte
	identifier  uint16
	sequence    uint16
	payload     []byte
	retained    quota.Charge
}

// ValidConfig validates finite storage and service bounds.
func ValidConfig(config Config, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config == (Config{}) {
		return true
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	return config.MaxEchoes > 0 && config.MaxPayloadBytes > 0 && config.MaxPayloadBytes <= icmpns.MaxEchoPayloadBytes &&
		config.MaxPayloadBytes <= mtu-40-icmpHeader &&
		config.MaxNeighbors > 0 && config.MaxResolutions > 0 && config.MaxResolutions <= config.MaxNeighbors &&
		config.MaxQueuedResponses > 0 && config.MaxAttempts > 0 && config.RetryServiceAttempts > 0
}

// New installs the ICMPv6 participant only when the namespace has an immutable
// operational IPv6 identity. Otherwise the selected service remains present
// and truthfully returns NOT_SUPPORTED without retaining protocol backing.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil || !ValidConfig(config, 1500, nil, nil, false) {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || !ValidConfig(config, common.RequiredFrameBytesLocked()-14, common.PolicyLocked(), common.QuotasLocked(), true) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	seed := uint16(common.RandSeedLocked())
	if seed == 0 {
		seed = 1
	}
	adapter := &Adapter{
		core: common, config: config, policy: common.PolicyLocked(), quotas: common.QuotasLocked(),
		hardwareAddress: common.HardwareAddressLocked(), gatewayHardwareAddress: common.GatewayHardwareAddressLocked(),
		address: common.IPv6AddressLocked(), scopeID: common.IPv6ScopeIDLocked(),
		nextIdentifier: seed, nextSequence: 1,
	}
	if config == (Config{}) || !adapter.operationalAddress() {
		common.Unlock()
		return adapter, nil
	}
	adapter.echoes = make([]*echo, 0, config.MaxEchoes)
	adapter.byIdentity = make(map[uint32]*echo, config.MaxEchoes)
	adapter.resolutions = make([]*resolution, 0, config.MaxResolutions)
	adapter.byTarget = make(map[netip.Addr]*resolution, config.MaxResolutions)
	adapter.neighbors = make(map[netip.Addr]*neighborEntry, config.MaxNeighbors)
	adapter.responses = make([]*response, 0, config.MaxQueuedResponses)
	common.Unlock()
	if err := common.Install(lnetocore.Participant{
		IngressOrder: serviceOrder, Ingress: adapter.ingressLocked,
		EgressOrder: serviceOrder, HasEgress: adapter.hasWorkLocked, Egress: adapter.egressLocked,
		CloseOrder: closeOrder, Close: adapter.CloseLocked,
	}); err != nil {
		return nil, err
	}
	return adapter, nil
}

func (a *Adapter) Operations() icmpns.Operations {
	if a == nil {
		return 0
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() || !a.enabledLocked() {
		return 0
	}
	return icmpns.SupportedOperations
}

func (a *Adapter) operationalAddress() bool {
	return a.config != (Config{}) && a.address.IsValid() && a.address.Is6()
}

func (a *Adapter) enabledLocked() bool {
	return a != nil && !a.closed && a.operationalAddress()
}

func (a *Adapter) scopeMatches(address netip.Addr, scopeID uint32) bool {
	if address.IsLinkLocalUnicast() {
		return scopeID != 0 && scopeID == a.scopeID
	}
	return scopeID == 0
}

// TryEcho validates authority and copies payload immediately.
func (a *Adapter) TryEcho(request icmpns.EchoRequest) (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() || a.closed {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !a.enabledLocked() {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !request.Valid() || !a.scopeMatches(request.Destination, request.ScopeID) {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if len(request.Payload) == 0 || len(request.Payload) > a.config.MaxPayloadBytes {
		return nil, 0, nscore.Fail(nscore.FailureMessageTooLarge, lneto.ErrShortBuffer)
	}
	if !a.policy.CheckAddress(policy.OperationICMPv6Echo, request.Destination) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if _, ok := a.destinationMACLocked(request.Destination); !ok {
		return nil, 0, nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	if len(a.echoes) >= int(a.config.MaxEchoes) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	identifier, sequence, ok := a.allocateIdentityLocked()
	if !ok {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	exchange := &echo{owner: a, destination: request.Destination, scopeID: request.ScopeID, payload: append([]byte(nil), request.Payload...), identifier: identifier, sequence: sequence, state: statePending}
	if err := a.quotas.AcquireResourceAndQueuedBytes(&exchange.retained, quota.ResourceICMPv6, 1, uint64(len(exchange.payload))); err != nil {
		clear(exchange.payload)
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireICMPv6Work(&exchange.work, 1); err != nil {
		exchange.retained.Release()
		exchange.retained.ResetReleased()
		clear(exchange.payload)
		return nil, 0, lnetocore.MapError(err)
	}
	a.echoes = append(a.echoes, exchange)
	a.byIdentity[identityKey(identifier, sequence)] = exchange
	return exchange, nscore.ProgressInProgress, nil
}

// TryResolve creates one exact pending cache entry and bounded solicitation.
func (a *Adapter) TryResolve(request icmpns.NeighborRequest) (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() || a.closed {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !a.enabledLocked() {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !request.Valid() || !a.scopeMatches(request.Address, request.ScopeID) {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if !a.policy.CheckAddress(policy.OperationICMPv6Resolve, request.Address) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if entry := a.neighbors[request.Address]; entry != nil && entry.complete {
		if len(a.resolutions) >= int(a.config.MaxResolutions) {
			return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
		}
		resolved := &resolution{owner: a, entry: entry, state: stateDone}
		if err := a.quotas.AcquireResource(&resolved.retained, quota.ResourceICMPv6, 1); err != nil {
			return nil, 0, lnetocore.MapError(err)
		}
		a.resolutions = append(a.resolutions, resolved)
		return resolved, nscore.ProgressDone, nil
	}
	if a.byTarget[request.Address] != nil {
		return nil, 0, nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	if len(a.resolutions) >= int(a.config.MaxResolutions) || len(a.neighbors) >= int(a.config.MaxNeighbors) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	entry := &neighborEntry{address: request.Address, scopeID: request.ScopeID}
	if err := a.quotas.AcquireResource(&entry.retained, quota.ResourceICMPv6, 1); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	resolved := &resolution{owner: a, entry: entry, state: statePending}
	if err := a.quotas.AcquireResource(&resolved.retained, quota.ResourceICMPv6, 1); err != nil {
		entry.retained.Release()
		entry.retained.ResetReleased()
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireICMPv6Work(&resolved.work, 1); err != nil {
		resolved.retained.Release()
		resolved.retained.ResetReleased()
		entry.retained.Release()
		entry.retained.ResetReleased()
		return nil, 0, lnetocore.MapError(err)
	}
	a.neighbors[request.Address] = entry
	a.byTarget[request.Address] = resolved
	a.resolutions = append(a.resolutions, resolved)
	return resolved, nscore.ProgressInProgress, nil
}

func (a *Adapter) LookupNeighbor(request icmpns.NeighborRequest) (icmpns.Neighbor, bool, error) {
	if a == nil {
		return icmpns.Neighbor{}, false, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() || a.closed {
		return icmpns.Neighbor{}, false, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !a.enabledLocked() {
		return icmpns.Neighbor{}, false, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !request.Valid() || !a.scopeMatches(request.Address, request.ScopeID) {
		return icmpns.Neighbor{}, false, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if !a.policy.CheckAddress(policy.OperationICMPv6Lookup, request.Address) {
		return icmpns.Neighbor{}, false, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	entry := a.neighbors[request.Address]
	if entry == nil || !entry.complete {
		return icmpns.Neighbor{}, false, nil
	}
	return neighborValue(entry), true, nil
}

func (a *Adapter) SeedNeighbor(neighbor icmpns.Neighbor) error {
	if a == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() || a.closed {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !a.enabledLocked() {
		return nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !neighbor.Valid() || !a.scopeMatches(neighbor.Address, neighbor.ScopeID) {
		return nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if !a.policy.CheckAddress(policy.OperationICMPv6Seed, neighbor.Address) {
		return nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	entry := a.neighbors[neighbor.Address]
	if entry == nil {
		if len(a.neighbors) >= int(a.config.MaxNeighbors) {
			return nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
		}
		entry = &neighborEntry{address: neighbor.Address, scopeID: neighbor.ScopeID}
		if err := a.quotas.AcquireResource(&entry.retained, quota.ResourceICMPv6, 1); err != nil {
			return lnetocore.MapError(err)
		}
		a.neighbors[neighbor.Address] = entry
	}
	entry.mac = neighbor.MAC
	entry.complete = true
	if pending := a.byTarget[neighbor.Address]; pending != nil {
		pending.completeLocked()
	}
	return nil
}

func (a *Adapter) RemoveNeighbor(request icmpns.NeighborRequest) error {
	if a == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() || a.closed {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !a.enabledLocked() {
		return nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !request.Valid() || !a.scopeMatches(request.Address, request.ScopeID) {
		return nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if !a.policy.CheckAddress(policy.OperationICMPv6Remove, request.Address) {
		return nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	entry := a.neighbors[request.Address]
	if entry == nil {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	if a.byTarget[request.Address] != nil {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	a.removeNeighborLocked(entry)
	return nil
}

func (e *echo) Readiness() nscore.Readiness {
	if e == nil || e.owner == nil {
		return nscore.ReadyClosed
	}
	e.owner.core.Lock()
	defer e.owner.core.Unlock()
	if e.state == stateClosed || e.owner.closed || e.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if e.state == stateFailed {
		return nscore.ReadyError
	}
	if e.state == stateDone {
		return nscore.ReadyICMPv6Reply
	}
	return 0
}

func (e *echo) TryResult(dst []byte) (icmpns.EchoResult, icmpns.Next, error) {
	if e == nil || e.owner == nil {
		return icmpns.EchoResult{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	e.owner.core.Lock()
	defer e.owner.core.Unlock()
	if e.state == stateClosed || e.owner.closed || e.owner.core.ClosedLocked() {
		return icmpns.EchoResult{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if e.state == stateFailed {
		return icmpns.EchoResult{}, 0, e.failure
	}
	if e.state != stateDone {
		return icmpns.EchoResult{}, icmpns.NextWouldBlock, nil
	}
	copied := copy(dst, e.payload)
	return icmpns.EchoResult{Source: e.destination, ScopeID: e.scopeID, Identifier: e.identifier, Sequence: e.sequence, Copied: copied, PayloadBytes: len(e.payload)}, icmpns.NextReady, nil
}

func (e *echo) Cancel() error {
	if e == nil || e.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	e.owner.core.Lock()
	defer e.owner.core.Unlock()
	if e.state == stateClosed || e.owner.closed || e.owner.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if e.state == stateDone || e.state == stateFailed {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	e.failLocked(nscore.FailureCanceled, errEchoCanceled)
	return nil
}

func (e *echo) Close() error {
	if e == nil || e.owner == nil {
		return nil
	}
	e.owner.core.Lock()
	defer e.owner.core.Unlock()
	return e.closeLocked()
}

func (e *echo) closeLocked() error {
	if e.state == stateClosed {
		return nil
	}
	e.retireLocked()
	e.state = stateClosed
	removeEcho(e.owner, e)
	clear(e.payload)
	e.payload = nil
	e.releaseWorkLocked()
	e.retained.Release()
	e.retained.ResetReleased()
	e.owner = nil
	return nil
}

func (e *echo) completeLocked() {
	if e.state == stateClosed || e.state == stateDone || e.state == stateFailed {
		return
	}
	e.retireLocked()
	e.state = stateDone
	e.releaseWorkLocked()
}

func (e *echo) failLocked(failure nscore.Failure, cause error) {
	if e.state == stateClosed || e.state == stateDone || e.state == stateFailed {
		return
	}
	e.retireLocked()
	e.state = stateFailed
	e.failure = nscore.Fail(failure, cause)
	e.releaseWorkLocked()
}

func (e *echo) retireLocked() {
	if e.owner != nil && e.owner.byIdentity[identityKey(e.identifier, e.sequence)] == e {
		delete(e.owner.byIdentity, identityKey(e.identifier, e.sequence))
	}
	e.retry = 0
}

func (e *echo) releaseWorkLocked() {
	e.work.Release()
	e.work.ResetReleased()
}

func (r *resolution) Readiness() nscore.Readiness {
	if r == nil || r.owner == nil {
		return nscore.ReadyClosed
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == stateClosed || r.owner.closed || r.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if r.state == stateFailed {
		return nscore.ReadyError
	}
	if r.state == stateDone {
		return nscore.ReadyICMPv6Neighbor
	}
	return 0
}

func (r *resolution) TryResult() (icmpns.Neighbor, icmpns.Next, error) {
	if r == nil || r.owner == nil {
		return icmpns.Neighbor{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == stateClosed || r.owner.closed || r.owner.core.ClosedLocked() {
		return icmpns.Neighbor{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if r.state == stateFailed {
		return icmpns.Neighbor{}, 0, r.failure
	}
	if r.state != stateDone || r.entry == nil || !r.entry.complete {
		return icmpns.Neighbor{}, icmpns.NextWouldBlock, nil
	}
	return neighborValue(r.entry), icmpns.NextReady, nil
}

func (r *resolution) Cancel() error {
	if r == nil || r.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == stateClosed || r.owner.closed || r.owner.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if r.state == stateDone || r.state == stateFailed {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	r.failLocked(nscore.FailureCanceled, errNeighborCanceled, true)
	return nil
}

func (r *resolution) Close() error {
	if r == nil || r.owner == nil {
		return nil
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	return r.closeLocked()
}

func (r *resolution) closeLocked() error {
	if r.state == stateClosed {
		return nil
	}
	removePending := r.state != stateDone
	r.retireLocked()
	if removePending && r.entry != nil && !r.entry.complete {
		r.owner.removeNeighborLocked(r.entry)
	}
	r.state = stateClosed
	removeResolution(r.owner, r)
	r.releaseWorkLocked()
	r.retained.Release()
	r.retained.ResetReleased()
	r.entry = nil
	r.owner = nil
	return nil
}

func (r *resolution) completeLocked() {
	if r.state == stateClosed || r.state == stateDone || r.state == stateFailed {
		return
	}
	r.retireLocked()
	r.state = stateDone
	r.releaseWorkLocked()
}

func (r *resolution) failLocked(failure nscore.Failure, cause error, removeEntry bool) {
	if r.state == stateClosed || r.state == stateDone || r.state == stateFailed {
		return
	}
	r.retireLocked()
	if removeEntry && r.entry != nil && !r.entry.complete {
		r.owner.removeNeighborLocked(r.entry)
		r.entry = nil
	}
	r.state = stateFailed
	r.failure = nscore.Fail(failure, cause)
	r.releaseWorkLocked()
}

func (r *resolution) retireLocked() {
	if r.owner != nil && r.entry != nil && r.owner.byTarget[r.entry.address] == r {
		delete(r.owner.byTarget, r.entry.address)
	}
	r.retry = 0
}

func (r *resolution) releaseWorkLocked() {
	r.work.Release()
	r.work.ResetReleased()
}

func (a *Adapter) hasWorkLocked() bool {
	if a == nil || a.closed || len(a.responses) != 0 {
		return a != nil && !a.closed && len(a.responses) != 0
	}
	for _, r := range a.resolutions {
		if r != nil && (r.state == statePending || r.state == stateWaiting) {
			return true
		}
	}
	for _, e := range a.echoes {
		if e != nil && (e.state == statePending || e.state == stateWaiting) {
			return true
		}
	}
	return false
}

func (a *Adapter) egressLocked(dst []byte) (int, bool, error) {
	if len(a.responses) != 0 {
		response := a.responses[0]
		written, err := a.writeResponseLocked(dst, response)
		if err != nil {
			return 0, false, err
		}
		copy(a.responses, a.responses[1:])
		a.responses[len(a.responses)-1] = nil
		a.responses = a.responses[:len(a.responses)-1]
		a.releaseResponseLocked(response)
		return written, true, nil
	}
	total := len(a.resolutions) + len(a.echoes)
	if total == 0 {
		return 0, false, nil
	}
	if a.cursor >= total {
		a.cursor = 0
	}
	for offset := 0; offset < total; offset++ {
		index := (a.cursor + offset) % total
		if index < len(a.resolutions) {
			r := a.resolutions[index]
			if r == nil || (r.state != statePending && r.state != stateWaiting) {
				continue
			}
			if r.state == stateWaiting {
				a.cursor = (index + 1) % total
				if r.retry > 1 {
					r.retry--
					return 0, true, nil
				}
				if r.attempts >= a.config.MaxAttempts {
					r.failLocked(nscore.FailureTimedOut, errNeighborLimit, true)
					return 0, true, nil
				}
				r.state = statePending
				return 0, true, nil
			}
			written, err := a.writeSolicitationLocked(dst, r.entry)
			if err != nil {
				return 0, false, err
			}
			a.cursor = (index + 1) % total
			r.attempts++
			r.retry = a.config.RetryServiceAttempts
			r.state = stateWaiting
			return written, true, nil
		}
		e := a.echoes[index-len(a.resolutions)]
		if e == nil || (e.state != statePending && e.state != stateWaiting) {
			continue
		}
		if e.state == stateWaiting {
			a.cursor = (index + 1) % total
			if e.retry > 1 {
				e.retry--
				return 0, true, nil
			}
			if e.attempts >= a.config.MaxAttempts {
				e.failLocked(nscore.FailureTimedOut, errEchoLimit)
				return 0, true, nil
			}
			e.state = statePending
			return 0, true, nil
		}
		destinationMAC, ok := a.destinationMACLocked(e.destination)
		if !ok {
			a.cursor = (index + 1) % total
			e.failLocked(nscore.FailureInvalidState, lneto.ErrBadState)
			return 0, true, nil
		}
		written, err := a.writeEchoLocked(dst, e.destination, destinationMAC, lnetoicmp.TypeEchoRequest, e.identifier, e.sequence, e.payload, 64)
		if err != nil {
			return 0, false, err
		}
		a.cursor = (index + 1) % total
		e.attempts++
		e.retry = a.config.RetryServiceAttempts
		e.state = stateWaiting
		return written, true, nil
	}
	return 0, false, nil
}

func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || ethernetFrame.EtherTypeOrSize() != ethernet.TypeIPv6 {
		return false, err
	}
	ipFrame, err := lnetoipv6.NewFrame(ethernetFrame.Payload())
	if err != nil {
		return true, nil
	}
	version, _, _ := ipFrame.VersionTrafficAndFlow()
	if version != 6 || ipFrame.NextHeader() != lneto.IPProtoIPv6ICMP || int(ipFrame.PayloadLength())+40 > len(ethernetFrame.Payload()) {
		return ipFrame.NextHeader() == lneto.IPProtoIPv6ICMP, nil
	}
	source, destination := netip.AddrFrom16(*ipFrame.SourceAddr()), netip.AddrFrom16(*ipFrame.DestinationAddr())
	dstMAC := *ethernetFrame.DestinationHardwareAddr()
	localUnicast := destination == a.address && dstMAC == a.hardwareAddress
	localSolicited := destination == solicitedNode(a.address) && dstMAC == solicitedNodeMAC(a.address)
	if !localUnicast && !localSolicited {
		return false, nil
	}
	payload := ipFrame.Payload()
	icmpFrame, err := lnetoicmp.NewFrame(payload)
	if err != nil || !validIPv6Source(source) || destination.IsUnspecified() {
		return true, nil
	}
	var checksum lneto.CRC791
	ipFrame.CRCWritePseudo(&checksum)
	if checksum.PayloadSum16(payload) != 0 {
		return true, nil
	}
	srcMAC := *ethernetFrame.SourceHardwareAddr()
	if !validUnicastMAC(srcMAC) {
		return true, nil
	}
	switch icmpFrame.Type() {
	case lnetoicmp.TypeEchoRequest:
		return true, a.ingressEchoRequestLocked(ipFrame, icmpFrame, source, destination, srcMAC, dstMAC)
	case lnetoicmp.TypeEchoReply:
		return true, a.ingressEchoReplyLocked(icmpFrame, source, destination, dstMAC)
	case lnetoicmp.TypeNeighborSolicitation:
		return true, a.ingressSolicitationLocked(ipFrame, icmpFrame, payload, source, destination, srcMAC, dstMAC)
	case lnetoicmp.TypeNeighborAdvertisement:
		return true, a.ingressAdvertisementLocked(ipFrame, icmpFrame, payload, source, destination, srcMAC, dstMAC)
	default:
		return true, nil
	}
}

func (a *Adapter) ingressEchoRequestLocked(ipFrame lnetoipv6.Frame, frame lnetoicmp.Frame, source, destination netip.Addr, srcMAC, dstMAC [6]byte) error {
	if frame.Code() != 0 || destination != a.address || dstMAC != a.hardwareAddress || ipFrame.HopLimit() == 0 {
		return nil
	}
	echoFrame := lnetoicmp.FrameEcho{Frame: frame}
	payload := echoFrame.Data()
	if len(payload) == 0 || len(payload) > a.config.MaxPayloadBytes || len(a.responses) >= int(a.config.MaxQueuedResponses) || !a.policy.CheckAddress(policy.OperationICMPv6Respond, source) {
		return nil
	}
	response := &response{kind: responseEcho, destination: source, dstMAC: srcMAC, identifier: echoFrame.Identifier(), sequence: echoFrame.SequenceNumber(), payload: append([]byte(nil), payload...)}
	if err := a.quotas.AcquireResourceAndQueuedBytes(&response.retained, quota.ResourceICMPv6, 1, uint64(len(response.payload))); err != nil {
		clear(response.payload)
		return nil
	}
	a.responses = append(a.responses, response)
	return nil
}

func (a *Adapter) ingressEchoReplyLocked(frame lnetoicmp.Frame, source, destination netip.Addr, dstMAC [6]byte) error {
	if frame.Code() != 0 || destination != a.address || dstMAC != a.hardwareAddress {
		return nil
	}
	echoFrame := lnetoicmp.FrameEcho{Frame: frame}
	exchange := a.byIdentity[identityKey(echoFrame.Identifier(), echoFrame.SequenceNumber())]
	if exchange == nil || exchange.destination != source || !bytes.Equal(exchange.payload, echoFrame.Data()) {
		return nil
	}
	exchange.completeLocked()
	return nil
}

func (a *Adapter) ingressSolicitationLocked(ipFrame lnetoipv6.Frame, frame lnetoicmp.Frame, raw []byte, source, destination netip.Addr, srcMAC, dstMAC [6]byte) error {
	if ipFrame.HopLimit() != 255 || frame.Code() != 0 || len(raw) != ndpSize || destination != solicitedNode(a.address) || dstMAC != solicitedNodeMAC(a.address) || !a.policy.CheckAddress(policy.OperationICMPv6Advertise, source) {
		return nil
	}
	if !allZero(raw[4:8]) || netip.AddrFrom16(*(*[16]byte)(raw[8:24])) != a.address || raw[24] != 1 || raw[25] != 1 || [6]byte(raw[26:32]) != srcMAC {
		return nil
	}
	if len(a.responses) >= int(a.config.MaxQueuedResponses) {
		return nil
	}
	_ = a.seedPassiveLocked(source, a.scopeFor(source), srcMAC)
	response := &response{kind: responseAdvertisement, destination: source, dstMAC: srcMAC}
	if err := a.quotas.AcquireResource(&response.retained, quota.ResourceICMPv6, 1); err != nil {
		return nil
	}
	a.responses = append(a.responses, response)
	return nil
}

func (a *Adapter) ingressAdvertisementLocked(ipFrame lnetoipv6.Frame, frame lnetoicmp.Frame, raw []byte, source, destination netip.Addr, srcMAC, dstMAC [6]byte) error {
	if ipFrame.HopLimit() != 255 || frame.Code() != 0 || len(raw) != ndpSize || destination != a.address || dstMAC != a.hardwareAddress {
		return nil
	}
	if raw[4]&0x40 == 0 || raw[4]&0x1f != 0 || !allZero(raw[5:8]) || raw[24] != 2 || raw[25] != 1 || [6]byte(raw[26:32]) != srcMAC {
		return nil
	}
	target := netip.AddrFrom16(*(*[16]byte)(raw[8:24]))
	if target != source {
		return nil
	}
	pending := a.byTarget[target]
	if pending == nil || pending.entry == nil || !a.policy.CheckAddress(policy.OperationICMPv6Resolve, target) {
		return nil
	}
	pending.entry.mac = srcMAC
	pending.entry.complete = true
	pending.completeLocked()
	return nil
}

func (a *Adapter) writeResponseLocked(dst []byte, response *response) (int, error) {
	switch response.kind {
	case responseEcho:
		return a.writeEchoLocked(dst, response.destination, response.dstMAC, lnetoicmp.TypeEchoReply, response.identifier, response.sequence, response.payload, 64)
	case responseAdvertisement:
		return a.writeAdvertisementLocked(dst, response.destination, response.dstMAC)
	default:
		return 0, lneto.ErrBug
	}
}

func (a *Adapter) writeEchoLocked(dst []byte, destination netip.Addr, dstMAC [6]byte, typ lnetoicmp.Type, identifier, sequence uint16, payload []byte, hop uint8) (int, error) {
	frameBytes := 14 + 40 + icmpHeader + len(payload)
	if len(dst) < frameBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:frameBytes]
	clear(frame)
	icmpPayload, ipFrame := a.baseFrameLocked(frame, destination, dstMAC, icmpHeader+len(payload), hop)
	icmpFrame, _ := lnetoicmp.NewFrame(icmpPayload)
	echoFrame := lnetoicmp.FrameEcho{Frame: icmpFrame}
	echoFrame.SetType(typ)
	echoFrame.SetCode(0)
	echoFrame.SetIdentifier(identifier)
	echoFrame.SetSequenceNumber(sequence)
	copy(echoFrame.Data(), payload)
	setChecksum(ipFrame, icmpFrame, icmpPayload)
	return frameBytes, nil
}

func (a *Adapter) writeSolicitationLocked(dst []byte, entry *neighborEntry) (int, error) {
	if entry == nil {
		return 0, lneto.ErrBug
	}
	destination := solicitedNode(entry.address)
	frameBytes := 14 + 40 + ndpSize
	if len(dst) < frameBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:frameBytes]
	clear(frame)
	payload, ipFrame := a.baseFrameLocked(frame, destination, solicitedNodeMAC(entry.address), ndpSize, 255)
	icmpFrame, _ := lnetoicmp.NewFrame(payload)
	icmpFrame.SetType(lnetoicmp.TypeNeighborSolicitation)
	icmpFrame.SetCode(0)
	copy(payload[8:24], entry.address.AsSlice())
	payload[24], payload[25] = 1, 1
	copy(payload[26:32], a.hardwareAddress[:])
	setChecksum(ipFrame, icmpFrame, payload)
	return frameBytes, nil
}

func (a *Adapter) writeAdvertisementLocked(dst []byte, destination netip.Addr, dstMAC [6]byte) (int, error) {
	frameBytes := 14 + 40 + ndpSize
	if len(dst) < frameBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:frameBytes]
	clear(frame)
	payload, ipFrame := a.baseFrameLocked(frame, destination, dstMAC, ndpSize, 255)
	icmpFrame, _ := lnetoicmp.NewFrame(payload)
	icmpFrame.SetType(lnetoicmp.TypeNeighborAdvertisement)
	icmpFrame.SetCode(0)
	payload[4] = 0x60
	copy(payload[8:24], a.address.AsSlice())
	payload[24], payload[25] = 2, 1
	copy(payload[26:32], a.hardwareAddress[:])
	setChecksum(ipFrame, icmpFrame, payload)
	return frameBytes, nil
}

func (a *Adapter) baseFrameLocked(frame []byte, destination netip.Addr, dstMAC [6]byte, payloadBytes int, hop uint8) ([]byte, lnetoipv6.Frame) {
	ethernetFrame, _ := ethernet.NewFrame(frame)
	*ethernetFrame.DestinationHardwareAddr() = dstMAC
	*ethernetFrame.SourceHardwareAddr() = a.hardwareAddress
	ethernetFrame.SetEtherType(ethernet.TypeIPv6)
	ipFrame, _ := lnetoipv6.NewFrame(frame[14:])
	ipFrame.SetVersionTrafficAndFlow(6, 0, 0)
	ipFrame.SetPayloadLength(uint16(payloadBytes))
	ipFrame.SetNextHeader(lneto.IPProtoIPv6ICMP)
	ipFrame.SetHopLimit(hop)
	*ipFrame.SourceAddr() = a.address.As16()
	*ipFrame.DestinationAddr() = destination.As16()
	return frame[14+40 : 14+40+payloadBytes], ipFrame
}

func setChecksum(ipFrame lnetoipv6.Frame, icmpFrame lnetoicmp.Frame, payload []byte) {
	icmpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWritePseudo(&checksum)
	icmpFrame.SetCRC(checksum.PayloadSum16(payload))
}

func (a *Adapter) destinationMACLocked(address netip.Addr) ([6]byte, bool) {
	if entry := a.neighbors[address]; entry != nil && entry.complete {
		return entry.mac, true
	}
	if address.IsLinkLocalUnicast() {
		return [6]byte{}, false
	}
	return a.gatewayHardwareAddress, validUnicastMAC(a.gatewayHardwareAddress)
}

func (a *Adapter) seedPassiveLocked(address netip.Addr, scopeID uint32, mac [6]byte) error {
	if !validIPv6Source(address) || !validUnicastMAC(mac) || !a.scopeMatches(address, scopeID) || !a.policy.CheckAddress(policy.OperationICMPv6Seed, address) {
		return errPolicyDenied
	}
	entry := a.neighbors[address]
	if entry == nil {
		if len(a.neighbors) >= int(a.config.MaxNeighbors) {
			return lneto.ErrExhausted
		}
		entry = &neighborEntry{address: address, scopeID: scopeID}
		if err := a.quotas.AcquireResource(&entry.retained, quota.ResourceICMPv6, 1); err != nil {
			return err
		}
		a.neighbors[address] = entry
	}
	entry.mac = mac
	entry.complete = true
	if pending := a.byTarget[address]; pending != nil {
		pending.completeLocked()
	}
	return nil
}

func (a *Adapter) removeNeighborLocked(entry *neighborEntry) {
	if entry == nil || a.neighbors[entry.address] != entry {
		return
	}
	delete(a.neighbors, entry.address)
	entry.retained.Release()
	entry.retained.ResetReleased()
	*entry = neighborEntry{}
}

func (a *Adapter) allocateIdentityLocked() (uint16, uint16, bool) {
	for range int(a.config.MaxEchoes) + 1 {
		identifier, sequence := a.nextIdentifier, a.nextSequence
		a.nextSequence++
		if a.nextSequence == 0 {
			a.nextSequence = 1
			a.nextIdentifier++
			if a.nextIdentifier == 0 {
				a.nextIdentifier = 1
			}
		}
		if a.byIdentity[identityKey(identifier, sequence)] == nil {
			return identifier, sequence, true
		}
	}
	return 0, 0, false
}

// CloseLocked synchronously cancels work, clears queues/cache, and releases all
// exact quota charges. Caller holds the shared core lock.
func (a *Adapter) CloseLocked() {
	if a == nil || a.closed {
		return
	}
	a.closed = true
	for len(a.echoes) != 0 {
		_ = a.echoes[len(a.echoes)-1].closeLocked()
	}
	for len(a.resolutions) != 0 {
		_ = a.resolutions[len(a.resolutions)-1].closeLocked()
	}
	for len(a.responses) != 0 {
		response := a.responses[len(a.responses)-1]
		a.responses = a.responses[:len(a.responses)-1]
		a.releaseResponseLocked(response)
	}
	for _, entry := range a.neighbors {
		a.removeNeighborLocked(entry)
	}
	clear(a.byIdentity)
	clear(a.byTarget)
	clear(a.neighbors)
	a.echoes, a.resolutions, a.responses = nil, nil, nil
	a.byIdentity, a.byTarget, a.neighbors = nil, nil, nil
}

func (a *Adapter) releaseResponseLocked(response *response) {
	if response == nil {
		return
	}
	clear(response.payload)
	response.payload = nil
	response.retained.Release()
	response.retained.ResetReleased()
}

func (a *Adapter) scopeFor(address netip.Addr) uint32 {
	if address.IsLinkLocalUnicast() {
		return a.scopeID
	}
	return 0
}

func neighborValue(entry *neighborEntry) icmpns.Neighbor {
	if entry == nil {
		return icmpns.Neighbor{}
	}
	return icmpns.Neighbor{Address: entry.address, ScopeID: entry.scopeID, MAC: entry.mac}
}

func identityKey(identifier, sequence uint16) uint32 {
	return uint32(identifier)<<16 | uint32(sequence)
}

func removeEcho(owner *Adapter, target *echo) {
	for i, value := range owner.echoes {
		if value != target {
			continue
		}
		oldTotal := len(owner.resolutions) + len(owner.echoes)
		removedIndex := len(owner.resolutions) + i
		copy(owner.echoes[i:], owner.echoes[i+1:])
		owner.echoes[len(owner.echoes)-1] = nil
		owner.echoes = owner.echoes[:len(owner.echoes)-1]
		adjustCursorAfterRemoval(owner, removedIndex, oldTotal)
		return
	}
}

func removeResolution(owner *Adapter, target *resolution) {
	for i, value := range owner.resolutions {
		if value != target {
			continue
		}
		oldTotal := len(owner.resolutions) + len(owner.echoes)
		copy(owner.resolutions[i:], owner.resolutions[i+1:])
		owner.resolutions[len(owner.resolutions)-1] = nil
		owner.resolutions = owner.resolutions[:len(owner.resolutions)-1]
		adjustCursorAfterRemoval(owner, i, oldTotal)
		return
	}
}

func adjustCursorAfterRemoval(owner *Adapter, removedIndex, oldTotal int) {
	if owner == nil || oldTotal <= 1 {
		if owner != nil {
			owner.cursor = 0
		}
		return
	}
	owner.cursor %= oldTotal
	if owner.cursor > removedIndex {
		owner.cursor--
	}
	if owner.cursor >= oldTotal-1 {
		owner.cursor = 0
	}
}

func solicitedNode(address netip.Addr) netip.Addr {
	value := address.As16()
	return netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, value[13], value[14], value[15]})
}

func solicitedNodeMAC(address netip.Addr) [6]byte {
	value := address.As16()
	return [6]byte{0x33, 0x33, 0xff, value[13], value[14], value[15]}
}

func validIPv6Source(address netip.Addr) bool {
	return address.IsValid() && address.Is6() && !address.Is4In6() && address.Zone() == "" && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast()
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) && mac[0]&1 == 0
}

func allZero(bytes []byte) bool {
	for _, value := range bytes {
		if value != 0 {
			return false
		}
	}
	return true
}
