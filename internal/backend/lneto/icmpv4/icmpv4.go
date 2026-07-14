// Package icmpv4 implements bounded immediate ICMPv4 echo exchanges over one
// shared lneto namespace without using lneto's blocking client wrappers.
package icmpv4

import (
	"bytes"
	"errors"
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoicmp "github.com/soypat/lneto/ipv4/icmpv4"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ icmpns.Echo = (*echo)(nil)

const (
	serviceOrder = 5
	closeOrder   = 5
)

var (
	errPolicyDenied = errors.New("net: ICMPv4 policy denied operation")
	errCanceled     = errors.New("ICMPv4 echo canceled")
	errReplyLimit   = errors.New("ICMPv4 reply service-attempt limit reached")
)

// Config fixes concurrent echo resources, copied payload bytes, transmission
// attempts, and service-attempt retry bounds. Zero MaxEchoes disables ICMPv4
// truthfully and requires the complete zero value.
type Config struct {
	MaxEchoes            uint16
	MaxPayloadBytes      int
	MaxAttempts          uint16
	RetryServiceAttempts uint16
}

// Adapter owns ICMPv4 echo wire state and bounded service participation.
type Adapter struct {
	core                   *lnetocore.Namespace
	config                 Config
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte
	policy                 *policy.Policy
	quotas                 *quota.Account
	echoes                 []*echo
	byIdentity             map[uint32]*echo
	cursor                 int
	nextIdentifier         uint16
	nextSequence           uint16
}

type echoState uint8

const (
	echoPending echoState = iota + 1
	echoWaiting
	echoDone
	echoFailed
	echoClosed
)

type echo struct {
	owner       *Adapter
	destination netip.Addr
	payload     []byte
	identifier  uint16
	sequence    uint16
	attempts    uint16
	retry       uint16
	state       echoState
	failure     error
	retained    quota.Charge
	work        quota.Charge
}

// New attaches ICMPv4-local state and its immediate packet participant.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
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
		core: common, config: config,
		hardwareAddress:        common.HardwareAddressLocked(),
		gatewayHardwareAddress: common.GatewayHardwareAddressLocked(), policy: common.PolicyLocked(), quotas: common.QuotasLocked(),
		echoes: make([]*echo, 0, config.MaxEchoes), byIdentity: make(map[uint32]*echo, config.MaxEchoes),
		nextIdentifier: seed, nextSequence: 1,
	}
	common.Unlock()
	if err := common.Install(lnetocore.Participant{
		IngressOrder: serviceOrder,
		Ingress:      adapter.ingressLocked,
		EgressOrder:  serviceOrder,
		HasEgress:    adapter.hasWorkLocked,
		Egress:       adapter.egressLocked,
		CloseOrder:   closeOrder,
		Close:        adapter.CloseLocked,
	}); err != nil {
		return nil, err
	}
	return adapter, nil
}

// ValidConfig validates ICMPv4-local storage and deterministic work bounds.
func ValidConfig(config Config, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxEchoes == 0 {
		return config == (Config{})
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	return config.MaxPayloadBytes >= 0 && config.MaxPayloadBytes <= icmpns.MaxEchoPayloadBytes &&
		config.MaxPayloadBytes <= mtu-28 && config.MaxAttempts > 0 && config.RetryServiceAttempts > 0
}

// TryEcho immediately validates authority and copies request payload into one
// finite exchange resource.
func (a *Adapter) TryEcho(request icmpns.Request) (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !request.Valid() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if len(request.Payload) > a.config.MaxPayloadBytes {
		return nil, 0, nscore.Fail(nscore.FailureMessageTooLarge, lneto.ErrShortBuffer)
	}
	if a.config.MaxEchoes == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !a.policy.CheckAddress(policy.OperationICMPv4Echo, request.Destination) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(a.echoes) == int(a.config.MaxEchoes) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	identifier, sequence, ok := a.allocateIdentityLocked()
	if !ok {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	exchange := &echo{
		owner: a, destination: request.Destination,
		payload: append([]byte(nil), request.Payload...), identifier: identifier, sequence: sequence,
		state: echoPending,
	}
	if err := a.quotas.AcquireResourceAndQueuedBytes(&exchange.retained, quota.ResourceICMPv4, 1, uint64(len(exchange.payload))); err != nil {
		clear(exchange.payload)
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireICMPv4Work(&exchange.work, 1); err != nil {
		exchange.retained.Release()
		exchange.retained.ResetReleased()
		clear(exchange.payload)
		return nil, 0, lnetocore.MapError(err)
	}
	a.byIdentity[identityKey(identifier, sequence)] = exchange
	a.echoes = append(a.echoes, exchange)
	return exchange, nscore.ProgressInProgress, nil
}

func (e *echo) Readiness() nscore.Readiness {
	if e == nil || e.owner == nil {
		return nscore.ReadyClosed
	}
	e.owner.core.Lock()
	defer e.owner.core.Unlock()
	if e.state == echoClosed || e.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if e.state == echoFailed {
		return nscore.ReadyError
	}
	if e.state == echoDone {
		return nscore.ReadyICMPv4Reply
	}
	return 0
}

func (e *echo) TryResult(dst []byte) (icmpns.Result, icmpns.Next, error) {
	if e == nil || e.owner == nil {
		return icmpns.Result{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	e.owner.core.Lock()
	defer e.owner.core.Unlock()
	if e.state == echoClosed || e.owner.core.ClosedLocked() {
		return icmpns.Result{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if e.state == echoFailed {
		return icmpns.Result{}, 0, e.failure
	}
	if e.state != echoDone {
		return icmpns.Result{}, icmpns.NextWouldBlock, nil
	}
	copied := copy(dst, e.payload)
	result := icmpns.Result{
		Source: e.destination, Identifier: e.identifier, Sequence: e.sequence,
		Copied: copied, PayloadBytes: len(e.payload),
	}
	return result, icmpns.NextReady, nil
}

func (e *echo) Cancel() error {
	if e == nil || e.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	e.owner.core.Lock()
	defer e.owner.core.Unlock()
	if e.state == echoClosed || e.owner.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if e.state == echoDone || e.state == echoFailed {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	e.failLocked(nscore.FailureCanceled, errCanceled)
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
	if e.state == echoClosed {
		return nil
	}
	e.retireTransportLocked()
	e.state = echoClosed
	if e.owner != nil {
		removeEcho(e.owner, e)
	}
	clear(e.payload)
	e.payload = nil
	e.destination = netip.Addr{}
	e.identifier = 0
	e.sequence = 0
	e.attempts = 0
	e.failure = nil
	e.releaseWorkLocked()
	e.retained.Release()
	e.retained.ResetReleased()
	return nil
}

func (e *echo) retireTransportLocked() {
	if e == nil || e.owner == nil || e.identifier == 0 {
		return
	}
	key := identityKey(e.identifier, e.sequence)
	if e.owner.byIdentity[key] == e {
		delete(e.owner.byIdentity, key)
	}
	e.retry = 0
}

func (e *echo) completeLocked() {
	if e.state == echoClosed || e.state == echoDone || e.state == echoFailed {
		return
	}
	e.retireTransportLocked()
	e.state = echoDone
	e.releaseWorkLocked()
}

func (e *echo) failLocked(failure nscore.Failure, cause error) {
	if e.state == echoClosed || e.state == echoDone || e.state == echoFailed {
		return
	}
	e.retireTransportLocked()
	e.state = echoFailed
	e.failure = nscore.Fail(failure, cause)
	e.releaseWorkLocked()
}

func (e *echo) releaseWorkLocked() {
	e.work.Release()
	e.work.ResetReleased()
}

// CloseLocked releases every echo and retained allocation. The caller must
// hold the shared core lock.
func (a *Adapter) CloseLocked() {
	if a == nil {
		return
	}
	for len(a.echoes) > 0 {
		_ = a.echoes[len(a.echoes)-1].closeLocked()
	}
	clear(a.byIdentity)
	a.byIdentity = nil
	a.echoes = nil
	a.cursor = 0
}

func (a *Adapter) hasWorkLocked() bool {
	for _, exchange := range a.echoes {
		if exchange != nil && (exchange.state == echoPending || exchange.state == echoWaiting) {
			return true
		}
	}
	return false
}

// egressLocked performs one bounded exchange operation. worked may be true
// without a packet when a retry countdown or timeout transition completes.
func (a *Adapter) egressLocked(dst []byte) (written int, worked bool, err error) {
	if len(a.echoes) == 0 {
		return 0, false, nil
	}
	for offset := 0; offset < len(a.echoes); offset++ {
		index := a.cursor + offset
		if index >= len(a.echoes) {
			index -= len(a.echoes)
		}
		exchange := a.echoes[index]
		if exchange == nil || (exchange.state != echoPending && exchange.state != echoWaiting) {
			continue
		}
		a.cursor = index + 1
		if a.cursor == len(a.echoes) {
			a.cursor = 0
		}
		if exchange.state == echoWaiting {
			if exchange.retry > 1 {
				exchange.retry--
				return 0, true, nil
			}
			if exchange.attempts >= a.config.MaxAttempts {
				exchange.failLocked(nscore.FailureTimedOut, errReplyLimit)
				return 0, true, nil
			}
			exchange.state = echoPending
			return 0, true, nil
		}

		frameBytes := 14 + 20 + 8 + len(exchange.payload)
		if len(dst) < frameBytes {
			return 0, false, lneto.ErrShortBuffer
		}
		frame := dst[:frameBytes]
		clear(frame)
		ethernetFrame, _ := ethernet.NewFrame(frame)
		*ethernetFrame.DestinationHardwareAddr() = a.gatewayHardwareAddress
		*ethernetFrame.SourceHardwareAddr() = a.hardwareAddress
		ethernetFrame.SetEtherType(ethernet.TypeIPv4)
		ipFrame, _ := ipv4.NewFrame(frame[14:])
		ipFrame.SetVersionAndIHL(4, 5)
		ipFrame.SetTotalLength(uint16(20 + 8 + len(exchange.payload)))
		ipFrame.SetID(a.core.NextIPv4IDLocked())
		ipFrame.SetFlags(0)
		ipFrame.SetTTL(64)
		ipFrame.SetProtocol(lneto.IPProtoICMP)
		*ipFrame.SourceAddr() = a.core.IPv4AddressLocked().As4()
		*ipFrame.DestinationAddr() = exchange.destination.As4()
		ipFrame.SetCRC(0)
		ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
		icmpFrame, _ := lnetoicmp.NewFrame(frame[14+20:])
		echoFrame := lnetoicmp.FrameEcho{Frame: icmpFrame}
		echoFrame.SetType(lnetoicmp.TypeEcho)
		echoFrame.SetCode(0)
		echoFrame.SetIdentifier(exchange.identifier)
		echoFrame.SetSequenceNumber(exchange.sequence)
		copy(echoFrame.Data(), exchange.payload)
		echoFrame.SetCRC(0)
		var checksum lneto.CRC791
		echoFrame.SetCRC(checksum.PayloadSum16(echoFrame.RawData()))
		exchange.attempts++
		exchange.retry = a.config.RetryServiceAttempts
		exchange.state = echoWaiting
		return frameBytes, true, nil
	}
	return 0, false, nil
}

func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || ethernetFrame.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return false, err
	}
	if *ethernetFrame.DestinationHardwareAddr() != a.hardwareAddress {
		return false, nil
	}
	if !validUnicastMAC(*ethernetFrame.SourceHardwareAddr()) {
		return true, nil
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		return false, err
	}
	version, headerWords := ipFrame.VersionAndIHL()
	if version != 4 || headerWords < 5 || ipFrame.Protocol() != lneto.IPProtoICMP || netip.AddrFrom4(*ipFrame.DestinationAddr()) != a.core.IPv4AddressLocked() {
		return false, nil
	}
	var validator lneto.Validator
	ipFrame.ValidateExceptCRC(&validator)
	if err := validator.ErrPop(); err != nil || ipFrame.CalculateHeaderCRC() != 0 || ipFrame.Flags().MoreFragments() || ipFrame.Flags().FragmentOffset() != 0 {
		return false, nil
	}
	icmpFrame, err := lnetoicmp.NewFrame(ipFrame.Payload())
	if err != nil || icmpFrame.Type() != lnetoicmp.TypeEchoReply || icmpFrame.Code() != 0 {
		return false, nil
	}
	echoFrame := lnetoicmp.FrameEcho{Frame: icmpFrame}
	exchange := a.byIdentity[identityKey(echoFrame.Identifier(), echoFrame.SequenceNumber())]
	if exchange == nil || (exchange.state != echoPending && exchange.state != echoWaiting) || netip.AddrFrom4(*ipFrame.SourceAddr()) != exchange.destination {
		return false, nil
	}
	var checksum lneto.CRC791
	if checksum.PayloadSum16(echoFrame.RawData()) != 0 {
		exchange.failLocked(nscore.FailureIO, lneto.ErrBadCRC)
		return true, nil
	}
	if !bytes.Equal(echoFrame.Data(), exchange.payload) {
		exchange.failLocked(nscore.FailureIO, lneto.ErrMismatch)
		return true, nil
	}
	exchange.completeLocked()
	return true, nil
}

func (a *Adapter) allocateIdentityLocked() (uint16, uint16, bool) {
	attempts := int(a.config.MaxEchoes) + 1
	for range attempts {
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

func identityKey(identifier, sequence uint16) uint32 {
	return uint32(identifier)<<16 | uint32(sequence)
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ethernet.BroadcastAddr() && mac[0]&1 == 0
}

func removeEcho(owner *Adapter, target *echo) {
	if owner == nil {
		return
	}
	for i, exchange := range owner.echoes {
		if exchange != target {
			continue
		}
		copy(owner.echoes[i:], owner.echoes[i+1:])
		owner.echoes[len(owner.echoes)-1] = nil
		owner.echoes = owner.echoes[:len(owner.echoes)-1]
		if len(owner.echoes) == 0 {
			owner.cursor = 0
		} else if owner.cursor > i {
			owner.cursor--
		} else if owner.cursor >= len(owner.echoes) {
			owner.cursor = 0
		}
		return
	}
}
