// Package ntp implements bounded immediate NTP client synchronizations over one
// shared lneto namespace using only packet codecs and the immediate NTP client
// state machine. It never uses blocking transport, deadlines, sleeps, backoff,
// goroutines, or ambient wall-clock authority.
package ntp

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"time"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetontp "github.com/soypat/lneto/ntp"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ ntpns.Sync = (*syncResource)(nil)

const (
	firstEphemeralNTPPort uint16 = 54000
	serviceOrder                 = 7
	closeOrder                   = 7
)

var errPolicyDenied = errors.New("net: NTP policy denied operation")

// Config fixes one server, explicit clock, concurrent resources, transmission
// attempts, and service-attempt retry bounds. Zero MaxSyncs disables NTP
// truthfully and requires the complete zero value.
type Config struct {
	Server               netip.Addr
	Clock                ntpns.Clock
	MaxSyncs             uint16
	MaxAttempts          uint16
	RetryServiceAttempts uint16
	Precision            int8
}

// Adapter owns NTP wire state and bounded service participation.
type Adapter struct {
	core                   *lnetocore.Namespace
	config                 Config
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte
	policy                 *policy.Policy
	quotas                 *quota.Account
	syncs                  []*syncResource
	byPort                 map[uint16]*syncResource
	cursor                 int
	nextPort               uint16
}

type syncState uint8

const (
	syncPrepare syncState = iota + 1
	syncSend
	syncWaiting
	syncDone
	syncFailed
	syncClosed
)

type syncResource struct {
	owner       *Adapter
	client      lnetontp.Client
	clockSample time.Time
	request     [lnetontp.SizeHeader]byte
	sample      ntpns.Sample
	failure     error
	state       syncState
	attempts    uint16
	retry       uint16

	portLease lnetocore.UDPPortLease
	retained  quota.Charge
	work      quota.Charge
}

// New attaches NTP-local state and its immediate packet participant.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || !ValidConfig(config, common.PolicyLocked(), common.QuotasLocked(), true) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	adapter := &Adapter{
		core: common, config: config,
		hardwareAddress:        common.HardwareAddressLocked(),
		gatewayHardwareAddress: common.GatewayHardwareAddressLocked(), policy: common.PolicyLocked(), quotas: common.QuotasLocked(),
		syncs: make([]*syncResource, 0, config.MaxSyncs), byPort: make(map[uint16]*syncResource, config.MaxSyncs),
		nextPort: firstEphemeralNTPPort,
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

// ValidConfig validates NTP-local authority and deterministic work bounds.
func ValidConfig(config Config, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxSyncs == 0 {
		return !config.Server.IsValid() && config.Clock == nil && config.MaxAttempts == 0 && config.RetryServiceAttempts == 0 && config.Precision == 0
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	limitedBroadcast := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	return config.Server.Is4() && !config.Server.Is4In6() && !config.Server.IsUnspecified() && config.Server.Zone() == "" &&
		!config.Server.IsMulticast() && config.Server != limitedBroadcast && usableClock(config.Clock) &&
		config.MaxAttempts > 0 && config.RetryServiceAttempts > 0 && config.Precision >= -30 && config.Precision <= 0
}

// TrySync immediately validates authority and creates one finite two-exchange
// synchronization resource.
func (a *Adapter) TrySync() (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if a.config.MaxSyncs == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !a.policy.CheckEndpoint(policy.OperationNTPSync, a.config.Server, lnetontp.ServerPort) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(a.syncs) == int(a.config.MaxSyncs) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	now := a.config.Clock.Now().UTC()
	if _, err := lnetontp.TimestampFromTime(now); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	sync := &syncResource{owner: a, state: syncPrepare}
	if !a.allocatePortLocked(&sync.portLease) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	if err := a.quotas.AcquireResource(&sync.retained, quota.ResourceNTP, 1); err != nil {
		sync.portLease.ReleaseLocked()
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireNTPWork(&sync.work, 1); err != nil {
		sync.retained.Release()
		sync.retained.ResetReleased()
		sync.portLease.ReleaseLocked()
		return nil, 0, lnetocore.MapError(err)
	}
	sync.client.Reset(a.config.Precision, sync.clockNow)
	port := sync.portLease.UDPPort()
	a.byPort[port] = sync
	a.syncs = append(a.syncs, sync)
	return sync, nscore.ProgressInProgress, nil
}

func (s *syncResource) clockNow() time.Time {
	return s.clockSample
}

func (s *syncResource) Readiness() nscore.Readiness {
	if s == nil || s.owner == nil {
		return nscore.ReadyClosed
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.state == syncClosed || s.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if s.state == syncFailed {
		return nscore.ReadyError
	}
	if s.state == syncDone {
		return nscore.ReadyNTPResult
	}
	return 0
}

func (s *syncResource) TryResult() (ntpns.Sample, ntpns.Next, error) {
	if s == nil || s.owner == nil {
		return ntpns.Sample{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.state == syncClosed || s.owner.core.ClosedLocked() {
		return ntpns.Sample{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if s.state == syncFailed {
		return ntpns.Sample{}, 0, s.failure
	}
	if s.state != syncDone {
		return ntpns.Sample{}, ntpns.NextWouldBlock, nil
	}
	return s.sample, ntpns.NextReady, nil
}

func (s *syncResource) Cancel() error {
	if s == nil || s.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.state == syncClosed || s.owner.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if s.state == syncDone || s.state == syncFailed {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	s.failLocked(nscore.FailureCanceled, errors.New("NTP synchronization canceled"))
	return nil
}

func (s *syncResource) Close() error {
	if s == nil || s.owner == nil {
		return nil
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	return s.closeLocked()
}

func (s *syncResource) closeLocked() error {
	if s.state == syncClosed {
		return nil
	}
	s.retireTransportLocked()
	s.state = syncClosed
	if s.owner != nil {
		removeSync(s.owner, s)
	}
	clear(s.request[:])
	s.sample = ntpns.Sample{}
	s.clockSample = time.Time{}
	s.failure = nil
	s.attempts = 0
	s.releaseWorkLocked()
	s.retained.Release()
	s.retained.ResetReleased()
	s.client = lnetontp.Client{}
	return nil
}

func (s *syncResource) retireTransportLocked() {
	if s == nil {
		return
	}
	port := s.portLease.UDPPort()
	if s.owner != nil && port != 0 && s.owner.byPort[port] == s {
		delete(s.owner.byPort, port)
	}
	s.portLease.ReleaseLocked()
	s.retry = 0
}

func (s *syncResource) completeLocked(sample ntpns.Sample) {
	if s.state == syncClosed || s.state == syncDone || s.state == syncFailed {
		return
	}
	s.retireTransportLocked()
	s.sample = sample
	s.state = syncDone
	s.releaseWorkLocked()
}

func (s *syncResource) failLocked(failure nscore.Failure, cause error) {
	if s.state == syncClosed || s.state == syncDone || s.state == syncFailed {
		return
	}
	s.retireTransportLocked()
	s.state = syncFailed
	s.failure = nscore.Fail(failure, cause)
	s.releaseWorkLocked()
}

func (s *syncResource) releaseWorkLocked() {
	s.work.Release()
	s.work.ResetReleased()
}

// CloseLocked releases every synchronization and retained allocation. The
// caller must hold the shared core lock.
func (a *Adapter) CloseLocked() {
	if a == nil {
		return
	}
	for len(a.syncs) > 0 {
		_ = a.syncs[len(a.syncs)-1].closeLocked()
	}
	clear(a.byPort)
	a.byPort = nil
	a.syncs = nil
	a.cursor = 0
}

func (a *Adapter) hasWorkLocked() bool {
	for _, sync := range a.syncs {
		if sync != nil && (sync.state == syncPrepare || sync.state == syncSend || sync.state == syncWaiting) {
			return true
		}
	}
	return false
}

// egressLocked performs one bounded synchronization operation. worked may be
// true without a packet when a retry countdown or timeout transition completes.
func (a *Adapter) egressLocked(dst []byte) (written int, worked bool, err error) {
	if len(a.syncs) == 0 {
		return 0, false, nil
	}
	for offset := 0; offset < len(a.syncs); offset++ {
		index := a.cursor + offset
		if index >= len(a.syncs) {
			index -= len(a.syncs)
		}
		sync := a.syncs[index]
		if sync == nil || (sync.state != syncPrepare && sync.state != syncSend && sync.state != syncWaiting) {
			continue
		}
		a.cursor = index + 1
		if a.cursor == len(a.syncs) {
			a.cursor = 0
		}
		if sync.state == syncWaiting {
			if sync.retry > 1 {
				sync.retry--
				return 0, true, nil
			}
			if sync.attempts >= a.config.MaxAttempts {
				sync.failLocked(nscore.FailureTimedOut, errors.New("NTP response service-attempt limit reached"))
				return 0, true, nil
			}
			sync.state = syncSend
			return 0, true, nil
		}
		if sync.state == syncPrepare {
			sync.clockSample = a.config.Clock.Now().UTC()
			if _, clockErr := lnetontp.TimestampFromTime(sync.clockSample); clockErr != nil {
				sync.failLocked(nscore.FailureInvalidState, clockErr)
				return 0, true, nil
			}
			clear(sync.request[:])
			n, encodeErr := sync.client.Encapsulate(sync.request[:], 0, 0)
			if encodeErr != nil {
				sync.failLocked(nscore.FailureInvalidState, encodeErr)
				return 0, true, nil
			}
			if n != lnetontp.SizeHeader {
				sync.failLocked(nscore.FailureIO, lneto.ErrMismatchLen)
				return 0, true, nil
			}
			sync.attempts = 0
			sync.state = syncSend
		}

		frameBytes := 14 + 20 + 8 + lnetontp.SizeHeader
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
		ipFrame.SetTotalLength(uint16(20 + 8 + lnetontp.SizeHeader))
		ipFrame.SetID(a.core.NextIPv4IDLocked())
		ipFrame.SetFlags(0)
		ipFrame.SetTTL(64)
		ipFrame.SetProtocol(lneto.IPProtoUDP)
		*ipFrame.SourceAddr() = a.core.IPv4AddressLocked().As4()
		*ipFrame.DestinationAddr() = a.config.Server.As4()
		ipFrame.SetCRC(0)
		ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
		udpFrame, _ := lnetoudp.NewFrame(frame[14+20:])
		udpFrame.SetSourcePort(sync.portLease.UDPPort())
		udpFrame.SetDestinationPort(lnetontp.ServerPort)
		udpFrame.SetLength(uint16(8 + lnetontp.SizeHeader))
		copy(frame[14+20+8:], sync.request[:])
		udpFrame.SetCRC(0)
		var checksum lneto.CRC791
		ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
		udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
		sync.attempts++
		sync.retry = a.config.RetryServiceAttempts
		sync.state = syncWaiting
		return frameBytes, true, nil
	}
	return 0, false, nil
}

func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || ethernetFrame.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return false, err
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		return false, err
	}
	version, headerWords := ipFrame.VersionAndIHL()
	if version != 4 || headerWords < 5 || ipFrame.Protocol() != lneto.IPProtoUDP || netip.AddrFrom4(*ipFrame.DestinationAddr()) != a.core.IPv4AddressLocked() {
		return false, nil
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		return false, nil
	}
	sync := a.byPort[udpFrame.DestinationPort()]
	if sync == nil || sync.state != syncWaiting || netip.AddrFrom4(*ipFrame.SourceAddr()) != a.config.Server || udpFrame.SourcePort() != lnetontp.ServerPort {
		return false, nil
	}
	var validator lneto.Validator
	ipFrame.ValidateExceptCRC(&validator)
	if err := validator.ErrPop(); err != nil {
		sync.failLocked(nscore.FailureIO, err)
		return true, nil
	}
	if ipFrame.CalculateHeaderCRC() != 0 || ipFrame.Flags().MoreFragments() || ipFrame.Flags().FragmentOffset() != 0 {
		sync.failLocked(nscore.FailureIO, lneto.ErrBadCRC)
		return true, nil
	}
	udpFrame.ValidateSize(&validator)
	if err := validator.ErrPop(); err != nil {
		sync.failLocked(nscore.FailureIO, err)
		return true, nil
	}
	udpLength := udpFrame.Length()
	if udpFrame.CRC() != 0 {
		var checksum lneto.CRC791
		ipFrame.CRCWriteUDPPseudo(&checksum, udpLength)
		if checksum.PayloadSum16(udpFrame.RawData()[:udpLength]) != 0 {
			sync.failLocked(nscore.FailureIO, lneto.ErrBadCRC)
			return true, nil
		}
	}
	payload := udpFrame.RawData()[8:udpLength]
	if len(payload) != lnetontp.SizeHeader {
		sync.failLocked(nscore.FailureMessageTooLarge, lneto.ErrMismatchLen)
		return true, nil
	}
	ntpFrame, err := lnetontp.NewFrame(payload)
	if err != nil {
		sync.failLocked(nscore.FailureIO, err)
		return true, nil
	}
	mode, ntpVersion, leap := ntpFrame.Flags()
	stratum := ntpFrame.Stratum()
	if mode != lnetontp.ModeServer || ntpVersion != lnetontp.Version4 || leap >= 3 || stratum == 0 || stratum >= lnetontp.StratumUnsync || ntpFrame.ReceiveTime().IsZero() || ntpFrame.TransmitTime().IsZero() {
		sync.failLocked(nscore.FailureTemporary, lneto.ErrInvalidField)
		return true, nil
	}
	sync.clockSample = a.config.Clock.Now().UTC()
	if _, clockErr := lnetontp.TimestampFromTime(sync.clockSample); clockErr != nil {
		sync.failLocked(nscore.FailureInvalidState, clockErr)
		return true, nil
	}
	requestFrame, _ := lnetontp.NewFrame(sync.request[:])
	if sync.clockSample.Before(requestFrame.TransmitTime().Time()) {
		sync.failLocked(nscore.FailureInvalidState, errors.New("NTP host clock moved backward during exchange"))
		return true, nil
	}
	if err := sync.client.Demux(payload, 0); err != nil {
		if errors.Is(err, lneto.ErrPacketDrop) {
			return true, nil
		}
		sync.failLocked(nscore.FailureIO, err)
		return true, nil
	}
	if !sync.client.IsDone() {
		sync.state = syncPrepare
		sync.attempts = 0
		sync.retry = 0
		return true, nil
	}
	rtt := sync.client.RoundTripDelay()
	offset := sync.client.Offset()
	corrected := sync.clockSample.Add(offset)
	sample := ntpns.Sample{
		Server: a.config.Server, CorrectedTime: corrected, Offset: offset, RoundTripDelay: rtt,
		Stratum: uint8(stratum), Leap: uint8(leap), Version: ntpVersion, ReferenceID: *ntpFrame.ReferenceID(),
	}
	if !sample.Valid() {
		sync.failLocked(nscore.FailureTemporary, lneto.ErrInvalidField)
		return true, nil
	}
	sync.completeLocked(sample)
	return true, nil
}

func usableClock(clock ntpns.Clock) bool {
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

func (a *Adapter) allocatePortLocked(lease *lnetocore.UDPPortLease) bool {
	attempts := int(a.config.MaxSyncs) + a.core.UDPPortLeaseCountLocked() + 1
	next, ok := a.core.TryLeaseUDPPortRangeIntoLocked(lease, a.nextPort, firstEphemeralNTPPort, attempts)
	if ok {
		a.nextPort = next
	}
	return ok
}

func removeSync(owner *Adapter, target *syncResource) {
	if owner == nil {
		return
	}
	for i, sync := range owner.syncs {
		if sync != target {
			continue
		}
		copy(owner.syncs[i:], owner.syncs[i+1:])
		owner.syncs[len(owner.syncs)-1] = nil
		owner.syncs = owner.syncs[:len(owner.syncs)-1]
		if len(owner.syncs) == 0 {
			owner.cursor = 0
		} else if owner.cursor > i {
			owner.cursor--
		} else if owner.cursor >= len(owner.syncs) {
			owner.cursor = 0
		}
		return
	}
}
