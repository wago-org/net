// Package mdns implements bounded immediate IPv4 multicast DNS queries,
// configured service responses, and announcements over one shared lneto core.
// It uses only exported Ethernet II, IPv4, UDP, and DNS packet codecs.
package mdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"

	lneto "github.com/soypat/lneto"
	lnetodns "github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var (
	_ mdnsns.Query        = (*query)(nil)
	_ mdnsns.Announcement = (*announcement)(nil)
)

const (
	Port         uint16 = 5353
	serviceOrder        = 8
	closeOrder          = 8
	cacheFlush   uint16 = 1 << 15
)

var (
	multicastAddress        = netip.AddrFrom4([4]byte{224, 0, 0, 251})
	limitedBroadcastAddress = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	multicastMAC            = [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}
	errPolicyDenied         = errors.New("net: mDNS policy denied operation")
	errPortInUse            = errors.New("net: mDNS UDP port 5353 is already owned")
	errQueryCanceled        = errors.New("mDNS query canceled")
	errAnnouncementCancel   = errors.New("mDNS announcement canceled")
	errResponseLimit        = errors.New("mDNS response service-attempt limit reached")
)

// Config fixes every retained service, operation, packet, retry, parse, and
// automatic-response dimension. The exact zero value disables mDNS.
type Config struct {
	Services              []mdnsns.Service
	MaxServices           uint16
	MaxQueries            uint16
	MaxAnnouncements      uint16
	MaxRecords            uint16
	MaxPacketBytes        int
	MaxQueuedResponses    uint16
	MaxQuestionsPerPacket uint16
	MaxRecordsPerPacket   uint16
	MaxAttempts           uint16
	RetryServiceAttempts  uint16
}

type Adapter struct {
	core            *lnetocore.Namespace
	config          Config
	hardwareAddress [6]byte
	policy          *policy.Policy
	quotas          *quota.Account
	portLease       lnetocore.UDPPortLease
	queueCharge     quota.Charge

	services         []mdnsns.Service
	serviceResources [][]lnetodns.Resource
	queries          []*query
	announcements    []*announcement
	cursor           int

	decode            lnetodns.Message
	responseResources []lnetodns.Resource

	responseSlots [][]byte
	responseHead  int
	responseCount int
}

type operationState uint8

const (
	statePending operationState = iota + 1
	stateWaiting
	stateDone
	stateFailed
	stateClosed
)

type query struct {
	owner    *Adapter
	request  mdnsns.Request
	packet   []byte
	records  []mdnsns.Record
	cursor   int
	state    operationState
	attempts uint16
	retry    uint16
	failure  error
	retained quota.Charge
	work     quota.Charge
}

type announcement struct {
	owner    *Adapter
	service  uint16
	packet   []byte
	state    operationState
	attempts uint16
	retry    uint16
	failure  error
	retained quota.Charge
	work     quota.Charge
}

func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || !ValidConfig(config, common.RequiredFrameBytesLocked()-14, common.PolicyLocked(), common.QuotasLocked(), true) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	a := &Adapter{
		core: common, config: cloneConfig(config), hardwareAddress: common.HardwareAddressLocked(),
		policy: common.PolicyLocked(), quotas: common.QuotasLocked(),
	}
	if zeroConfig(config) {
		common.Unlock()
		return a, nil
	}
	a.queries = make([]*query, 0, config.MaxQueries)
	a.announcements = make([]*announcement, 0, config.MaxAnnouncements)
	a.services = a.config.Services
	if len(a.services) != 0 {
		a.serviceResources = make([][]lnetodns.Resource, len(a.services))
		for i := range a.services {
			resources, err := serviceResources(a.services[i], 0)
			if err != nil {
				common.Unlock()
				return nil, lnetocore.MapError(err)
			}
			a.serviceResources[i] = resources
		}
		a.responseResources = make([]lnetodns.Resource, 0, config.MaxRecordsPerPacket)
	}
	if config.MaxQueries != 0 || len(config.Services) != 0 {
		if !common.TryLeaseUDPPortIntoLocked(&a.portLease, Port) {
			common.Unlock()
			return nil, nscore.Fail(nscore.FailureAddressInUse, errPortInUse)
		}
	}
	if config.MaxQueuedResponses != 0 {
		bytes := uint64(config.MaxQueuedResponses) * uint64(config.MaxPacketBytes)
		if err := a.quotas.AcquireQueuedBytes(&a.queueCharge, bytes); err != nil {
			a.portLease.ReleaseLocked()
			common.Unlock()
			return nil, lnetocore.MapError(err)
		}
		a.responseSlots = make([][]byte, config.MaxQueuedResponses)
		for i := range a.responseSlots {
			a.responseSlots[i] = make([]byte, 0, config.MaxPacketBytes)
		}
	}
	a.decode.LimitResourceDecoding(config.MaxQuestionsPerPacket, config.MaxRecordsPerPacket, config.MaxRecordsPerPacket, config.MaxRecordsPerPacket)
	common.Unlock()
	if err := common.Install(lnetocore.Participant{
		IngressOrder: serviceOrder, Ingress: a.ingressLocked,
		EgressOrder: serviceOrder, HasEgress: a.hasWorkLocked, Egress: a.egressLocked,
		CloseOrder: closeOrder, Close: a.CloseLocked,
	}); err != nil {
		common.Lock()
		a.CloseLocked()
		common.Unlock()
		return nil, err
	}
	return a, nil
}

func ValidConfig(config Config, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxQueries == 0 && len(config.Services) == 0 && config.MaxAnnouncements == 0 {
		return zeroConfig(config)
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	if config.MaxQueries == 0 && len(config.Services) == 0 || config.MaxServices < uint16(len(config.Services)) ||
		config.MaxRecords == 0 || config.MaxPacketBytes < lnetodns.MaxSizeUDP || config.MaxPacketBytes > mtu-28 ||
		config.MaxQuestionsPerPacket == 0 || config.MaxRecordsPerPacket == 0 || config.MaxAttempts == 0 || config.RetryServiceAttempts == 0 {
		return false
	}
	if len(config.Services) == 0 {
		if config.MaxServices != 0 || config.MaxAnnouncements != 0 || config.MaxQueuedResponses != 0 {
			return false
		}
	} else if config.MaxServices == 0 || config.MaxAnnouncements == 0 || config.MaxQueuedResponses == 0 {
		return false
	}
	for _, service := range config.Services {
		if !service.Valid() {
			return false
		}
	}
	return true
}

func zeroConfig(config Config) bool {
	return len(config.Services) == 0 && config.MaxServices == 0 && config.MaxQueries == 0 && config.MaxAnnouncements == 0 &&
		config.MaxRecords == 0 && config.MaxPacketBytes == 0 && config.MaxQueuedResponses == 0 && config.MaxQuestionsPerPacket == 0 &&
		config.MaxRecordsPerPacket == 0 && config.MaxAttempts == 0 && config.RetryServiceAttempts == 0
}

func cloneConfig(config Config) Config {
	cloned := config
	cloned.Services = append([]mdnsns.Service(nil), config.Services...)
	return cloned
}

func (a *Adapter) TryQuery(request mdnsns.Request) (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if a.config.MaxQueries == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !request.Valid() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if !a.policy.CheckDNS(policy.OperationMDNSQuery, request.Name) || !a.policy.CheckEndpoint(policy.OperationMDNSSend, multicastAddress, Port) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(a.queries) == int(a.config.MaxQueries) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	request.Name = strings.Clone(request.Name)
	packet, err := buildQueryPacket(request, a.config.MaxPacketBytes)
	if err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	q := &query{owner: a, request: request, packet: packet, records: make([]mdnsns.Record, 0, a.config.MaxRecords), state: statePending}
	if err := a.quotas.AcquireResourceAndQueuedBytes(&q.retained, quota.ResourceMDNS, 1, queryRetainedBytes(a.config)); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireMDNSWork(&q.work, 1); err != nil {
		q.retained.Release()
		q.retained.ResetReleased()
		return nil, 0, lnetocore.MapError(err)
	}
	a.queries = append(a.queries, q)
	return q, nscore.ProgressInProgress, nil
}

func (a *Adapter) TryAnnounce(service uint16) (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if a.config.MaxAnnouncements == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if int(service) >= len(a.services) {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	selected := a.services[service]
	if !a.policy.CheckDNS(policy.OperationMDNSRespond, selected.Name) || !a.policy.CheckDNS(policy.OperationMDNSRespond, selected.Host) ||
		!a.policy.CheckEndpoint(policy.OperationMDNSSend, multicastAddress, Port) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(a.announcements) == int(a.config.MaxAnnouncements) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	packet, err := buildServicePacket(selected, 0, a.config.MaxPacketBytes)
	if err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	ann := &announcement{owner: a, service: service, packet: packet, state: statePending}
	if err := a.quotas.AcquireResourceAndQueuedBytes(&ann.retained, quota.ResourceMDNS, 1, uint64(a.config.MaxPacketBytes)); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireMDNSWork(&ann.work, 1); err != nil {
		ann.retained.Release()
		ann.retained.ResetReleased()
		return nil, 0, lnetocore.MapError(err)
	}
	a.announcements = append(a.announcements, ann)
	return ann, nscore.ProgressInProgress, nil
}

func (q *query) Readiness() nscore.Readiness {
	if q == nil || q.owner == nil {
		return nscore.ReadyClosed
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	if q.state == stateClosed || q.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if q.state == stateFailed {
		return nscore.ReadyError
	}
	if q.state == stateDone {
		return nscore.ReadyMDNSResult
	}
	return 0
}

func (q *query) TryNext() (mdnsns.Record, mdnsns.Next, error) {
	if q == nil || q.owner == nil {
		return mdnsns.Record{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	if q.state == stateClosed || q.owner.core.ClosedLocked() {
		return mdnsns.Record{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if q.state == stateFailed {
		return mdnsns.Record{}, 0, q.failure
	}
	if q.cursor < len(q.records) {
		record := q.records[q.cursor]
		q.cursor++
		if !record.Valid() {
			return mdnsns.Record{}, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
		}
		return record, mdnsns.NextReady, nil
	}
	if q.state == stateDone {
		return mdnsns.Record{}, mdnsns.NextEOF, nil
	}
	return mdnsns.Record{}, mdnsns.NextWouldBlock, nil
}

func (q *query) Cancel() error {
	if q == nil || q.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	if q.state == stateClosed || q.owner.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if q.state == stateDone || q.state == stateFailed {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	q.failLocked(nscore.FailureCanceled, errQueryCanceled)
	return nil
}

func (q *query) Close() error {
	if q == nil || q.owner == nil {
		return nil
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	return q.closeLocked()
}

func (q *query) closeLocked() error {
	if q.state == stateClosed {
		return nil
	}
	q.state = stateClosed
	if q.owner != nil {
		removeQuery(q.owner, q)
	}
	clear(q.packet)
	q.packet = nil
	clear(q.records)
	q.records = nil
	q.request = mdnsns.Request{}
	q.failure = nil
	q.releaseWorkLocked()
	q.retained.Release()
	q.retained.ResetReleased()
	return nil
}

func (q *query) failLocked(failure nscore.Failure, cause error) {
	if q.state == stateDone || q.state == stateFailed || q.state == stateClosed {
		return
	}
	q.state = stateFailed
	q.failure = nscore.Fail(failure, cause)
	q.retry = 0
	q.releaseWorkLocked()
}

func (q *query) completeLocked(records []mdnsns.Record) {
	if q.state == stateDone || q.state == stateFailed || q.state == stateClosed {
		return
	}
	q.records = append(q.records[:0], records...)
	q.cursor = 0
	q.state = stateDone
	q.retry = 0
	q.releaseWorkLocked()
}

func (q *query) releaseWorkLocked() {
	q.work.Release()
	q.work.ResetReleased()
}

func (a *announcement) Readiness() nscore.Readiness {
	if a == nil || a.owner == nil {
		return nscore.ReadyClosed
	}
	a.owner.core.Lock()
	defer a.owner.core.Unlock()
	if a.state == stateClosed || a.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if a.state == stateFailed {
		return nscore.ReadyError
	}
	if a.state == stateDone {
		return nscore.ReadyMDNSAnnouncement
	}
	return 0
}

func (a *announcement) TryFinish() (mdnsns.Next, error) {
	if a == nil || a.owner == nil {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.owner.core.Lock()
	defer a.owner.core.Unlock()
	if a.state == stateClosed || a.owner.core.ClosedLocked() {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if a.state == stateFailed {
		return 0, a.failure
	}
	if a.state == stateDone {
		return mdnsns.NextReady, nil
	}
	return mdnsns.NextWouldBlock, nil
}

func (a *announcement) Cancel() error {
	if a == nil || a.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.owner.core.Lock()
	defer a.owner.core.Unlock()
	if a.state == stateClosed || a.owner.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if a.state == stateDone || a.state == stateFailed {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	a.failLocked(nscore.FailureCanceled, errAnnouncementCancel)
	return nil
}

func (a *announcement) Close() error {
	if a == nil || a.owner == nil {
		return nil
	}
	a.owner.core.Lock()
	defer a.owner.core.Unlock()
	return a.closeLocked()
}

func (a *announcement) closeLocked() error {
	if a.state == stateClosed {
		return nil
	}
	a.state = stateClosed
	if a.owner != nil {
		removeAnnouncement(a.owner, a)
	}
	clear(a.packet)
	a.packet = nil
	a.failure = nil
	a.releaseWorkLocked()
	a.retained.Release()
	a.retained.ResetReleased()
	return nil
}

func (a *announcement) failLocked(failure nscore.Failure, cause error) {
	if a.state == stateDone || a.state == stateFailed || a.state == stateClosed {
		return
	}
	a.state = stateFailed
	a.failure = nscore.Fail(failure, cause)
	a.retry = 0
	a.releaseWorkLocked()
}

func (a *announcement) completeLocked() {
	if a.state == stateDone || a.state == stateFailed || a.state == stateClosed {
		return
	}
	a.state = stateDone
	a.retry = 0
	a.releaseWorkLocked()
}

func (a *announcement) releaseWorkLocked() {
	a.work.Release()
	a.work.ResetReleased()
}

func (a *Adapter) CloseLocked() {
	if a == nil {
		return
	}
	for len(a.announcements) > 0 {
		_ = a.announcements[len(a.announcements)-1].closeLocked()
	}
	for len(a.queries) > 0 {
		_ = a.queries[len(a.queries)-1].closeLocked()
	}
	for i := range a.responseSlots {
		clear(a.responseSlots[i])
		a.responseSlots[i] = nil
	}
	a.responseSlots = nil
	a.responseCount = 0
	a.responseHead = 0
	a.decode.Reset()
	for i := range a.serviceResources {
		clear(a.serviceResources[i])
		a.serviceResources[i] = nil
	}
	a.serviceResources = nil
	clear(a.responseResources)
	a.responseResources = nil
	clear(a.services)
	a.services = nil
	a.portLease.ReleaseLocked()
	a.queueCharge.Release()
	a.queueCharge.ResetReleased()
}

func (a *Adapter) hasWorkLocked() bool {
	if a.responseCount != 0 {
		return true
	}
	for _, q := range a.queries {
		if q.state == statePending || q.state == stateWaiting {
			return true
		}
	}
	for _, ann := range a.announcements {
		if ann.state == statePending || ann.state == stateWaiting {
			return true
		}
	}
	return false
}

func (a *Adapter) egressLocked(dst []byte) (int, bool, error) {
	if a.responseCount != 0 {
		packet := a.responseSlots[a.responseHead]
		n, err := a.writeFrame(dst, packet)
		if err != nil {
			return 0, false, err
		}
		clear(packet)
		a.responseSlots[a.responseHead] = packet[:0]
		a.responseHead = (a.responseHead + 1) % len(a.responseSlots)
		a.responseCount--
		return n, true, nil
	}
	total := len(a.queries) + len(a.announcements)
	if total == 0 {
		return 0, false, nil
	}
	for offset := 0; offset < total; offset++ {
		index := (a.cursor + offset) % total
		if index < len(a.queries) {
			q := a.queries[index]
			if q.state != statePending && q.state != stateWaiting {
				continue
			}
			if q.state == stateWaiting {
				a.cursor = (index + 1) % total
				if q.retry > 1 {
					q.retry--
					return 0, true, nil
				}
				if q.attempts >= a.config.MaxAttempts {
					q.failLocked(nscore.FailureTimedOut, errResponseLimit)
					return 0, true, nil
				}
				q.state = statePending
				return 0, true, nil
			}
			n, err := a.writeFrame(dst, q.packet)
			if err != nil {
				return 0, false, err
			}
			a.cursor = (index + 1) % total
			q.attempts++
			q.retry = a.config.RetryServiceAttempts
			q.state = stateWaiting
			return n, true, nil
		}
		ann := a.announcements[index-len(a.queries)]
		if ann.state != statePending && ann.state != stateWaiting {
			continue
		}
		if ann.state == stateWaiting {
			a.cursor = (index + 1) % total
			if ann.retry > 1 {
				ann.retry--
				return 0, true, nil
			}
			ann.state = statePending
			return 0, true, nil
		}
		n, err := a.writeFrame(dst, ann.packet)
		if err != nil {
			return 0, false, err
		}
		a.cursor = (index + 1) % total
		ann.attempts++
		if ann.attempts >= a.config.MaxAttempts {
			ann.completeLocked()
		} else {
			ann.retry = a.config.RetryServiceAttempts
			ann.state = stateWaiting
		}
		return n, true, nil
	}
	return 0, false, nil
}

func (a *Adapter) writeFrame(dst, packet []byte) (int, error) {
	frameBytes := 14 + 20 + 8 + len(packet)
	if len(dst) < frameBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:frameBytes]
	clear(frame)
	eth, _ := ethernet.NewFrame(frame)
	*eth.DestinationHardwareAddr() = multicastMAC
	*eth.SourceHardwareAddr() = a.hardwareAddress
	eth.SetEtherType(ethernet.TypeIPv4)
	ip, _ := ipv4.NewFrame(frame[14:])
	ip.SetVersionAndIHL(4, 5)
	ip.SetTotalLength(uint16(20 + 8 + len(packet)))
	ip.SetID(a.core.NextIPv4IDLocked())
	ip.SetFlags(0)
	ip.SetTTL(255)
	ip.SetProtocol(lneto.IPProtoUDP)
	*ip.SourceAddr() = a.core.IPv4AddressLocked().As4()
	*ip.DestinationAddr() = multicastAddress.As4()
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp, _ := lnetoudp.NewFrame(frame[34:])
	udp.SetSourcePort(Port)
	udp.SetDestinationPort(Port)
	udp.SetLength(uint16(8 + len(packet)))
	copy(frame[42:], packet)
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frameBytes, nil
}

func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	payload, source, matched, err := a.validateFrame(frame)
	if !matched {
		return false, err
	}
	if err != nil {
		return true, nil
	}
	_ = source
	dnsFrame, err := lnetodns.NewFrame(payload)
	if err != nil {
		return true, nil
	}
	if dnsFrame.TxID() != 0 || dnsFrame.QDCount() > a.config.MaxQuestionsPerPacket ||
		dnsFrame.ANCount() > a.config.MaxRecordsPerPacket || dnsFrame.NSCount() > a.config.MaxRecordsPerPacket || dnsFrame.ARCount() > a.config.MaxRecordsPerPacket ||
		uint32(dnsFrame.ANCount())+uint32(dnsFrame.NSCount())+uint32(dnsFrame.ARCount()) > uint32(a.config.MaxRecordsPerPacket) {
		return true, nil
	}
	a.decode.Reset()
	_, incomplete, err := a.decode.Decode(payload)
	if err != nil || incomplete {
		return true, nil
	}
	flags := dnsFrame.Flags()
	if flags.OpCode() != lnetodns.OpCodeQuery || flags.IsTruncated() {
		return true, nil
	}
	if flags.IsResponse() {
		if !flags.IsAuthorativeAnswer() || flags.ResponseCode() != lnetodns.RCodeSuccess {
			return true, nil
		}
		a.acceptResponseLocked()
	} else {
		a.queueResponseLocked()
	}
	return true, nil
}

func (a *Adapter) validateFrame(frame []byte) ([]byte, netip.Addr, bool, error) {
	eth, err := ethernet.NewFrame(frame)
	if err != nil || eth.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return nil, netip.Addr{}, false, err
	}
	destinationMAC := *eth.DestinationHardwareAddr()
	if destinationMAC != multicastMAC && destinationMAC != a.hardwareAddress {
		return nil, netip.Addr{}, false, nil
	}
	if !validUnicastMAC(*eth.SourceHardwareAddr()) {
		return nil, netip.Addr{}, true, lneto.ErrInvalidAddr
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		return nil, netip.Addr{}, false, err
	}
	version, ihl := ip.VersionAndIHL()
	destination := netip.AddrFrom4(*ip.DestinationAddr())
	if ip.Protocol() != lneto.IPProtoUDP || (destination != multicastAddress && destination != a.core.IPv4AddressLocked()) {
		return nil, netip.Addr{}, false, nil
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		return nil, netip.Addr{}, true, err
	}
	if udp.SourcePort() != Port || udp.DestinationPort() != Port {
		return nil, netip.Addr{}, false, nil
	}
	if version != 4 || ihl < 5 || ip.TTL() != 255 {
		return nil, netip.Addr{}, true, lneto.ErrBadState
	}
	var validator lneto.Validator
	ip.ValidateExceptCRC(&validator)
	if validator.ErrPop() != nil || ip.CalculateHeaderCRC() != 0 || ip.Flags().MoreFragments() || ip.Flags().FragmentOffset() != 0 {
		return nil, netip.Addr{}, true, lneto.ErrBadCRC
	}
	udp.ValidateSize(&validator)
	if err := validator.ErrPop(); err != nil {
		return nil, netip.Addr{}, true, err
	}
	length := udp.Length()
	if int(length)-8 > a.config.MaxPacketBytes {
		return nil, netip.Addr{}, true, lneto.ErrShortBuffer
	}
	if udp.CRC() != 0 {
		var checksum lneto.CRC791
		ip.CRCWriteUDPPseudo(&checksum, length)
		if checksum.PayloadSum16(udp.RawData()[:length]) != 0 {
			return nil, netip.Addr{}, true, lneto.ErrBadCRC
		}
	}
	source := netip.AddrFrom4(*ip.SourceAddr())
	if source.IsUnspecified() || source.IsLoopback() || source.IsMulticast() || source == limitedBroadcastAddress {
		return nil, netip.Addr{}, true, lneto.ErrInvalidAddr
	}
	return udp.RawData()[8:length], source, true, nil
}

func (a *Adapter) acceptResponseLocked() {
	for _, q := range a.queries {
		if (q.state != statePending && q.state != stateWaiting) || q.attempts == 0 {
			continue
		}
		records := q.records[:0]
		for _, resource := range allResources(&a.decode) {
			record, ok := convertResource(resource, q.request)
			if !ok || duplicateRecord(records, record) {
				continue
			}
			if len(records) == int(a.config.MaxRecords) {
				q.failLocked(nscore.FailureResourceLimit, lneto.ErrExhausted)
				records = nil
				break
			}
			records = append(records, record)
		}
		if len(records) != 0 {
			q.completeLocked(records)
		}
	}
}

func (a *Adapter) queueResponseLocked() {
	if len(a.services) == 0 || a.responseCount == len(a.responseSlots) || !a.policy.CheckEndpoint(policy.OperationMDNSSend, multicastAddress, Port) {
		return
	}
	resources := a.responseResources[:0]
	defer func() {
		clear(resources)
		a.responseResources = resources[:0]
	}()
	for _, question := range a.decode.Questions {
		questionName := canonicalName(question.Name)
		questionClass := lnetodns.Class(uint16(question.Class) &^ cacheFlush)
		if (questionClass != lnetodns.ClassINET && questionClass != lnetodns.ClassANY) || questionName == "" || !a.policy.CheckDNS(policy.OperationMDNSRespond, questionName) {
			continue
		}
		for i, service := range a.services {
			if !a.policy.CheckDNS(policy.OperationMDNSRespond, service.Name) || !a.policy.CheckDNS(policy.OperationMDNSRespond, service.Host) {
				continue
			}
			resources = appendServiceAnswers(resources, questionName, question.Type, service, a.serviceResources[i], a.decode.Answers, int(a.config.MaxRecordsPerPacket))
		}
	}
	if len(resources) == 0 {
		return
	}
	packet, err := appendResponsePacket(a.responseSlots[(a.responseHead+a.responseCount)%len(a.responseSlots)][:0], resources, a.config.MaxPacketBytes)
	if err != nil {
		return
	}
	index := (a.responseHead + a.responseCount) % len(a.responseSlots)
	a.responseSlots[index] = packet
	a.responseCount++
}

func buildQueryPacket(request mdnsns.Request, maxBytes int) ([]byte, error) {
	name, err := lnetodns.NewName(request.Name)
	if err != nil {
		return nil, err
	}
	questions := make([]lnetodns.Question, 0, 4)
	for _, pair := range []struct {
		bit mdnsns.RecordTypes
		typ lnetodns.Type
	}{{mdnsns.RecordsA, lnetodns.TypeA}, {mdnsns.RecordsPTR, lnetodns.TypePTR}, {mdnsns.RecordsSRV, lnetodns.TypeSRV}, {mdnsns.RecordsTXT, lnetodns.TypeTXT}} {
		if request.Types&pair.bit != 0 {
			questions = append(questions, lnetodns.Question{Name: name, Type: pair.typ, Class: lnetodns.ClassINET})
		}
	}
	message := lnetodns.Message{Questions: questions}
	if int(message.Len()) > maxBytes {
		return nil, lneto.ErrShortBuffer
	}
	storage := make([]byte, 0, maxBytes)
	return message.AppendTo(storage, 0, 0)
}

func buildServicePacket(service mdnsns.Service, only lnetodns.Type, maxBytes int) ([]byte, error) {
	resources, err := serviceResources(service, only)
	if err != nil {
		return nil, err
	}
	storage := make([]byte, 0, maxBytes)
	return appendResponsePacket(storage, resources, maxBytes)
}

func appendResponsePacket(storage []byte, resources []lnetodns.Resource, maxBytes int) ([]byte, error) {
	message := lnetodns.Message{Answers: resources}
	if int(message.Len()) > maxBytes {
		return nil, lneto.ErrShortBuffer
	}
	return message.AppendTo(storage, 0, lnetodns.HeaderFlags(1<<15|1<<10))
}

func serviceResources(service mdnsns.Service, only lnetodns.Type) ([]lnetodns.Resource, error) {
	name, err := lnetodns.NewName(service.Name)
	if err != nil {
		return nil, err
	}
	host, err := lnetodns.NewName(service.Host)
	if err != nil {
		return nil, err
	}
	typeName, err := lnetodns.NewName(serviceType(service.Name))
	if err != nil {
		return nil, err
	}
	class := lnetodns.Class(uint16(lnetodns.ClassINET) | cacheFlush)
	resources := make([]lnetodns.Resource, 0, 4)
	add := func(typ lnetodns.Type) {
		var resource lnetodns.Resource
		switch typ {
		case lnetodns.TypePTR:
			resource.SetPTR(typeName, lnetodns.ClassINET, service.TTLSeconds, name)
		case lnetodns.TypeSRV:
			resource.SetSRV(name, class, service.TTLSeconds, 0, 0, service.Port, host)
		case lnetodns.TypeTXT:
			resource.SetTXT(name, class, service.TTLSeconds, service.TXT[:service.TXTLength])
		case lnetodns.TypeA:
			address := service.Address.As4()
			resource.SetA(host, class, service.TTLSeconds, address[:])
		}
		resources = append(resources, resource)
	}
	if only == 0 {
		add(lnetodns.TypePTR)
		add(lnetodns.TypeSRV)
		add(lnetodns.TypeTXT)
		add(lnetodns.TypeA)
	} else {
		add(only)
		if only == lnetodns.TypeSRV {
			add(lnetodns.TypeA)
		}
	}
	return resources, nil
}

func appendServiceAnswers(resources []lnetodns.Resource, name string, questionType lnetodns.Type, service mdnsns.Service, serviceRecords, knownAnswers []lnetodns.Resource, limit int) []lnetodns.Resource {
	if name == "" {
		return resources
	}
	matches := questionType == lnetodns.TypeALL ||
		questionType == lnetodns.TypePTR && name == serviceType(service.Name) ||
		(questionType == lnetodns.TypeSRV || questionType == lnetodns.TypeTXT) && name == service.Name ||
		questionType == lnetodns.TypeA && name == service.Host
	if !matches {
		return resources
	}
	for i, resource := range serviceRecords {
		typ := resource.Header().Type
		if questionType != lnetodns.TypeALL && typ != questionType && !(questionType == lnetodns.TypeSRV && typ == lnetodns.TypeA) {
			continue
		}
		if len(resources) == limit {
			break
		}
		if !duplicateWireResource(resources, resource) && !suppressedByKnownAnswer(knownAnswers, resource) {
			resources = append(resources, serviceRecords[i])
		}
	}
	return resources
}

func convertResource(resource lnetodns.Resource, request mdnsns.Request) (mdnsns.Record, bool) {
	header := resource.Header()
	name := canonicalName(header.Name)
	if name == "" || name != request.Name || lnetodns.Class(uint16(header.Class)&^cacheFlush) != lnetodns.ClassINET || header.TTL == 0 {
		return mdnsns.Record{}, false
	}
	record := mdnsns.Record{Name: name, TTLSeconds: header.TTL, CacheFlush: uint16(header.Class)&cacheFlush != 0}
	data := resource.RawData()
	switch header.Type {
	case lnetodns.TypeA:
		if request.Types&mdnsns.RecordsA == 0 || len(data) != 4 {
			return mdnsns.Record{}, false
		}
		record.Type = mdnsns.RecordA
		record.Address = netip.AddrFrom4([4]byte(data))
	case lnetodns.TypePTR:
		if request.Types&mdnsns.RecordsPTR == 0 {
			return mdnsns.Record{}, false
		}
		target, ok := decodeResourceName(data, 0)
		if !ok {
			return mdnsns.Record{}, false
		}
		record.Type, record.Target = mdnsns.RecordPTR, target
	case lnetodns.TypeSRV:
		if request.Types&mdnsns.RecordsSRV == 0 || len(data) < 7 {
			return mdnsns.Record{}, false
		}
		target, ok := decodeResourceName(data, 6)
		if !ok {
			return mdnsns.Record{}, false
		}
		record.Type, record.Priority, record.Weight, record.Port, record.Target = mdnsns.RecordSRV,
			binary.BigEndian.Uint16(data[0:2]), binary.BigEndian.Uint16(data[2:4]), binary.BigEndian.Uint16(data[4:6]), target
	case lnetodns.TypeTXT:
		if request.Types&mdnsns.RecordsTXT == 0 || len(data) > mdnsns.MaxTXTBytes {
			return mdnsns.Record{}, false
		}
		record.Type, record.TXTLength = mdnsns.RecordTXT, uint16(len(data))
		copy(record.TXT[:], data)
	default:
		return mdnsns.Record{}, false
	}
	return record, record.Valid()
}

func decodeResourceName(data []byte, offset uint16) (string, bool) {
	var name lnetodns.Name
	next, err := name.Decode(data, offset)
	if err != nil || int(next) != len(data) {
		return "", false
	}
	value := canonicalName(name)
	return value, value != ""
}

func canonicalName(name lnetodns.Name) string {
	return strings.TrimSuffix(strings.ToLower(name.String()), ".")
}

func serviceType(name string) string {
	_, rest, ok := strings.Cut(name, ".")
	if !ok {
		return name
	}
	return rest
}

func allResources(message *lnetodns.Message) []lnetodns.Resource {
	resources := make([]lnetodns.Resource, 0, len(message.Answers)+len(message.Authorities)+len(message.Additionals))
	resources = append(resources, message.Answers...)
	resources = append(resources, message.Authorities...)
	resources = append(resources, message.Additionals...)
	return resources
}

func duplicateRecord(records []mdnsns.Record, record mdnsns.Record) bool {
	for _, existing := range records {
		if existing.Name == record.Name && existing.Type == record.Type && existing.Address == record.Address && existing.Target == record.Target &&
			existing.Port == record.Port && existing.Priority == record.Priority && existing.Weight == record.Weight && existing.TXTLength == record.TXTLength &&
			existing.TXT == record.TXT {
			return true
		}
	}
	return false
}

func duplicateWireResource(resources []lnetodns.Resource, candidate lnetodns.Resource) bool {
	if len(resources) == 0 {
		return false
	}
	candidateHeader := candidate.Header()
	candidateName := canonicalName(candidateHeader.Name)
	for _, resource := range resources {
		header := resource.Header()
		if canonicalName(header.Name) == candidateName && header.Type == candidateHeader.Type &&
			lnetodns.Class(uint16(header.Class)&^cacheFlush) == lnetodns.Class(uint16(candidateHeader.Class)&^cacheFlush) &&
			sameResourceData(resource, candidate) {
			return true
		}
	}
	return false
}

func suppressedByKnownAnswer(knownAnswers []lnetodns.Resource, candidate lnetodns.Resource) bool {
	for _, known := range knownAnswers {
		if sameKnownAnswer(known, candidate) {
			return true
		}
	}
	return false
}

func sameKnownAnswer(known, candidate lnetodns.Resource) bool {
	knownHeader, candidateHeader := known.Header(), candidate.Header()
	knownName, candidateName := canonicalName(knownHeader.Name), canonicalName(candidateHeader.Name)
	if knownName == "" || knownName != candidateName || knownHeader.Type != candidateHeader.Type ||
		lnetodns.Class(uint16(knownHeader.Class)&^cacheFlush) != lnetodns.ClassINET ||
		uint64(knownHeader.TTL)*2 < uint64(candidateHeader.TTL) {
		return false
	}
	return sameResourceData(known, candidate)
}

func sameResourceData(left, right lnetodns.Resource) bool {
	leftData, rightData := left.RawData(), right.RawData()
	switch right.Header().Type {
	case lnetodns.TypeA, lnetodns.TypeTXT:
		return bytes.Equal(leftData, rightData)
	case lnetodns.TypePTR:
		leftTarget, leftOK := decodeResourceName(leftData, 0)
		rightTarget, rightOK := decodeResourceName(rightData, 0)
		return leftOK && rightOK && leftTarget == rightTarget
	case lnetodns.TypeSRV:
		if len(leftData) < 7 || len(rightData) < 7 || !bytes.Equal(leftData[:6], rightData[:6]) {
			return false
		}
		leftTarget, leftOK := decodeResourceName(leftData, 6)
		rightTarget, rightOK := decodeResourceName(rightData, 6)
		return leftOK && rightOK && leftTarget == rightTarget
	default:
		return false
	}
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) && mac[0]&1 == 0
}

func queryRetainedBytes(config Config) uint64 {
	return uint64(config.MaxPacketBytes) + uint64(config.MaxRecords)*(2*254+16+mdnsns.MaxTXTBytes)
}

func removeQuery(owner *Adapter, target *query) {
	for i, value := range owner.queries {
		if value == target {
			copy(owner.queries[i:], owner.queries[i+1:])
			owner.queries[len(owner.queries)-1] = nil
			owner.queries = owner.queries[:len(owner.queries)-1]
			owner.cursor = 0
			return
		}
	}
}

func removeAnnouncement(owner *Adapter, target *announcement) {
	for i, value := range owner.announcements {
		if value == target {
			copy(owner.announcements[i:], owner.announcements[i+1:])
			owner.announcements[len(owner.announcements)-1] = nil
			owner.announcements = owner.announcements[:len(owner.announcements)-1]
			owner.cursor = 0
			return
		}
	}
}
