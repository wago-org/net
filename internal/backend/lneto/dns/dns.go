package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	lnetodns "github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ dnsns.Query = (*dnsQuery)(nil)

const (
	firstEphemeralDNSPort   uint16 = 53000
	dnsQueryPacketCapacity         = lnetodns.SizeHeader + 2*(253+2+4) + 11
	inlineDNSRecordCapacity        = 8
)

var (
	errPolicyDenied  = errors.New("net: endpoint policy denied operation")
	errCanceled      = errors.New("DNS query canceled")
	errResponseLimit = errors.New("DNS response service-attempt limit reached")
)

const (
	serviceOrder = 10
	closeOrder   = 10
)

// Config fixes resolver authority, response retention, concurrency, and
// deterministic retransmission work. Zero MaxQueries disables DNS truthfully.
// MaxQueries continues to limit live guest query handles until they are closed,
// even after a terminal query has already retired its transport state.
type Config struct {
	Server               netip.Addr
	MaxQueries           uint16
	MaxRecords           uint16
	MaxResponseBytes     int
	MaxAttempts          uint16
	RetryServiceAttempts uint16
}

// Adapter owns DNS query state, wire codecs, retries, response retention, and
// UDP service participation over one shared lneto core.
type Adapter struct {
	core                   *lnetocore.Namespace
	config                 Config
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte
	policy                 *policy.Policy
	quotas                 *quota.Account
	queries                []*dnsQuery
	freeRecordOverflow     [][]dnsns.Record
	byPort                 map[uint16]*dnsQuery
	candidates             []dnsns.Record
	names                  []string
	cursor                 int
	nextPort               uint16
	nextTxID               uint16
}

// New attaches DNS-local state and its bounded service participant to common.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || !ValidConfig(config, common.RequiredFrameBytesLocked()-14, common.PolicyLocked(), common.QuotasLocked(), true) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	n := &Adapter{
		core: common, config: config,
		hardwareAddress:        common.HardwareAddressLocked(),
		gatewayHardwareAddress: common.GatewayHardwareAddressLocked(), policy: common.PolicyLocked(), quotas: common.QuotasLocked(),
		queries: make([]*dnsQuery, 0, config.MaxQueries), byPort: make(map[uint16]*dnsQuery, config.MaxQueries),
		candidates: make([]dnsns.Record, config.MaxResponseBytes/11),
		names:      make([]string, 2*(config.MaxResponseBytes/11)),
		nextPort:   firstEphemeralDNSPort, nextTxID: uint16(common.RandSeedLocked()) | 1,
	}
	if config.MaxQueries > 0 && int(config.MaxRecords) > inlineDNSRecordCapacity {
		n.freeRecordOverflow = make([][]dnsns.Record, 0, config.MaxQueries)
	}
	common.Unlock()
	if err := common.Install(lnetocore.Participant{
		IngressOrder: serviceOrder,
		Ingress:      n.ingressLocked,
		EgressOrder:  serviceOrder,
		HasEgress:    n.hasWorkLocked,
		Egress:       n.egressLocked,
		CloseOrder:   closeOrder,
		Close:        n.CloseLocked,
	}); err != nil {
		return nil, err
	}
	return n, nil
}

type dnsQueryState uint8

const (
	dnsQueryPending dnsQueryState = iota + 1
	dnsQueryWaiting
	dnsQueryDone
	dnsQueryFailed
	dnsQueryClosed
)

type dnsQuery struct {
	owner          *Adapter
	request        dnsns.Request
	localPort      uint16
	txid           uint16
	packet         []byte
	packetStorage  [dnsQueryPacketCapacity]byte
	records        []dnsns.Record
	recordStorage  [inlineDNSRecordCapacity]dnsns.Record
	recordOverflow []dnsns.Record
	cursor         int
	attempts       uint16
	retry          uint16
	state          dnsQueryState
	failure        error

	portLease lnetocore.UDPPortLease
	retained  quota.Charge
	work      quota.Charge
}

func (n *Adapter) acquireRecordOverflowLocked() []dnsns.Record {
	if n == nil {
		return nil
	}
	if len(n.freeRecordOverflow) == 0 {
		return make([]dnsns.Record, 0, n.config.MaxRecords)
	}
	records := n.freeRecordOverflow[len(n.freeRecordOverflow)-1]
	n.freeRecordOverflow = n.freeRecordOverflow[:len(n.freeRecordOverflow)-1]
	return records
}

func (n *Adapter) recycleRecordOverflowLocked(records []dnsns.Record) {
	if n == nil || records == nil {
		return
	}
	clear(records)
	n.freeRecordOverflow = append(n.freeRecordOverflow, records[:0:cap(records)])
}

func (n *Adapter) TryResolve(request dnsns.Request) (nscore.Resource, nscore.Progress, error) {
	if n == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.core.Lock()
	defer n.core.Unlock()
	if n.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !request.Valid() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.config.MaxQueries == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !n.policy.CheckDNS(policy.OperationDNSResolve, request.Name) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(n.queries) == int(n.config.MaxQueries) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	query := &dnsQuery{owner: n, request: request, txid: n.nextTxID}
	if int(n.config.MaxRecords) <= len(query.recordStorage) {
		query.records = query.recordStorage[:0:n.config.MaxRecords]
	} else {
		query.recordOverflow = n.acquireRecordOverflowLocked()
		if query.recordOverflow == nil {
			return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
		}
		query.records = query.recordOverflow[:0:n.config.MaxRecords]
	}
	if !n.allocatePortLocked(&query.portLease) {
		n.recycleRecordOverflowLocked(query.recordOverflow)
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	query.localPort = query.portLease.UDPPort()
	packet, err := buildDNSQueryPacketInto(query.packetStorage[:], request, n.nextTxID, n.config.MaxResponseBytes)
	if err != nil {
		query.portLease.ReleaseLocked()
		n.recycleRecordOverflowLocked(query.recordOverflow)
		return nil, 0, lnetocore.MapError(err)
	}
	query.packet = packet
	query.state = dnsQueryPending
	if err := n.quotas.AcquireResourceAndQueuedBytes(&query.retained, quota.ResourceDNS, 1, dnsRetainedBytes(n.config)); err != nil {
		query.portLease.ReleaseLocked()
		n.recycleRecordOverflowLocked(query.recordOverflow)
		return nil, 0, lnetocore.MapError(err)
	}
	workUnits := uint64(1)
	if request.Types == dnsns.RecordsA|dnsns.RecordsAAAA {
		workUnits = 2
	}
	if err := n.quotas.AcquireDNSWork(&query.work, workUnits); err != nil {
		query.retained.Release()
		query.retained.ResetReleased()
		query.portLease.ReleaseLocked()
		n.recycleRecordOverflowLocked(query.recordOverflow)
		return nil, 0, lnetocore.MapError(err)
	}
	n.nextTxID++
	if n.nextTxID == 0 {
		n.nextTxID = 1
	}
	n.byPort[query.localPort] = query
	n.queries = append(n.queries, query)
	return query, nscore.ProgressInProgress, nil
}

func (q *dnsQuery) Readiness() nscore.Readiness {
	if q == nil || q.owner == nil {
		return nscore.ReadyClosed
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	if q.state == dnsQueryClosed || q.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if q.state == dnsQueryFailed {
		return nscore.ReadyError
	}
	if q.state == dnsQueryDone {
		return nscore.ReadyDNSResult
	}
	return 0
}

func (q *dnsQuery) TryNext() (dnsns.Record, dnsns.Next, error) {
	if q == nil || q.owner == nil {
		return dnsns.Record{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	if q.state == dnsQueryClosed || q.owner.core.ClosedLocked() {
		return dnsns.Record{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if q.state == dnsQueryFailed {
		return dnsns.Record{}, 0, q.failure
	}
	if q.cursor < len(q.records) {
		record := q.records[q.cursor]
		q.cursor++
		if !record.Valid() {
			return dnsns.Record{}, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
		}
		return record, dnsns.NextReady, nil
	}
	if q.state == dnsQueryDone {
		return dnsns.Record{}, dnsns.NextEOF, nil
	}
	return dnsns.Record{}, dnsns.NextWouldBlock, nil
}

func (q *dnsQuery) Cancel() error {
	if q == nil || q.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	if q.state == dnsQueryClosed || q.owner.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if q.state == dnsQueryDone || q.state == dnsQueryFailed {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	q.failLocked(nscore.FailureCanceled, errCanceled)
	return nil
}

func (q *dnsQuery) Close() error {
	if q == nil || q.owner == nil {
		return nil
	}
	q.owner.core.Lock()
	defer q.owner.core.Unlock()
	return q.closeLocked()
}

func (q *dnsQuery) closeLocked() error {
	if q.state == dnsQueryClosed {
		return nil
	}
	q.state = dnsQueryClosed
	q.retireTransportLocked()
	if q.owner != nil {
		removeQuery(q.owner, q)
	}
	clear(q.packet)
	clear(q.packetStorage[:])
	q.packet = nil
	for i := range q.records {
		q.records[i] = dnsns.Record{}
	}
	clear(q.recordStorage[:])
	q.records = nil
	q.cursor = 0
	q.request = dnsns.Request{}
	q.failure = nil
	q.releaseQuotaLocked()
	if q.owner != nil {
		q.owner.recycleRecordOverflowLocked(q.recordOverflow)
	}
	q.recordOverflow = nil
	return nil
}

func (q *dnsQuery) retireTransportLocked() {
	if q == nil {
		return
	}
	if q.owner != nil && q.localPort != 0 && q.owner.byPort != nil && q.owner.byPort[q.localPort] == q {
		delete(q.owner.byPort, q.localPort)
	}
	q.portLease.ReleaseLocked()
	q.localPort = 0
	q.retry = 0
	q.txid = 0
}

func (q *dnsQuery) failLocked(failure nscore.Failure, cause error) {
	if q.state == dnsQueryClosed || q.state == dnsQueryDone || q.state == dnsQueryFailed {
		return
	}
	q.retireTransportLocked()
	q.state = dnsQueryFailed
	q.failure = nscore.Fail(failure, cause)
	q.releaseWorkLocked()
}

func (q *dnsQuery) completeLocked(records []dnsns.Record) {
	if q.state == dnsQueryClosed || q.state == dnsQueryDone || q.state == dnsQueryFailed {
		return
	}
	q.retireTransportLocked()
	q.records = append(q.records[:0], records...)
	q.cursor = 0
	q.state = dnsQueryDone
	q.releaseWorkLocked()
}

func (q *dnsQuery) releaseWorkLocked() {
	q.work.Release()
	q.work.ResetReleased()
}

func (q *dnsQuery) releaseQuotaLocked() {
	q.releaseWorkLocked()
	q.retained.Release()
	q.retained.ResetReleased()
}

// CloseLocked releases every DNS query and retained allocation. The caller
// must hold the shared core lock.
func (n *Adapter) CloseLocked() {
	if n == nil {
		return
	}
	for len(n.queries) > 0 {
		_ = n.queries[len(n.queries)-1].closeLocked()
	}
	clear(n.byPort)
	clear(n.candidates)
	clear(n.names)
	for i := range n.freeRecordOverflow {
		clear(n.freeRecordOverflow[i])
	}
	n.byPort = nil
	n.freeRecordOverflow = nil
	n.queries = nil
	n.candidates = nil
	n.names = nil
	n.cursor = 0
}

func (n *Adapter) hasWorkLocked() bool {
	for _, query := range n.queries {
		if query != nil && (query.state == dnsQueryPending || query.state == dnsQueryWaiting) {
			return true
		}
	}
	return false
}

// egressLocked performs one bounded query operation. worked may be true
// with a zero packet when one retry countdown or timeout transition completed.
func (n *Adapter) egressLocked(dst []byte) (written int, worked bool, err error) {
	if len(n.queries) == 0 {
		return 0, false, nil
	}
	for offset := 0; offset < len(n.queries); offset++ {
		index := n.cursor + offset
		if index >= len(n.queries) {
			index -= len(n.queries)
		}
		query := n.queries[index]
		if query == nil || (query.state != dnsQueryPending && query.state != dnsQueryWaiting) {
			continue
		}
		n.cursor = index + 1
		if n.cursor == len(n.queries) {
			n.cursor = 0
		}
		if query.state == dnsQueryWaiting {
			if query.retry > 1 {
				query.retry--
				return 0, true, nil
			}
			if query.attempts >= n.config.MaxAttempts {
				query.failLocked(nscore.FailureTimedOut, errResponseLimit)
				return 0, true, nil
			}
			query.state = dnsQueryPending
			return 0, true, nil
		}
		frameBytes := 14 + 20 + 8 + len(query.packet)
		if len(dst) < frameBytes {
			return 0, false, lneto.ErrShortBuffer
		}
		frame := dst[:frameBytes]
		clear(frame)
		ethernetFrame, _ := ethernet.NewFrame(frame)
		*ethernetFrame.DestinationHardwareAddr() = n.gatewayHardwareAddress
		*ethernetFrame.SourceHardwareAddr() = n.hardwareAddress
		ethernetFrame.SetEtherType(ethernet.TypeIPv4)
		ipFrame, _ := ipv4.NewFrame(frame[14:])
		ipFrame.SetVersionAndIHL(4, 5)
		ipFrame.SetTotalLength(uint16(20 + 8 + len(query.packet)))
		ipFrame.SetID(n.core.NextIPv4IDLocked())
		ipFrame.SetFlags(0)
		ipFrame.SetTTL(64)
		ipFrame.SetProtocol(lneto.IPProtoUDP)
		*ipFrame.SourceAddr() = n.core.IPv4AddressLocked().As4()
		*ipFrame.DestinationAddr() = n.config.Server.As4()
		ipFrame.SetCRC(0)
		ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
		udpFrame, _ := lnetoudp.NewFrame(frame[14+20:])
		udpFrame.SetSourcePort(query.localPort)
		udpFrame.SetDestinationPort(lnetodns.ServerPort)
		udpFrame.SetLength(uint16(8 + len(query.packet)))
		copy(frame[14+20+8:], query.packet)
		udpFrame.SetCRC(0)
		var checksum lneto.CRC791
		ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
		udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
		query.attempts++
		query.retry = n.config.RetryServiceAttempts
		query.state = dnsQueryWaiting
		return frameBytes, true, nil
	}
	return 0, false, nil
}

func (n *Adapter) ingressLocked(frame []byte) (bool, error) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || ethernetFrame.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return false, err
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		return false, err
	}
	version, headerWords := ipFrame.VersionAndIHL()
	if version != 4 || headerWords < 5 || ipFrame.Protocol() != lneto.IPProtoUDP || netip.AddrFrom4(*ipFrame.DestinationAddr()) != n.core.IPv4AddressLocked() {
		return false, nil
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		return false, nil
	}
	query := n.byPort[udpFrame.DestinationPort()]
	if query == nil || (query.state != dnsQueryPending && query.state != dnsQueryWaiting) || netip.AddrFrom4(*ipFrame.SourceAddr()) != n.config.Server || udpFrame.SourcePort() != lnetodns.ServerPort {
		return false, nil
	}
	var validator lneto.Validator
	ipFrame.ValidateExceptCRC(&validator)
	if err := validator.ErrPop(); err != nil {
		query.failLocked(nscore.FailureIO, err)
		return true, nil
	}
	if ipFrame.CalculateHeaderCRC() != 0 || ipFrame.Flags().MoreFragments() || ipFrame.Flags().FragmentOffset() != 0 {
		query.failLocked(nscore.FailureIO, lneto.ErrBadCRC)
		return true, nil
	}
	udpFrame.ValidateSize(&validator)
	if err := validator.ErrPop(); err != nil {
		query.failLocked(nscore.FailureIO, err)
		return true, nil
	}
	udpLength := udpFrame.Length()
	if udpFrame.CRC() != 0 {
		var checksum lneto.CRC791
		ipFrame.CRCWriteUDPPseudo(&checksum, udpLength)
		if checksum.PayloadSum16(udpFrame.RawData()[:udpLength]) != 0 {
			query.failLocked(nscore.FailureIO, lneto.ErrBadCRC)
			return true, nil
		}
	}
	payload := udpFrame.RawData()[8:udpLength]
	if len(payload) > n.config.MaxResponseBytes {
		query.failLocked(nscore.FailureMessageTooLarge, lneto.ErrShortBuffer)
		return true, nil
	}
	records, response, failure, err := parseDNSResponseInto(query.records[:0], n.candidates, n.names, payload, query.txid, query.request, int(n.config.MaxRecords))
	if !response {
		return true, nil
	}
	if err != nil {
		query.failLocked(failure, err)
		return true, nil
	}
	query.completeLocked(records)
	return true, nil
}

func buildDNSQueryPacket(request dnsns.Request, txid uint16, maxResponseBytes int) ([]byte, error) {
	packetBytes, err := dnsQueryPacketSize(request, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	return writeDNSQueryPacket(make([]byte, packetBytes), request, txid, maxResponseBytes), nil
}

func buildDNSQueryPacketInto(storage []byte, request dnsns.Request, txid uint16, maxResponseBytes int) ([]byte, error) {
	packetBytes, err := dnsQueryPacketSize(request, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	if len(storage) < packetBytes {
		return nil, lneto.ErrShortBuffer
	}
	return writeDNSQueryPacket(storage[:packetBytes], request, txid, maxResponseBytes), nil
}

func dnsQueryPacketSize(request dnsns.Request, maxResponseBytes int) (int, error) {
	if !request.Valid() {
		return 0, lneto.ErrInvalidAddr
	}
	if maxResponseBytes <= 0 || maxResponseBytes > int(^uint16(0)) {
		return 0, lneto.ErrInvalidConfig
	}
	questionCount := dnsQuestionCount(request.Types)
	wireNameBytes := len(request.Name) + 2
	return lnetodns.SizeHeader + questionCount*(wireNameBytes+4) + 11, nil
}

func writeDNSQueryPacket(packet []byte, request dnsns.Request, txid uint16, maxResponseBytes int) []byte {
	clear(packet)
	questionCount := dnsQuestionCount(request.Types)
	binary.BigEndian.PutUint16(packet[0:2], txid)
	binary.BigEndian.PutUint16(packet[2:4], 1<<8)
	binary.BigEndian.PutUint16(packet[4:6], uint16(questionCount))
	binary.BigEndian.PutUint16(packet[10:12], 1)
	offset := lnetodns.SizeHeader
	if request.Types&dnsns.RecordsA != 0 {
		offset = appendDNSQuestion(packet, offset, request.Name, lnetodns.TypeA)
	}
	if request.Types&dnsns.RecordsAAAA != 0 {
		offset = appendDNSQuestion(packet, offset, request.Name, lnetodns.TypeAAAA)
	}
	packet[offset] = 0
	binary.BigEndian.PutUint16(packet[offset+1:offset+3], 41)
	binary.BigEndian.PutUint16(packet[offset+3:offset+5], uint16(maxResponseBytes))
	return packet
}

func dnsQuestionCount(types dnsns.RecordTypes) int {
	count := 0
	if types&dnsns.RecordsA != 0 {
		count++
	}
	if types&dnsns.RecordsAAAA != 0 {
		count++
	}
	return count
}

func appendDNSQuestion(packet []byte, offset int, name string, typ lnetodns.Type) int {
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}
		packet[offset] = byte(i - labelStart)
		offset++
		copy(packet[offset:], name[labelStart:i])
		offset += i - labelStart
		labelStart = i + 1
	}
	packet[offset] = 0
	offset++
	binary.BigEndian.PutUint16(packet[offset:offset+2], uint16(typ))
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], uint16(lnetodns.ClassINET))
	return offset + 4
}

func parseDNSResponse(payload []byte, txid uint16, request dnsns.Request, maxRecords int) ([]dnsns.Record, bool, nscore.Failure, error) {
	records := make([]dnsns.Record, 0, maxRecords)
	candidates := make([]dnsns.Record, len(payload)/11)
	names := make([]string, 2*len(candidates))
	return parseDNSResponseInto(records, candidates, names, payload, txid, request, maxRecords)
}

func parseDNSResponseInto(records, candidateStorage []dnsns.Record, nameStorage []string, payload []byte, txid uint16, request dnsns.Request, maxRecords int) ([]dnsns.Record, bool, nscore.Failure, error) {
	candidateCount := 0
	nameCount := 0
	defer func() {
		clear(candidateStorage[:candidateCount])
		clear(nameStorage[:nameCount])
	}()
	frame, err := lnetodns.NewFrame(payload)
	if err != nil {
		return nil, true, nscore.FailureIO, err
	}
	flags := frame.Flags()
	if frame.TxID() != txid || !flags.IsResponse() {
		return nil, false, 0, nil
	}
	if flags.OpCode() != lnetodns.OpCodeQuery {
		return nil, true, nscore.FailureIO, lneto.ErrInvalidField
	}
	offset, err := validateDNSQuestions(payload, lnetodns.SizeHeader, frame.QDCount(), request)
	if err != nil {
		return nil, true, nscore.FailureIO, err
	}
	if flags.IsTruncated() {
		return nil, true, nscore.FailureTemporary, lneto.ErrTruncatedFrame
	}
	if rcode := flags.ResponseCode(); rcode != lnetodns.RCodeSuccess {
		failure := nscore.FailureTemporary
		switch rcode {
		case lnetodns.RCodeNameError:
			failure = nscore.FailureNameNotFound
		case lnetodns.RCodeFormatError:
			failure = nscore.FailureInvalidArgument
		case lnetodns.RCodeNotImplemented:
			failure = nscore.FailureNotSupported
		case lnetodns.RCodeRefused:
			failure = nscore.FailureAccessDenied
		}
		return nil, true, failure, rcode
	}

	for range int(frame.ANCount()) {
		record, recognized, next, decodeErr := decodeDNSAnswer(payload, offset, request, nameStorage, &nameCount)
		if decodeErr != nil {
			failure := nscore.FailureIO
			if errors.Is(decodeErr, lneto.ErrExhausted) {
				failure = nscore.FailureResourceLimit
			}
			return nil, true, failure, decodeErr
		}
		offset = next
		if !recognized {
			continue
		}
		if candidateCount == len(candidateStorage) {
			return nil, true, nscore.FailureResourceLimit, lneto.ErrExhausted
		}
		candidateStorage[candidateCount] = record
		candidateCount++
	}
	for range int(frame.NSCount()) + int(frame.ARCount()) {
		offset, err = skipDNSResource(payload, offset)
		if err != nil {
			return nil, true, nscore.FailureIO, err
		}
	}
	if offset != len(payload) {
		return nil, true, nscore.FailureIO, lneto.ErrInvalidLengthField
	}
	records, failure, err := selectDNSAnswersInto(records, candidateStorage[:candidateCount], request, maxRecords)
	if err != nil {
		return nil, true, failure, err
	}
	return records, true, 0, nil
}

func validateDNSQuestions(payload []byte, offset int, count uint16, request dnsns.Request) (int, error) {
	expectedCount := 0
	if request.Types&dnsns.RecordsA != 0 {
		expectedCount++
	}
	if request.Types&dnsns.RecordsAAAA != 0 {
		expectedCount++
	}
	if int(count) != expectedCount {
		return offset, lneto.ErrInvalidField
	}
	var name [253]byte
	for index := 0; index < expectedCount; index++ {
		length, next, err := decodeDNSNameInto(name[:], payload, offset)
		if err != nil || next+4 > len(payload) {
			if err == nil {
				err = lneto.ErrTruncatedFrame
			}
			return offset, err
		}
		expectedType := lnetodns.TypeA
		if request.Types&dnsns.RecordsA == 0 || index != 0 {
			expectedType = lnetodns.TypeAAAA
		}
		typ := lnetodns.Type(binary.BigEndian.Uint16(payload[next : next+2]))
		class := lnetodns.Class(binary.BigEndian.Uint16(payload[next+2 : next+4]))
		if !equalDNSName(name[:length], request.Name) || typ != expectedType || class != lnetodns.ClassINET {
			return offset, lneto.ErrInvalidField
		}
		offset = next + 4
	}
	return offset, nil
}

func equalDNSName(decoded []byte, name string) bool {
	if len(decoded) != len(name) {
		return false
	}
	for i, value := range decoded {
		if value != name[i] {
			return false
		}
	}
	return true
}

func decodeDNSAnswer(payload []byte, offset int, request dnsns.Request, nameStorage []string, nameCount *int) (record dnsns.Record, recognized bool, nextOffset int, err error) {
	var owner [253]byte
	ownerLength, next, err := decodeDNSNameInto(owner[:], payload, offset)
	if err != nil || next+10 > len(payload) {
		if err == nil {
			err = lneto.ErrTruncatedFrame
		}
		return record, false, offset, err
	}
	typ := lnetodns.Type(binary.BigEndian.Uint16(payload[next : next+2]))
	class := lnetodns.Class(binary.BigEndian.Uint16(payload[next+2 : next+4]))
	ttl := binary.BigEndian.Uint32(payload[next+4 : next+8])
	length := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
	dataStart := next + 10
	dataEnd := dataStart + length
	if dataEnd > len(payload) {
		return record, false, offset, lneto.ErrTruncatedFrame
	}
	if class != lnetodns.ClassINET {
		return record, false, dataEnd, nil
	}
	switch typ {
	case lnetodns.TypeA:
		if length != 4 {
			return record, false, offset, lneto.ErrInvalidLengthField
		}
		if request.Types&dnsns.RecordsA == 0 {
			return record, false, dataEnd, nil
		}
		ownerName, err := internDNSName(owner[:ownerLength], request.Name, nameStorage, nameCount)
		if err != nil {
			return record, false, offset, err
		}
		record = dnsns.Record{Name: ownerName, Type: dnsns.RecordA, TTLSeconds: ttl, Address: netip.AddrFrom4([4]byte(payload[dataStart:dataEnd]))}
	case lnetodns.TypeAAAA:
		if length != 16 {
			return record, false, offset, lneto.ErrInvalidLengthField
		}
		if request.Types&dnsns.RecordsAAAA == 0 {
			return record, false, dataEnd, nil
		}
		ownerName, err := internDNSName(owner[:ownerLength], request.Name, nameStorage, nameCount)
		if err != nil {
			return record, false, offset, err
		}
		record = dnsns.Record{Name: ownerName, Type: dnsns.RecordAAAA, TTLSeconds: ttl, Address: netip.AddrFrom16([16]byte(payload[dataStart:dataEnd]))}
	case lnetodns.TypeCNAME:
		var canonical [253]byte
		canonicalLength, consumed, err := decodeDNSNameInto(canonical[:], payload, dataStart)
		if err != nil || consumed != dataEnd {
			if err == nil {
				err = lneto.ErrInvalidLengthField
			}
			return record, false, offset, err
		}
		ownerName, err := internDNSName(owner[:ownerLength], request.Name, nameStorage, nameCount)
		if err != nil {
			return record, false, offset, err
		}
		canonicalName, err := internDNSName(canonical[:canonicalLength], request.Name, nameStorage, nameCount)
		if err != nil {
			return record, false, offset, err
		}
		record = dnsns.Record{Name: ownerName, Type: dnsns.RecordCNAME, TTLSeconds: ttl, CanonicalName: canonicalName}
	default:
		return record, false, dataEnd, nil
	}
	return record, true, dataEnd, nil
}

func internDNSName(decoded []byte, requestName string, storage []string, count *int) (string, error) {
	if equalDNSName(decoded, requestName) {
		return requestName, nil
	}
	for _, name := range storage[:*count] {
		if equalDNSName(decoded, name) {
			return name, nil
		}
	}
	if *count == len(storage) {
		return "", lneto.ErrExhausted
	}
	name := string(decoded)
	storage[*count] = name
	*count = *count + 1
	return name, nil
}

func skipDNSResource(payload []byte, offset int) (int, error) {
	var name [253]byte
	_, next, err := decodeDNSNameInto(name[:], payload, offset)
	if err != nil || next+10 > len(payload) {
		if err == nil {
			err = lneto.ErrTruncatedFrame
		}
		return offset, err
	}
	dataEnd := next + 10 + int(binary.BigEndian.Uint16(payload[next+8:next+10]))
	if dataEnd > len(payload) {
		return offset, lneto.ErrTruncatedFrame
	}
	return dataEnd, nil
}

func selectDNSAnswers(candidates []dnsns.Record, request dnsns.Request, maxRecords int) ([]dnsns.Record, nscore.Failure, error) {
	records := make([]dnsns.Record, 0, min(maxRecords, len(candidates)))
	return selectDNSAnswersInto(records, candidates, request, maxRecords)
}

func selectDNSAnswersInto(records, candidates []dnsns.Record, request dnsns.Request, maxRecords int) ([]dnsns.Record, nscore.Failure, error) {
	records = records[:0]
	current := request.Name
	for {
		for _, record := range records {
			if record.Type == dnsns.RecordCNAME && record.Name == current {
				return nil, nscore.FailureIO, lneto.ErrInvalidField
			}
		}
		var cname dnsns.Record
		for _, candidate := range candidates {
			if candidate.Type != dnsns.RecordCNAME || candidate.Name != current {
				continue
			}
			if !candidate.Valid() {
				return nil, nscore.FailureIO, lneto.ErrInvalidField
			}
			if cname.Type == 0 {
				cname = candidate
				continue
			}
			if cname.CanonicalName != candidate.CanonicalName {
				return nil, nscore.FailureIO, lneto.ErrInvalidField
			}
		}
		if cname.Type == 0 {
			break
		}
		var err error
		records, err = appendUniqueDNSRecord(records, cname, maxRecords)
		if err != nil {
			return nil, nscore.FailureResourceLimit, err
		}
		current = cname.CanonicalName
	}
	for _, candidate := range candidates {
		if candidate.Name != current || candidate.Type == dnsns.RecordCNAME {
			continue
		}
		if !candidate.Valid() {
			return nil, nscore.FailureIO, lneto.ErrInvalidField
		}
		var err error
		records, err = appendUniqueDNSRecord(records, candidate, maxRecords)
		if err != nil {
			return nil, nscore.FailureResourceLimit, err
		}
	}
	return records, 0, nil
}

func appendUniqueDNSRecord(records []dnsns.Record, record dnsns.Record, maxRecords int) ([]dnsns.Record, error) {
	for _, existing := range records {
		if existing.Name == record.Name && existing.Type == record.Type && existing.Address == record.Address && existing.CanonicalName == record.CanonicalName {
			return records, nil
		}
	}
	if len(records) == maxRecords {
		return nil, lneto.ErrExhausted
	}
	return append(records, record), nil
}

func decodeDNSName(message []byte, offset int) (string, int, error) {
	var decoded [253]byte
	written, next, err := decodeDNSNameInto(decoded[:], message, offset)
	if err != nil {
		return "", offset, err
	}
	return string(decoded[:written]), next, nil
}

func decodeDNSNameInto(decoded, message []byte, offset int) (int, int, error) {
	if offset < 0 || offset >= len(message) {
		return 0, offset, lneto.ErrTruncatedFrame
	}
	written := 0
	position := offset
	next := -1
	for pointers := 0; ; {
		if position >= len(message) {
			return 0, offset, lneto.ErrTruncatedFrame
		}
		length := int(message[position])
		switch length & 0xc0 {
		case 0:
			position++
			if length == 0 {
				if next < 0 {
					next = position
				}
				if written == 0 {
					return 0, offset, lneto.ErrInvalidAddr
				}
				return written, next, nil
			}
			if length > 63 || position+length > len(message) {
				return 0, offset, lneto.ErrTruncatedFrame
			}
			separator := 0
			if written != 0 {
				separator = 1
			}
			if written+separator+length > len(decoded) {
				return 0, offset, lneto.ErrInvalidAddr
			}
			if separator != 0 {
				decoded[written] = '.'
				written++
			}
			for _, value := range message[position : position+length] {
				if value >= 'A' && value <= 'Z' {
					value += 'a' - 'A'
				}
				decoded[written] = value
				written++
			}
			position += length
		case 0xc0:
			if position+1 >= len(message) {
				return 0, offset, lneto.ErrTruncatedFrame
			}
			if next < 0 {
				next = position + 2
			}
			position = (length^0xc0)<<8 | int(message[position+1])
			pointers++
			if pointers > 10 || position >= len(message) {
				return 0, offset, lneto.ErrInvalidField
			}
		default:
			return 0, offset, lneto.ErrInvalidField
		}
	}
}

func dnsRetainedBytes(config Config) uint64 {
	return uint64(config.MaxResponseBytes) + uint64(config.MaxRecords)*(2*254+16) + 2*254
}

// ValidConfig validates DNS-local resolver, storage, retry, and authority bounds.
func ValidConfig(config Config, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxQueries == 0 {
		return config == (Config{})
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	return config.Server.Is4() && !config.Server.Is4In6() && !config.Server.IsUnspecified() && config.Server.Zone() == "" &&
		config.MaxRecords > 0 && config.MaxResponseBytes >= lnetodns.MaxSizeUDP && config.MaxResponseBytes <= mtu-28 &&
		config.MaxResponseBytes <= int(^uint16(0)) && config.MaxAttempts > 0 && config.RetryServiceAttempts > 0
}

func (n *Adapter) allocatePortLocked(lease *lnetocore.UDPPortLease) bool {
	attempts := int(n.config.MaxQueries) + n.core.UDPPortLeaseCountLocked() + 1
	next, ok := n.core.TryLeaseUDPPortRangeIntoLocked(lease, n.nextPort, firstEphemeralDNSPort, attempts)
	if ok {
		n.nextPort = next
	}
	return ok
}

func removeQuery(owner *Adapter, target *dnsQuery) {
	if owner == nil {
		return
	}
	for i, query := range owner.queries {
		if query != target {
			continue
		}
		copy(owner.queries[i:], owner.queries[i+1:])
		owner.queries[len(owner.queries)-1] = nil
		owner.queries = owner.queries[:len(owner.queries)-1]
		if len(owner.queries) == 0 {
			owner.cursor = 0
		} else if owner.cursor > i {
			owner.cursor--
		} else if owner.cursor >= len(owner.queries) {
			owner.cursor = 0
		}
		return
	}
}
