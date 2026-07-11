package lnetobackend

import (
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
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ dnsns.Query = (*dnsQuery)(nil)

const firstEphemeralDNSPort uint16 = 53000

// DNSConfig fixes resolver authority, response retention, concurrency, and
// deterministic retransmission work. Zero MaxQueries disables DNS truthfully.
type DNSConfig struct {
	Server               netip.Addr
	MaxQueries           uint16
	MaxRecords           uint16
	MaxResponseBytes     int
	MaxAttempts          uint16
	RetryServiceAttempts uint16
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
	owner     *Namespace
	request   dnsns.Request
	localPort uint16
	txid      uint16
	packet    []byte
	records   []dnsns.Record
	cursor    int
	attempts  uint16
	retry     uint16
	state     dnsQueryState
	failure   error

	portLease *lnetocore.UDPPortLease
	resource  *quota.Allocation
	queued    *quota.Allocation
	work      *quota.Allocation
}

func (n *Namespace) tryResolve(request dnsns.Request) (nscore.Resource, nscore.Progress, error) {
	if n == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.core.Lock()
	defer n.core.Unlock()
	if n.core.ClosedLocked() || n.stack == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !request.Valid() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.dnsConfig.MaxQueries == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !n.policy.CheckDNS(policy.OperationDNSResolve, request.Name) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(n.dnsQueries) == int(n.dnsConfig.MaxQueries) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	portLease, ok := n.allocateDNSPortLocked()
	if !ok {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	localPort := portLease.UDPPort()
	packet, err := buildDNSQueryPacket(request, n.nextDNSTxID, n.dnsConfig.MaxResponseBytes)
	if err != nil {
		portLease.ReleaseLocked()
		return nil, 0, mapError(err)
	}

	resourceReservation, err := n.quotas.ReserveResource(quota.ResourceDNS, 1)
	if err != nil {
		portLease.ReleaseLocked()
		return nil, 0, mapError(err)
	}
	retainedBytes := dnsRetainedBytes(n.dnsConfig)
	queuedReservation, err := n.quotas.ReserveQueuedBytes(retainedBytes)
	if err != nil {
		resourceReservation.Rollback()
		portLease.ReleaseLocked()
		return nil, 0, mapError(err)
	}
	workUnits := uint64(1)
	if request.Types == dnsns.RecordsA|dnsns.RecordsAAAA {
		workUnits = 2
	}
	workReservation, err := n.quotas.ReserveDNSWork(workUnits)
	if err != nil {
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		portLease.ReleaseLocked()
		return nil, 0, mapError(err)
	}
	resourceAllocation, ok := resourceReservation.Commit()
	if !ok {
		workReservation.Rollback()
		queuedReservation.Rollback()
		portLease.ReleaseLocked()
		return nil, 0, nscore.Fail(nscore.FailureClosed, quota.ErrClosed)
	}
	queuedAllocation, ok := queuedReservation.Commit()
	if !ok {
		workReservation.Rollback()
		resourceAllocation.Release()
		portLease.ReleaseLocked()
		return nil, 0, nscore.Fail(nscore.FailureClosed, quota.ErrClosed)
	}
	workAllocation, ok := workReservation.Commit()
	if !ok {
		queuedAllocation.Release()
		resourceAllocation.Release()
		portLease.ReleaseLocked()
		return nil, 0, nscore.Fail(nscore.FailureClosed, quota.ErrClosed)
	}

	query := &dnsQuery{
		owner: n, request: request, localPort: localPort, txid: n.nextDNSTxID, portLease: portLease,
		packet: packet, records: make([]dnsns.Record, 0, n.dnsConfig.MaxRecords),
		state: dnsQueryPending, resource: resourceAllocation, queued: queuedAllocation, work: workAllocation,
	}
	n.nextDNSTxID++
	if n.nextDNSTxID == 0 {
		n.nextDNSTxID = 1
	}
	n.dnsByPort[localPort] = query
	n.dnsQueries = append(n.dnsQueries, query)
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
	q.failLocked(nscore.FailureCanceled, errors.New("DNS query canceled"))
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
	if q.owner != nil {
		delete(q.owner.dnsByPort, q.localPort)
		removeDNSQuery(q.owner, q)
	}
	clear(q.packet)
	q.packet = nil
	for i := range q.records {
		q.records[i] = dnsns.Record{}
	}
	q.records = nil
	q.request = dnsns.Request{}
	q.failure = nil
	if q.portLease != nil {
		q.portLease.ReleaseLocked()
		q.portLease = nil
	}
	q.releaseQuotaLocked()
	return nil
}

func (q *dnsQuery) failLocked(failure nscore.Failure, cause error) {
	if q.state == dnsQueryClosed || q.state == dnsQueryDone || q.state == dnsQueryFailed {
		return
	}
	q.state = dnsQueryFailed
	q.failure = nscore.Fail(failure, cause)
	q.releaseWorkLocked()
}

func (q *dnsQuery) completeLocked(records []dnsns.Record) {
	if q.state == dnsQueryClosed || q.state == dnsQueryDone || q.state == dnsQueryFailed {
		return
	}
	q.records = append(q.records[:0], records...)
	q.cursor = 0
	q.state = dnsQueryDone
	q.releaseWorkLocked()
}

func (q *dnsQuery) releaseWorkLocked() {
	if q.work != nil {
		q.work.Release()
		q.work = nil
	}
}

func (q *dnsQuery) releaseQuotaLocked() {
	q.releaseWorkLocked()
	if q.queued != nil {
		q.queued.Release()
		q.queued = nil
	}
	if q.resource != nil {
		q.resource.Release()
		q.resource = nil
	}
}

func (n *Namespace) hasDNSWorkLocked() bool {
	for _, query := range n.dnsQueries {
		if query != nil && (query.state == dnsQueryPending || query.state == dnsQueryWaiting) {
			return true
		}
	}
	return false
}

// egressDNSLocked performs one bounded query operation. worked may be true
// with a zero packet when one retry countdown or timeout transition completed.
func (n *Namespace) egressDNSLocked(dst []byte) (written int, worked bool, err error) {
	if len(n.dnsQueries) == 0 {
		return 0, false, nil
	}
	for offset := 0; offset < len(n.dnsQueries); offset++ {
		index := n.dnsCursor + offset
		if index >= len(n.dnsQueries) {
			index -= len(n.dnsQueries)
		}
		query := n.dnsQueries[index]
		if query == nil || (query.state != dnsQueryPending && query.state != dnsQueryWaiting) {
			continue
		}
		n.dnsCursor = index + 1
		if n.dnsCursor == len(n.dnsQueries) {
			n.dnsCursor = 0
		}
		if query.state == dnsQueryWaiting {
			if query.retry > 1 {
				query.retry--
				return 0, true, nil
			}
			if query.attempts >= n.dnsConfig.MaxAttempts {
				query.failLocked(nscore.FailureTimedOut, errors.New("DNS response service-attempt limit reached"))
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
		*ipFrame.SourceAddr() = n.ipv4Address.As4()
		*ipFrame.DestinationAddr() = n.dnsConfig.Server.As4()
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
		query.retry = n.dnsConfig.RetryServiceAttempts
		query.state = dnsQueryWaiting
		return frameBytes, true, nil
	}
	return 0, false, nil
}

func (n *Namespace) ingressDNSLocked(frame []byte) (bool, error) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || ethernetFrame.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return false, err
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		return false, err
	}
	version, headerWords := ipFrame.VersionAndIHL()
	if version != 4 || headerWords < 5 || ipFrame.Protocol() != lneto.IPProtoUDP || netip.AddrFrom4(*ipFrame.DestinationAddr()) != n.ipv4Address {
		return false, nil
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		return false, nil
	}
	query := n.dnsByPort[udpFrame.DestinationPort()]
	if query == nil || query.state == dnsQueryClosed || netip.AddrFrom4(*ipFrame.SourceAddr()) != n.dnsConfig.Server || udpFrame.SourcePort() != lnetodns.ServerPort {
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
	if len(payload) > n.dnsConfig.MaxResponseBytes {
		query.failLocked(nscore.FailureMessageTooLarge, lneto.ErrShortBuffer)
		return true, nil
	}
	records, response, failure, err := parseDNSResponse(payload, query.txid, query.request, int(n.dnsConfig.MaxRecords))
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
	name, err := lnetodns.NewName(request.Name)
	if err != nil {
		return nil, err
	}
	questions := make([]lnetodns.Question, 0, 2)
	if request.Types&dnsns.RecordsA != 0 {
		questions = append(questions, lnetodns.Question{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET})
	}
	if request.Types&dnsns.RecordsAAAA != 0 {
		questions = append(questions, lnetodns.Question{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET})
	}
	var edns lnetodns.Resource
	edns.SetEDNS0(uint16(maxResponseBytes), 0, 0, nil)
	message := lnetodns.Message{Questions: questions, Additionals: []lnetodns.Resource{edns}}
	return message.AppendTo(make([]byte, 0, message.Len()), txid, lnetodns.NewClientHeaderFlags(lnetodns.OpCodeQuery, true))
}

func parseDNSResponse(payload []byte, txid uint16, request dnsns.Request, maxRecords int) ([]dnsns.Record, bool, nscore.Failure, error) {
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

	candidates := make([]dnsns.Record, 0, min(int(frame.ANCount()), len(payload)/11))
	for range int(frame.ANCount()) {
		var record dnsns.Record
		var recognized bool
		record, recognized, offset, err = decodeDNSAnswer(payload, offset, request.Types)
		if err != nil {
			return nil, true, nscore.FailureIO, err
		}
		if recognized {
			candidates = append(candidates, record)
		}
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
	records, failure, err := selectDNSAnswers(candidates, request, maxRecords)
	if err != nil {
		return nil, true, failure, err
	}
	return records, true, 0, nil
}

func validateDNSQuestions(payload []byte, offset int, count uint16, request dnsns.Request) (int, error) {
	types := make([]lnetodns.Type, 0, 2)
	if request.Types&dnsns.RecordsA != 0 {
		types = append(types, lnetodns.TypeA)
	}
	if request.Types&dnsns.RecordsAAAA != 0 {
		types = append(types, lnetodns.TypeAAAA)
	}
	if int(count) != len(types) {
		return offset, lneto.ErrInvalidField
	}
	for _, expectedType := range types {
		name, next, err := decodeDNSName(payload, offset)
		if err != nil || next+4 > len(payload) {
			if err == nil {
				err = lneto.ErrTruncatedFrame
			}
			return offset, err
		}
		typ := lnetodns.Type(binary.BigEndian.Uint16(payload[next : next+2]))
		class := lnetodns.Class(binary.BigEndian.Uint16(payload[next+2 : next+4]))
		if name != request.Name || typ != expectedType || class != lnetodns.ClassINET {
			return offset, lneto.ErrInvalidField
		}
		offset = next + 4
	}
	return offset, nil
}

func decodeDNSAnswer(payload []byte, offset int, requested dnsns.RecordTypes) (record dnsns.Record, recognized bool, nextOffset int, err error) {
	name, next, err := decodeDNSName(payload, offset)
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
		if requested&dnsns.RecordsA == 0 {
			return record, false, dataEnd, nil
		}
		record = dnsns.Record{Name: name, Type: dnsns.RecordA, TTLSeconds: ttl, Address: netip.AddrFrom4([4]byte(payload[dataStart:dataEnd]))}
	case lnetodns.TypeAAAA:
		if length != 16 {
			return record, false, offset, lneto.ErrInvalidLengthField
		}
		if requested&dnsns.RecordsAAAA == 0 {
			return record, false, dataEnd, nil
		}
		record = dnsns.Record{Name: name, Type: dnsns.RecordAAAA, TTLSeconds: ttl, Address: netip.AddrFrom16([16]byte(payload[dataStart:dataEnd]))}
	case lnetodns.TypeCNAME:
		canonical, consumed, err := decodeDNSName(payload, dataStart)
		if err != nil || consumed != dataEnd {
			if err == nil {
				err = lneto.ErrInvalidLengthField
			}
			return record, false, offset, err
		}
		record = dnsns.Record{Name: name, Type: dnsns.RecordCNAME, TTLSeconds: ttl, CanonicalName: canonical}
	default:
		return record, false, dataEnd, nil
	}
	return record, true, dataEnd, nil
}

func skipDNSResource(payload []byte, offset int) (int, error) {
	_, next, err := decodeDNSName(payload, offset)
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
	current := request.Name
	visited := make(map[string]struct{}, len(candidates)+1)
	for {
		if _, exists := visited[current]; exists {
			return nil, nscore.FailureIO, lneto.ErrInvalidField
		}
		visited[current] = struct{}{}
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
	if offset < 0 || offset >= len(message) {
		return "", offset, lneto.ErrTruncatedFrame
	}
	labels := make([]string, 0, 4)
	position := offset
	next := -1
	for pointers := 0; ; {
		if position >= len(message) {
			return "", offset, lneto.ErrTruncatedFrame
		}
		length := int(message[position])
		switch length & 0xc0 {
		case 0:
			position++
			if length == 0 {
				if next < 0 {
					next = position
				}
				name := strings.ToLower(strings.Join(labels, "."))
				if name == "" || len(name) > 253 {
					return "", offset, lneto.ErrInvalidAddr
				}
				return name, next, nil
			}
			if length > 63 || position+length > len(message) {
				return "", offset, lneto.ErrTruncatedFrame
			}
			labels = append(labels, string(message[position:position+length]))
			position += length
		case 0xc0:
			if position+1 >= len(message) {
				return "", offset, lneto.ErrTruncatedFrame
			}
			if next < 0 {
				next = position + 2
			}
			position = (length^0xc0)<<8 | int(message[position+1])
			pointers++
			if pointers > 10 || position >= len(message) {
				return "", offset, lneto.ErrInvalidField
			}
		default:
			return "", offset, lneto.ErrInvalidField
		}
	}
}

func dnsRetainedBytes(config DNSConfig) uint64 {
	return uint64(config.MaxResponseBytes) + uint64(config.MaxRecords)*(2*254+16) + 2*254
}

func validDNSConfig(config DNSConfig, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxQueries == 0 {
		return config == (DNSConfig{})
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	return config.Server.Is4() && !config.Server.Is4In6() && !config.Server.IsUnspecified() && config.Server.Zone() == "" &&
		config.MaxRecords > 0 && config.MaxResponseBytes >= lnetodns.MaxSizeUDP && config.MaxResponseBytes <= mtu-28 &&
		config.MaxResponseBytes <= int(^uint16(0)) && config.MaxAttempts > 0 && config.RetryServiceAttempts > 0
}

func (n *Namespace) allocateDNSPortLocked() (*lnetocore.UDPPortLease, bool) {
	attempts := int(n.dnsConfig.MaxQueries) + len(n.udpOrder) + 1
	lease, next, ok := n.core.TryLeaseUDPPortRangeLocked(n.nextDNSPort, firstEphemeralDNSPort, attempts)
	if ok {
		n.nextDNSPort = next
	}
	return lease, ok
}

func removeDNSQuery(owner *Namespace, target *dnsQuery) {
	if owner == nil {
		return
	}
	for i, query := range owner.dnsQueries {
		if query != target {
			continue
		}
		copy(owner.dnsQueries[i:], owner.dnsQueries[i+1:])
		owner.dnsQueries[len(owner.dnsQueries)-1] = nil
		owner.dnsQueries = owner.dnsQueries[:len(owner.dnsQueries)-1]
		if len(owner.dnsQueries) == 0 {
			owner.dnsCursor = 0
		} else if owner.dnsCursor > i {
			owner.dnsCursor--
		} else if owner.dnsCursor >= len(owner.dnsQueries) {
			owner.dnsCursor = 0
		}
		return
	}
}
