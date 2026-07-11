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
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ namespace.DNSQuery = (*dnsQuery)(nil)

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
	request   namespace.DNSRequest
	localPort uint16
	txid      uint16
	packet    []byte
	records   []namespace.DNSRecord
	cursor    int
	attempts  uint16
	retry     uint16
	state     dnsQueryState
	failure   error

	resource *quota.Allocation
	queued   *quota.Allocation
	work     *quota.Allocation
}

func (n *Namespace) tryResolve(request namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	if n == nil {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.stack == nil {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if !request.Valid() {
		return nil, 0, namespace.Fail(namespace.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.dnsConfig.MaxQueries == 0 {
		return nil, 0, namespace.Fail(namespace.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !n.policy.CheckDNS(policy.OperationDNSResolve, request.Name) {
		return nil, 0, namespace.Fail(namespace.FailureAccessDenied, errPolicyDenied)
	}
	if len(n.dnsQueries) == int(n.dnsConfig.MaxQueries) {
		return nil, 0, namespace.Fail(namespace.FailureResourceLimit, lneto.ErrExhausted)
	}
	localPort, ok := n.allocateDNSPortLocked()
	if !ok {
		return nil, 0, namespace.Fail(namespace.FailureResourceLimit, lneto.ErrExhausted)
	}
	packet, err := buildDNSQueryPacket(request, n.nextDNSTxID, n.dnsConfig.MaxResponseBytes)
	if err != nil {
		return nil, 0, mapError(err)
	}

	resourceReservation, err := n.quotas.ReserveResource(quota.ResourceDNS, 1)
	if err != nil {
		return nil, 0, mapError(err)
	}
	retainedBytes := dnsRetainedBytes(n.dnsConfig)
	queuedReservation, err := n.quotas.ReserveQueuedBytes(retainedBytes)
	if err != nil {
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	workUnits := uint64(1)
	if request.Types == namespace.DNSRecordsA|namespace.DNSRecordsAAAA {
		workUnits = 2
	}
	workReservation, err := n.quotas.ReserveDNSWork(workUnits)
	if err != nil {
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	resourceAllocation, ok := resourceReservation.Commit()
	if !ok {
		workReservation.Rollback()
		queuedReservation.Rollback()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	queuedAllocation, ok := queuedReservation.Commit()
	if !ok {
		workReservation.Rollback()
		resourceAllocation.Release()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	workAllocation, ok := workReservation.Commit()
	if !ok {
		queuedAllocation.Release()
		resourceAllocation.Release()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}

	query := &dnsQuery{
		owner: n, request: request, localPort: localPort, txid: n.nextDNSTxID,
		packet: packet, records: make([]namespace.DNSRecord, 0, n.dnsConfig.MaxRecords),
		state: dnsQueryPending, resource: resourceAllocation, queued: queuedAllocation, work: workAllocation,
	}
	n.nextDNSTxID++
	if n.nextDNSTxID == 0 {
		n.nextDNSTxID = 1
	}
	n.dnsByPort[localPort] = query
	n.dnsQueries = append(n.dnsQueries, query)
	return query, namespace.ProgressInProgress, nil
}

func (q *dnsQuery) Readiness() namespace.Readiness {
	if q == nil || q.owner == nil {
		return namespace.ReadyClosed
	}
	q.owner.mu.Lock()
	defer q.owner.mu.Unlock()
	if q.state == dnsQueryClosed || q.owner.closed {
		return namespace.ReadyClosed
	}
	if q.state == dnsQueryFailed {
		return namespace.ReadyError
	}
	if q.state == dnsQueryDone {
		return namespace.ReadyDNSResult
	}
	return 0
}

func (q *dnsQuery) TryNext() (namespace.DNSRecord, namespace.DNSNext, error) {
	if q == nil || q.owner == nil {
		return namespace.DNSRecord{}, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	q.owner.mu.Lock()
	defer q.owner.mu.Unlock()
	if q.state == dnsQueryClosed || q.owner.closed {
		return namespace.DNSRecord{}, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if q.state == dnsQueryFailed {
		return namespace.DNSRecord{}, 0, q.failure
	}
	if q.cursor < len(q.records) {
		record := q.records[q.cursor]
		q.cursor++
		if !record.Valid() {
			return namespace.DNSRecord{}, 0, namespace.Fail(namespace.FailureIO, lneto.ErrBadState)
		}
		return record, namespace.DNSNextReady, nil
	}
	if q.state == dnsQueryDone {
		return namespace.DNSRecord{}, namespace.DNSNextEOF, nil
	}
	return namespace.DNSRecord{}, namespace.DNSNextWouldBlock, nil
}

func (q *dnsQuery) Cancel() error {
	if q == nil || q.owner == nil {
		return namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	q.owner.mu.Lock()
	defer q.owner.mu.Unlock()
	if q.state == dnsQueryClosed || q.owner.closed {
		return namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if q.state == dnsQueryDone || q.state == dnsQueryFailed {
		return namespace.Fail(namespace.FailureInvalidState, lneto.ErrBadState)
	}
	q.failLocked(namespace.FailureCanceled, errors.New("DNS query canceled"))
	return nil
}

func (q *dnsQuery) Close() error {
	if q == nil || q.owner == nil {
		return nil
	}
	q.owner.mu.Lock()
	defer q.owner.mu.Unlock()
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
		q.records[i] = namespace.DNSRecord{}
	}
	q.records = nil
	q.request = namespace.DNSRequest{}
	q.failure = nil
	q.releaseQuotaLocked()
	return nil
}

func (q *dnsQuery) failLocked(failure namespace.Failure, cause error) {
	if q.state == dnsQueryClosed || q.state == dnsQueryDone || q.state == dnsQueryFailed {
		return
	}
	q.state = dnsQueryFailed
	q.failure = namespace.Fail(failure, cause)
	q.releaseWorkLocked()
}

func (q *dnsQuery) completeLocked(records []namespace.DNSRecord) {
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
				query.failLocked(namespace.FailureTimedOut, errors.New("DNS response service-attempt limit reached"))
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
		ipFrame.SetID(n.nextIPv4ID)
		n.nextIPv4ID++
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
		query.failLocked(namespace.FailureIO, err)
		return true, nil
	}
	if ipFrame.CalculateHeaderCRC() != 0 || ipFrame.Flags().MoreFragments() || ipFrame.Flags().FragmentOffset() != 0 {
		query.failLocked(namespace.FailureIO, lneto.ErrBadCRC)
		return true, nil
	}
	udpFrame.ValidateSize(&validator)
	if err := validator.ErrPop(); err != nil {
		query.failLocked(namespace.FailureIO, err)
		return true, nil
	}
	udpLength := udpFrame.Length()
	if udpFrame.CRC() != 0 {
		var checksum lneto.CRC791
		ipFrame.CRCWriteUDPPseudo(&checksum, udpLength)
		if checksum.PayloadSum16(udpFrame.RawData()[:udpLength]) != 0 {
			query.failLocked(namespace.FailureIO, lneto.ErrBadCRC)
			return true, nil
		}
	}
	payload := udpFrame.RawData()[8:udpLength]
	if len(payload) > n.dnsConfig.MaxResponseBytes {
		query.failLocked(namespace.FailureMessageTooLarge, lneto.ErrShortBuffer)
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

func buildDNSQueryPacket(request namespace.DNSRequest, txid uint16, maxResponseBytes int) ([]byte, error) {
	name, err := lnetodns.NewName(request.Name)
	if err != nil {
		return nil, err
	}
	questions := make([]lnetodns.Question, 0, 2)
	if request.Types&namespace.DNSRecordsA != 0 {
		questions = append(questions, lnetodns.Question{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET})
	}
	if request.Types&namespace.DNSRecordsAAAA != 0 {
		questions = append(questions, lnetodns.Question{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET})
	}
	var edns lnetodns.Resource
	edns.SetEDNS0(uint16(maxResponseBytes), 0, 0, nil)
	message := lnetodns.Message{Questions: questions, Additionals: []lnetodns.Resource{edns}}
	return message.AppendTo(make([]byte, 0, message.Len()), txid, lnetodns.NewClientHeaderFlags(lnetodns.OpCodeQuery, true))
}

func parseDNSResponse(payload []byte, txid uint16, request namespace.DNSRequest, maxRecords int) ([]namespace.DNSRecord, bool, namespace.Failure, error) {
	frame, err := lnetodns.NewFrame(payload)
	if err != nil {
		return nil, true, namespace.FailureIO, err
	}
	flags := frame.Flags()
	if frame.TxID() != txid || !flags.IsResponse() {
		return nil, false, 0, nil
	}
	if flags.OpCode() != lnetodns.OpCodeQuery {
		return nil, true, namespace.FailureIO, lneto.ErrInvalidField
	}
	offset, err := validateDNSQuestions(payload, lnetodns.SizeHeader, frame.QDCount(), request)
	if err != nil {
		return nil, true, namespace.FailureIO, err
	}
	if flags.IsTruncated() {
		return nil, true, namespace.FailureTemporary, lneto.ErrTruncatedFrame
	}
	if rcode := flags.ResponseCode(); rcode != lnetodns.RCodeSuccess {
		failure := namespace.FailureTemporary
		switch rcode {
		case lnetodns.RCodeNameError:
			failure = namespace.FailureNameNotFound
		case lnetodns.RCodeFormatError:
			failure = namespace.FailureInvalidArgument
		case lnetodns.RCodeNotImplemented:
			failure = namespace.FailureNotSupported
		case lnetodns.RCodeRefused:
			failure = namespace.FailureAccessDenied
		}
		return nil, true, failure, rcode
	}

	candidates := make([]namespace.DNSRecord, 0, min(int(frame.ANCount()), len(payload)/11))
	for range int(frame.ANCount()) {
		var record namespace.DNSRecord
		var recognized bool
		record, recognized, offset, err = decodeDNSAnswer(payload, offset, request.Types)
		if err != nil {
			return nil, true, namespace.FailureIO, err
		}
		if recognized {
			candidates = append(candidates, record)
		}
	}
	for range int(frame.NSCount()) + int(frame.ARCount()) {
		offset, err = skipDNSResource(payload, offset)
		if err != nil {
			return nil, true, namespace.FailureIO, err
		}
	}
	if offset != len(payload) {
		return nil, true, namespace.FailureIO, lneto.ErrInvalidLengthField
	}
	records, failure, err := selectDNSAnswers(candidates, request, maxRecords)
	if err != nil {
		return nil, true, failure, err
	}
	return records, true, 0, nil
}

func validateDNSQuestions(payload []byte, offset int, count uint16, request namespace.DNSRequest) (int, error) {
	types := make([]lnetodns.Type, 0, 2)
	if request.Types&namespace.DNSRecordsA != 0 {
		types = append(types, lnetodns.TypeA)
	}
	if request.Types&namespace.DNSRecordsAAAA != 0 {
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

func decodeDNSAnswer(payload []byte, offset int, requested namespace.DNSRecordTypes) (record namespace.DNSRecord, recognized bool, nextOffset int, err error) {
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
		if requested&namespace.DNSRecordsA == 0 {
			return record, false, dataEnd, nil
		}
		record = namespace.DNSRecord{Name: name, Type: namespace.DNSRecordA, TTLSeconds: ttl, Address: netip.AddrFrom4([4]byte(payload[dataStart:dataEnd]))}
	case lnetodns.TypeAAAA:
		if length != 16 {
			return record, false, offset, lneto.ErrInvalidLengthField
		}
		if requested&namespace.DNSRecordsAAAA == 0 {
			return record, false, dataEnd, nil
		}
		record = namespace.DNSRecord{Name: name, Type: namespace.DNSRecordAAAA, TTLSeconds: ttl, Address: netip.AddrFrom16([16]byte(payload[dataStart:dataEnd]))}
	case lnetodns.TypeCNAME:
		canonical, consumed, err := decodeDNSName(payload, dataStart)
		if err != nil || consumed != dataEnd {
			if err == nil {
				err = lneto.ErrInvalidLengthField
			}
			return record, false, offset, err
		}
		record = namespace.DNSRecord{Name: name, Type: namespace.DNSRecordCNAME, TTLSeconds: ttl, CanonicalName: canonical}
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

func selectDNSAnswers(candidates []namespace.DNSRecord, request namespace.DNSRequest, maxRecords int) ([]namespace.DNSRecord, namespace.Failure, error) {
	records := make([]namespace.DNSRecord, 0, min(maxRecords, len(candidates)))
	current := request.Name
	visited := make(map[string]struct{}, len(candidates)+1)
	for {
		if _, exists := visited[current]; exists {
			return nil, namespace.FailureIO, lneto.ErrInvalidField
		}
		visited[current] = struct{}{}
		var cname namespace.DNSRecord
		for _, candidate := range candidates {
			if candidate.Type != namespace.DNSRecordCNAME || candidate.Name != current {
				continue
			}
			if !candidate.Valid() {
				return nil, namespace.FailureIO, lneto.ErrInvalidField
			}
			if cname.Type == 0 {
				cname = candidate
				continue
			}
			if cname.CanonicalName != candidate.CanonicalName {
				return nil, namespace.FailureIO, lneto.ErrInvalidField
			}
		}
		if cname.Type == 0 {
			break
		}
		var err error
		records, err = appendUniqueDNSRecord(records, cname, maxRecords)
		if err != nil {
			return nil, namespace.FailureResourceLimit, err
		}
		current = cname.CanonicalName
	}
	for _, candidate := range candidates {
		if candidate.Name != current || candidate.Type == namespace.DNSRecordCNAME {
			continue
		}
		if !candidate.Valid() {
			return nil, namespace.FailureIO, lneto.ErrInvalidField
		}
		var err error
		records, err = appendUniqueDNSRecord(records, candidate, maxRecords)
		if err != nil {
			return nil, namespace.FailureResourceLimit, err
		}
	}
	return records, 0, nil
}

func appendUniqueDNSRecord(records []namespace.DNSRecord, record namespace.DNSRecord, maxRecords int) ([]namespace.DNSRecord, error) {
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

func (n *Namespace) allocateDNSPortLocked() (uint16, bool) {
	attempts := int(n.dnsConfig.MaxQueries) + len(n.udpOrder) + 1
	port := n.nextDNSPort
	if port < firstEphemeralDNSPort {
		port = firstEphemeralDNSPort
	}
	for range attempts {
		if n.dnsByPort[port] == nil && n.udpByPort[port] == nil {
			n.nextDNSPort = port + 1
			if n.nextDNSPort < firstEphemeralDNSPort {
				n.nextDNSPort = firstEphemeralDNSPort
			}
			return port, true
		}
		port++
		if port < firstEphemeralDNSPort {
			port = firstEphemeralDNSPort
		}
	}
	return 0, false
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
