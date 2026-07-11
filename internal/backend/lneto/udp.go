package lnetobackend

import (
	"errors"
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ namespace.UDPSocket = (*udpSocket)(nil)

var errPolicyDenied = errors.New("net: endpoint policy denied operation")

// udpSocket uses adapter-owned fixed queues because lneto's exported high-level
// UDP wrappers back off and its immediate mux cannot represent an empty payload.
// Packet encoding and validation still use lneto's Ethernet/IPv4/UDP codecs.
type udpSocket struct {
	owner *Namespace
	local namespace.Endpoint
	rx    datagramQueue
	tx    datagramQueue

	resource *quota.Allocation
	queued   *quota.Allocation
	closed   bool
}

type datagramQueue struct {
	storage    []byte
	lengths    []int
	endpoints  []namespace.Endpoint
	maxPayload int
	head       int
	count      int
	bytes      int
	byteLimit  int
}

func newDatagramQueue(datagrams, maxPayload, byteLimit int) datagramQueue {
	return datagramQueue{
		storage:    make([]byte, datagrams*maxPayload),
		lengths:    make([]int, datagrams),
		endpoints:  make([]namespace.Endpoint, datagrams),
		maxPayload: maxPayload,
		byteLimit:  byteLimit,
	}
}

func (q *datagramQueue) push(payload []byte, endpoint namespace.Endpoint) bool {
	if q.count == len(q.lengths) || len(payload) > q.maxPayload || len(payload) > q.byteLimit-q.bytes {
		return false
	}
	index := q.head + q.count
	if index >= len(q.lengths) {
		index -= len(q.lengths)
	}
	if q.maxPayload != 0 {
		copy(q.slot(index), payload)
	}
	q.lengths[index] = len(payload)
	q.endpoints[index] = endpoint
	q.count++
	q.bytes += len(payload)
	return true
}

func (q *datagramQueue) peek() ([]byte, namespace.Endpoint, bool) {
	if q.count == 0 {
		return nil, namespace.Endpoint{}, false
	}
	length := q.lengths[q.head]
	if q.maxPayload == 0 {
		return nil, q.endpoints[q.head], true
	}
	return q.slot(q.head)[:length], q.endpoints[q.head], true
}

func (q *datagramQueue) pop(dst []byte) (namespace.DatagramResult, bool) {
	payload, endpoint, ok := q.peek()
	if !ok {
		return namespace.DatagramResult{}, false
	}
	length := q.lengths[q.head]
	copied := copy(dst, payload)
	q.discardHead()
	return namespace.DatagramResult{
		Copied:        copied,
		DatagramBytes: length,
		Source:        endpoint,
		Truncated:     copied < length,
		Ready:         true,
	}, true
}

func (q *datagramQueue) discardHead() {
	length := q.lengths[q.head]
	if q.maxPayload != 0 {
		clear(q.slot(q.head))
	}
	q.lengths[q.head] = 0
	q.endpoints[q.head] = namespace.Endpoint{}
	q.head++
	if q.head == len(q.lengths) {
		q.head = 0
	}
	q.count--
	q.bytes -= length
}

func (q *datagramQueue) slot(index int) []byte {
	start := index * q.maxPayload
	return q.storage[start : start+q.maxPayload]
}

func (q *datagramQueue) clear() {
	clear(q.storage)
	clear(q.lengths)
	clear(q.endpoints)
	q.storage = nil
	q.lengths = nil
	q.endpoints = nil
	q.head = 0
	q.count = 0
	q.bytes = 0
}

func (n *Namespace) tryBindUDP(local namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	if n == nil {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.stack == nil {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if !local.Valid() || !local.Address.Is4() || local.Port == 0 {
		return nil, 0, namespace.Fail(namespace.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.udpConfig.MaxSockets == 0 {
		return nil, 0, namespace.Fail(namespace.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !local.Address.IsUnspecified() && local.Address != n.ipv4Address {
		return nil, 0, namespace.Fail(namespace.FailureAddressUnavailable, lneto.ErrInvalidAddr)
	}
	if !n.policy.CheckEndpoint(policy.OperationUDPBind, local.Address, local.Port) {
		return nil, 0, namespace.Fail(namespace.FailureAccessDenied, errPolicyDenied)
	}
	if len(n.udpOrder) == int(n.udpConfig.MaxSockets) {
		return nil, 0, namespace.Fail(namespace.FailureResourceLimit, lneto.ErrExhausted)
	}
	if socket := n.udpByPort[local.Port]; socket != nil && !socket.closed {
		return nil, 0, namespace.Fail(namespace.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}
	if query := n.dnsByPort[local.Port]; query != nil && query.state != dnsQueryClosed {
		return nil, 0, namespace.Fail(namespace.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}

	resourceReservation, err := n.quotas.ReserveResource(quota.ResourceUDP, 1)
	if err != nil {
		return nil, 0, mapError(err)
	}
	retainedBytes := uint64(n.udpConfig.MaxPayloadBytes) * uint64(n.udpConfig.ReceiveDatagrams+n.udpConfig.TransmitDatagrams)
	queuedReservation, err := n.quotas.ReserveQueuedBytes(retainedBytes)
	if err != nil {
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	resourceAllocation, ok := resourceReservation.Commit()
	if !ok {
		queuedReservation.Rollback()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	queuedAllocation, ok := queuedReservation.Commit()
	if !ok {
		resourceAllocation.Release()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	socket := &udpSocket{
		owner:    n,
		local:    local,
		rx:       newDatagramQueue(n.udpConfig.ReceiveDatagrams, n.udpConfig.MaxPayloadBytes, n.udpConfig.ReceiveBytes),
		tx:       newDatagramQueue(n.udpConfig.TransmitDatagrams, n.udpConfig.MaxPayloadBytes, n.udpConfig.TransmitBytes),
		resource: resourceAllocation,
		queued:   queuedAllocation,
	}
	n.udpByPort[local.Port] = socket
	n.udpOrder = append(n.udpOrder, socket)
	return socket, namespace.ProgressDone, nil
}

func (s *udpSocket) LocalEndpoint() namespace.Endpoint {
	if s == nil {
		return namespace.Endpoint{}
	}
	return s.local
}

func (s *udpSocket) Readiness() namespace.Readiness {
	if s == nil || s.owner == nil {
		return namespace.ReadyClosed
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed {
		return namespace.ReadyClosed
	}
	var ready namespace.Readiness
	if s.rx.count > 0 {
		ready |= namespace.ReadyReadable
	}
	if s.tx.count < len(s.tx.lengths) {
		ready |= namespace.ReadyWritable
	}
	return ready
}

func (s *udpSocket) TryReceive(dst []byte) (namespace.DatagramResult, error) {
	if s == nil || s.owner == nil {
		return namespace.DatagramResult{}, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed {
		return namespace.DatagramResult{}, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	result, ok := s.rx.pop(dst)
	if !ok {
		return namespace.DatagramResult{}, nil
	}
	if !result.Valid(len(dst)) {
		return namespace.DatagramResult{}, namespace.Fail(namespace.FailureIO, lneto.ErrBadState)
	}
	return result, nil
}

func (s *udpSocket) TrySend(payload []byte, remote namespace.Endpoint) (namespace.Progress, error) {
	if s == nil || s.owner == nil {
		return 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed {
		return 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if !remote.Valid() || !remote.Address.Is4() || remote.Port == 0 {
		return 0, namespace.Fail(namespace.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if !s.owner.policy.CheckEndpoint(policy.OperationUDPSend, remote.Address, remote.Port) {
		return 0, namespace.Fail(namespace.FailureAccessDenied, errPolicyDenied)
	}
	if len(payload) > s.owner.udpConfig.MaxPayloadBytes {
		return 0, namespace.Fail(namespace.FailureMessageTooLarge, lneto.ErrShortBuffer)
	}
	if !s.tx.push(payload, remote) {
		return namespace.ProgressWouldBlock, nil
	}
	return namespace.ProgressDone, nil
}

func (s *udpSocket) Close() error {
	if s == nil || s.owner == nil {
		return nil
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	return s.closeLocked()
}

func (s *udpSocket) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.owner != nil && s.owner.udpByPort != nil {
		delete(s.owner.udpByPort, s.local.Port)
		for i, socket := range s.owner.udpOrder {
			if socket != s {
				continue
			}
			copy(s.owner.udpOrder[i:], s.owner.udpOrder[i+1:])
			s.owner.udpOrder[len(s.owner.udpOrder)-1] = nil
			s.owner.udpOrder = s.owner.udpOrder[:len(s.owner.udpOrder)-1]
			if len(s.owner.udpOrder) == 0 {
				s.owner.udpCursor = 0
			} else if s.owner.udpCursor > i {
				s.owner.udpCursor--
			} else if s.owner.udpCursor >= len(s.owner.udpOrder) {
				s.owner.udpCursor = 0
			}
			break
		}
	}
	s.rx.clear()
	s.tx.clear()
	if s.queued != nil {
		s.queued.Release()
		s.queued = nil
	}
	if s.resource != nil {
		s.resource.Release()
		s.resource = nil
	}
	return nil
}

func (n *Namespace) hasUDPEgressLocked() bool {
	for _, socket := range n.udpOrder {
		if !socket.closed && socket.tx.count > 0 {
			return true
		}
	}
	return false
}

func (n *Namespace) egressUDPLocked(dst []byte) (int, error) {
	if len(n.udpOrder) == 0 {
		return 0, nil
	}
	var selected *udpSocket
	for offset := 0; offset < len(n.udpOrder); offset++ {
		index := n.udpCursor + offset
		if index >= len(n.udpOrder) {
			index -= len(n.udpOrder)
		}
		socket := n.udpOrder[index]
		if !socket.closed && socket.tx.count > 0 {
			selected = socket
			n.udpCursor = index + 1
			if n.udpCursor == len(n.udpOrder) {
				n.udpCursor = 0
			}
			break
		}
	}
	if selected == nil {
		return 0, nil
	}
	payload, remote, _ := selected.tx.peek()
	frameBytes := 14 + 20 + 8 + len(payload)
	if len(dst) < frameBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:frameBytes]
	clear(frame)
	ethernetFrame, _ := ethernet.NewFrame(frame)
	*ethernetFrame.DestinationHardwareAddr() = n.gatewayHardwareAddress
	*ethernetFrame.SourceHardwareAddr() = n.hardwareAddress
	ethernetFrame.SetEtherType(ethernet.TypeIPv4)
	ipFrame, _ := ipv4.NewFrame(frame[14:])
	ipFrame.SetVersionAndIHL(4, 5)
	ipFrame.SetTotalLength(uint16(20 + 8 + len(payload)))
	ipFrame.SetID(n.nextIPv4ID)
	n.nextIPv4ID++
	ipFrame.SetFlags(ipv4.FlagDontFragment)
	ipFrame.SetTTL(64)
	ipFrame.SetProtocol(lneto.IPProtoUDP)
	*ipFrame.SourceAddr() = n.ipv4Address.As4()
	*ipFrame.DestinationAddr() = remote.Address.As4()
	ipFrame.SetCRC(0)
	ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
	udpFrame, _ := lnetoudp.NewFrame(frame[14+20:])
	udpFrame.SetSourcePort(selected.local.Port)
	udpFrame.SetDestinationPort(remote.Port)
	udpFrame.SetLength(uint16(8 + len(payload)))
	copy(frame[14+20+8:], payload)
	udpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
	udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
	selected.tx.discardHead()
	return frameBytes, nil
}

func (n *Namespace) ingressUDPLocked(frame []byte) (bool, error) {
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
	var validator lneto.Validator
	ipFrame.ValidateExceptCRC(&validator)
	if err := validator.ErrPop(); err != nil {
		return true, err
	}
	if ipFrame.CalculateHeaderCRC() != 0 || ipFrame.Flags().MoreFragments() || ipFrame.Flags().FragmentOffset() != 0 {
		return true, lneto.ErrBadCRC
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		return true, err
	}
	udpFrame.ValidateSize(&validator)
	if err := validator.ErrPop(); err != nil {
		return true, err
	}
	udpLength := udpFrame.Length()
	if udpFrame.CRC() != 0 {
		var checksum lneto.CRC791
		ipFrame.CRCWriteUDPPseudo(&checksum, udpLength)
		if checksum.PayloadSum16(udpFrame.RawData()[:udpLength]) != 0 {
			return true, lneto.ErrBadCRC
		}
	}
	selected := n.udpByPort[udpFrame.DestinationPort()]
	if selected == nil || selected.closed {
		return false, nil
	}
	source := namespace.Endpoint{Address: netip.AddrFrom4(*ipFrame.SourceAddr()), Port: udpFrame.SourcePort()}
	if !source.Valid() || source.Port == 0 {
		return true, lneto.ErrInvalidAddr
	}
	payload := udpFrame.RawData()[8:udpLength]
	_ = selected.rx.push(payload, source) // A full receive queue drops this datagram.
	return true, nil
}
