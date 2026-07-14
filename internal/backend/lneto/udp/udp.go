package udp

import (
	"errors"
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ udpns.Socket = (*udpSocket)(nil)

var errPolicyDenied = errors.New("net: endpoint policy denied operation")

const (
	firstEphemeralUDPPort uint16 = 49152
	serviceOrder                 = 20
	closeOrder                   = 30
)

// Config fixes all storage allocated for each nonblocking UDP socket. Zero
// MaxSockets disables UDP truthfully.
type Config struct {
	MaxSockets        uint16
	ReceiveBytes      int
	TransmitBytes     int
	ReceiveDatagrams  int
	TransmitDatagrams int
	MaxPayloadBytes   int
}

// Adapter owns UDP sockets, fixed datagram queues, and frame codecs over one
// shared lneto core.
type Adapter struct {
	core                   *lnetocore.Namespace
	config                 Config
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte
	policy                 *policy.Policy
	quotas                 *quota.Account
	byPort                 map[uint16]*udpSocket
	sockets                []*udpSocket
	freeBackings           []udpSocketBacking
	nextPort               uint16
	cursor                 int
}

// New attaches UDP-local state and its bounded service participant to common.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || !ValidConfig(config, common.RequiredFrameBytesLocked()-14, common.PolicyLocked(), common.QuotasLocked(), true) ||
		(config.MaxSockets != 0 && !common.GatewayHardwareAddressUsableLocked()) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	n := &Adapter{
		core: common, config: config,
		hardwareAddress:        common.HardwareAddressLocked(),
		gatewayHardwareAddress: common.GatewayHardwareAddressLocked(), policy: common.PolicyLocked(), quotas: common.QuotasLocked(),
		nextPort: firstEphemeralUDPPort,
	}
	if config.MaxSockets == 0 {
		common.Unlock()
		return n, nil
	}
	n.byPort = make(map[uint16]*udpSocket, config.MaxSockets)
	n.sockets = make([]*udpSocket, 0, config.MaxSockets)
	n.freeBackings = make([]udpSocketBacking, 0, config.MaxSockets)
	common.Unlock()
	if err := common.Install(lnetocore.Participant{
		IngressOrder: serviceOrder,
		Ingress:      n.ingressLocked,
		EgressOrder:  serviceOrder,
		HasEgress:    n.hasEgressLocked,
		Egress: func(dst []byte) (int, bool, error) {
			written, err := n.egressLocked(dst)
			return written, written != 0, err
		},
		CloseOrder: closeOrder,
		Close:      n.CloseLocked,
	}); err != nil {
		return nil, err
	}
	return n, nil
}

// ValidConfig validates UDP-local finite storage and authority.
func ValidConfig(config Config, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxSockets == 0 {
		return config == (Config{})
	}
	if (requireAuthority && (compiled == nil || account == nil)) || config.ReceiveDatagrams <= 0 || config.TransmitDatagrams <= 0 ||
		config.MaxPayloadBytes < 0 || config.MaxPayloadBytes > mtu-28 || config.MaxPayloadBytes > int(^uint16(0)) {
		return false
	}
	maxInt := int(^uint(0) >> 1)
	if config.ReceiveDatagrams > maxInt-config.TransmitDatagrams {
		return false
	}
	totalDatagrams := config.ReceiveDatagrams + config.TransmitDatagrams
	if config.MaxPayloadBytes != 0 && totalDatagrams > maxInt/config.MaxPayloadBytes {
		return false
	}
	return config.ReceiveBytes >= config.ReceiveDatagrams*config.MaxPayloadBytes &&
		config.TransmitBytes >= config.TransmitDatagrams*config.MaxPayloadBytes
}

// udpSocket uses adapter-owned fixed queues because lneto's exported high-level
// UDP wrappers back off and its immediate mux cannot represent an empty payload.
// Packet encoding and validation still use lneto's Ethernet/IPv4/UDP codecs.
type udpSocket struct {
	owner *Adapter
	local nscore.Endpoint
	rx    datagramQueue
	tx    datagramQueue

	portLease lnetocore.UDPPortLease
	retained  quota.Charge
	closed    bool
}

type datagramQueue struct {
	storage    []byte
	slots      []datagramSlot
	maxPayload int
	head       int
	count      int
	bytes      int
	byteLimit  int
}

func (n *Adapter) acquireSocketLocked(local nscore.Endpoint) *udpSocket {
	if n == nil {
		return nil
	}
	var backing udpSocketBacking
	if len(n.freeBackings) == 0 {
		backing = newSocketBackings(1, n.config)[0]
	} else {
		backing = n.freeBackings[len(n.freeBackings)-1]
		n.freeBackings = n.freeBackings[:len(n.freeBackings)-1]
	}
	socket := &udpSocket{owner: n, local: local}
	socket.rx.reset(backing.rxStorage, backing.rxSlots, n.config.MaxPayloadBytes, n.config.ReceiveBytes)
	socket.tx.reset(backing.txStorage, backing.txSlots, n.config.MaxPayloadBytes, n.config.TransmitBytes)
	return socket
}

func (n *Adapter) recycleSocketLocked(socket *udpSocket) {
	if n == nil || socket == nil {
		return
	}
	rxStorage, rxSlots := socket.rx.release()
	txStorage, txSlots := socket.tx.release()
	n.freeBackings = append(n.freeBackings, udpSocketBacking{
		rxStorage: rxStorage,
		txStorage: txStorage,
		rxSlots:   rxSlots,
		txSlots:   txSlots,
	})
	socket.local = nscore.Endpoint{}
	socket.portLease = lnetocore.UDPPortLease{}
	socket.retained = quota.Charge{}
	socket.closed = true
}

type datagramSlot struct {
	length   int
	endpoint nscore.Endpoint
}

type udpSocketBacking struct {
	rxStorage []byte
	txStorage []byte
	rxSlots   []datagramSlot
	txSlots   []datagramSlot
}

func newDatagramQueue(datagrams, maxPayload, byteLimit int) datagramQueue {
	return datagramQueue{
		storage:    make([]byte, datagrams*maxPayload),
		slots:      make([]datagramSlot, datagrams),
		maxPayload: maxPayload,
		byteLimit:  byteLimit,
	}
}

func newSocketDatagramQueues(config Config) (datagramQueue, datagramQueue) {
	backing := newSocketBackings(1, config)[0]
	return datagramQueue{
			storage: backing.rxStorage, slots: backing.rxSlots,
			maxPayload: config.MaxPayloadBytes, byteLimit: config.ReceiveBytes,
		}, datagramQueue{
			storage: backing.txStorage, slots: backing.txSlots,
			maxPayload: config.MaxPayloadBytes, byteLimit: config.TransmitBytes,
		}
}

func newSocketBackings(count int, config Config) []udpSocketBacking {
	if count == 0 {
		return nil
	}
	receiveDatagrams := config.ReceiveDatagrams
	totalDatagrams := receiveDatagrams + config.TransmitDatagrams
	storage := make([]byte, count*totalDatagrams*config.MaxPayloadBytes)
	slots := make([]datagramSlot, count*totalDatagrams)
	receiveBytes := receiveDatagrams * config.MaxPayloadBytes
	backings := make([]udpSocketBacking, count)
	for i := range backings {
		storageStart := i * totalDatagrams * config.MaxPayloadBytes
		slotStart := i * totalDatagrams
		backings[i] = udpSocketBacking{
			rxStorage: storage[storageStart : storageStart+receiveBytes : storageStart+receiveBytes],
			txStorage: storage[storageStart+receiveBytes : storageStart+totalDatagrams*config.MaxPayloadBytes],
			rxSlots:   slots[slotStart : slotStart+receiveDatagrams : slotStart+receiveDatagrams],
			txSlots:   slots[slotStart+receiveDatagrams : slotStart+totalDatagrams],
		}
	}
	return backings
}

func (q *datagramQueue) push(payload []byte, endpoint nscore.Endpoint) bool {
	if q.count == len(q.slots) || len(payload) > q.maxPayload || len(payload) > q.byteLimit-q.bytes {
		return false
	}
	index := q.head + q.count
	if index >= len(q.slots) {
		index -= len(q.slots)
	}
	if q.maxPayload != 0 {
		copy(q.slot(index), payload)
	}
	slot := &q.slots[index]
	slot.length = len(payload)
	slot.endpoint = endpoint
	q.count++
	q.bytes += len(payload)
	return true
}

func (q *datagramQueue) peek() ([]byte, nscore.Endpoint, bool) {
	if q.count == 0 {
		return nil, nscore.Endpoint{}, false
	}
	slot := &q.slots[q.head]
	if q.maxPayload == 0 {
		return nil, slot.endpoint, true
	}
	return q.slot(q.head)[:slot.length], slot.endpoint, true
}

func (q *datagramQueue) pop(dst []byte) (udpns.DatagramResult, bool) {
	payload, endpoint, ok := q.peek()
	if !ok {
		return udpns.DatagramResult{}, false
	}
	length := q.slots[q.head].length
	copied := copy(dst, payload)
	q.discardHead()
	return udpns.DatagramResult{
		Copied:        copied,
		DatagramBytes: length,
		Source:        endpoint,
		Truncated:     copied < length,
		Ready:         true,
	}, true
}

func (q *datagramQueue) discardHead() {
	slot := &q.slots[q.head]
	length := slot.length
	if length != 0 {
		clear(q.slot(q.head)[:length])
	}
	slot.length = 0
	slot.endpoint = nscore.Endpoint{}
	q.head++
	if q.head == len(q.slots) {
		q.head = 0
	}
	q.count--
	q.bytes -= length
}

func (q *datagramQueue) slot(index int) []byte {
	start := index * q.maxPayload
	return q.storage[start : start+q.maxPayload]
}

func (q *datagramQueue) reset(storage []byte, slots []datagramSlot, maxPayload, byteLimit int) {
	q.storage = storage
	q.slots = slots
	q.maxPayload = maxPayload
	q.head = 0
	q.count = 0
	q.bytes = 0
	q.byteLimit = byteLimit
}

func (q *datagramQueue) release() (storage []byte, slots []datagramSlot) {
	clear(q.storage)
	clear(q.slots)
	storage, slots = q.storage, q.slots
	q.storage = nil
	q.slots = nil
	q.maxPayload = 0
	q.head = 0
	q.count = 0
	q.bytes = 0
	q.byteLimit = 0
	return storage, slots
}

// TryBindUDP implements the narrow UDP namespace facet.
func (n *Adapter) TryBindUDP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.TryBind(local)
}

func (n *Adapter) TryBind(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	if n == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.core.Lock()
	defer n.core.Unlock()
	if n.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !local.Valid() || !local.Address.Is4() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.config.MaxSockets == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !local.Address.IsUnspecified() && local.Address != n.core.IPv4AddressLocked() {
		return nil, 0, nscore.Fail(nscore.FailureAddressUnavailable, lneto.ErrInvalidAddr)
	}
	if !n.policy.CheckEndpoint(policy.OperationUDPBind, local.Address, local.Port) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(n.sockets) == int(n.config.MaxSockets) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	requested := local
	socket := n.acquireSocketLocked(local)
	if socket == nil {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	if local.Port == 0 {
		attempts := int(n.config.MaxSockets) + n.core.UDPPortLeaseCountLocked() + 1
		next, ok := n.core.TryLeaseUDPPortRangeIntoLocked(&socket.portLease, n.nextPort, firstEphemeralUDPPort, attempts)
		if ok {
			n.nextPort = next
			local.Port = socket.portLease.UDPPort()
			socket.local = local
		}
	} else if !n.core.TryLeaseUDPPortIntoLocked(&socket.portLease, local.Port) {
		n.recycleSocketLocked(socket)
		return nil, 0, nscore.Fail(nscore.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}
	if socket.portLease.UDPPort() == 0 {
		n.recycleSocketLocked(socket)
		return nil, 0, nscore.Fail(nscore.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}
	// Port zero is only an allocation request. Check authority against the final
	// concrete port before publishing the socket so a deny rule for an ephemeral
	// port cannot be bypassed by binding the placeholder port zero.
	if requested.Port == 0 && !n.policy.CheckPortAllocation(policy.OperationUDPBind, requested.Address, local.Port) {
		socket.portLease.ReleaseLocked()
		n.recycleSocketLocked(socket)
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}

	retainedBytes := uint64(n.config.MaxPayloadBytes) * uint64(n.config.ReceiveDatagrams+n.config.TransmitDatagrams)
	if err := n.quotas.AcquireResourceAndQueuedBytes(&socket.retained, quota.ResourceUDP, 1, retainedBytes); err != nil {
		socket.portLease.ReleaseLocked()
		n.recycleSocketLocked(socket)
		return nil, 0, lnetocore.MapError(err)
	}
	n.byPort[local.Port] = socket
	n.sockets = append(n.sockets, socket)
	return socket, nscore.ProgressDone, nil
}

func (s *udpSocket) LocalEndpoint() nscore.Endpoint {
	if s == nil || s.owner == nil {
		return nscore.Endpoint{}
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	return s.local
}

func (s *udpSocket) Readiness() nscore.Readiness {
	if s == nil || s.owner == nil {
		return nscore.ReadyClosed
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	var ready nscore.Readiness
	if s.rx.count > 0 {
		ready |= nscore.ReadyReadable
	}
	if s.tx.count < len(s.tx.slots) {
		ready |= nscore.ReadyWritable
	}
	return ready
}

func (s *udpSocket) TryReceive(dst []byte) (udpns.DatagramResult, error) {
	if s == nil || s.owner == nil {
		return udpns.DatagramResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() {
		return udpns.DatagramResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	result, ok := s.rx.pop(dst)
	if !ok {
		return udpns.DatagramResult{}, nil
	}
	if !result.Valid(len(dst)) {
		return udpns.DatagramResult{}, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	return result, nil
}

func (s *udpSocket) TrySend(payload []byte, remote nscore.Endpoint) (nscore.Progress, error) {
	if s == nil || s.owner == nil {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !remote.Valid() || !remote.Address.Is4() || remote.Port == 0 {
		return 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if !s.owner.policy.CheckEndpoint(policy.OperationUDPSend, remote.Address, remote.Port) {
		return 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if len(payload) > s.owner.config.MaxPayloadBytes {
		return 0, nscore.Fail(nscore.FailureMessageTooLarge, lneto.ErrShortBuffer)
	}
	if !s.tx.push(payload, remote) {
		return nscore.ProgressWouldBlock, nil
	}
	return nscore.ProgressDone, nil
}

func (s *udpSocket) Close() error {
	if s == nil || s.owner == nil {
		return nil
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	return s.closeLocked()
}

func (s *udpSocket) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.owner != nil && s.owner.byPort != nil {
		delete(s.owner.byPort, s.local.Port)
		for i, socket := range s.owner.sockets {
			if socket != s {
				continue
			}
			copy(s.owner.sockets[i:], s.owner.sockets[i+1:])
			s.owner.sockets[len(s.owner.sockets)-1] = nil
			s.owner.sockets = s.owner.sockets[:len(s.owner.sockets)-1]
			if len(s.owner.sockets) == 0 {
				s.owner.cursor = 0
			} else if s.owner.cursor > i {
				s.owner.cursor--
			} else if s.owner.cursor >= len(s.owner.sockets) {
				s.owner.cursor = 0
			}
			break
		}
	}
	s.portLease.ReleaseLocked()
	s.retained.Release()
	s.retained.ResetReleased()
	if s.owner != nil {
		s.owner.recycleSocketLocked(s)
	}
	return nil
}

// CloseLocked releases every UDP socket and retained allocation. The caller
// must hold the shared core lock.
func (n *Adapter) CloseLocked() {
	if n == nil {
		return
	}
	for len(n.sockets) > 0 {
		_ = n.sockets[len(n.sockets)-1].closeLocked()
	}
	clear(n.byPort)
	n.byPort = nil
	clear(n.freeBackings)
	n.freeBackings = nil
	n.sockets = nil
	n.cursor = 0
}

func (n *Adapter) hasEgressLocked() bool {
	for _, socket := range n.sockets {
		if !socket.closed && socket.tx.count > 0 {
			return true
		}
	}
	return false
}

func (n *Adapter) egressLocked(dst []byte) (int, error) {
	if len(n.sockets) == 0 {
		return 0, nil
	}
	var selected *udpSocket
	selectedIndex := 0
	for offset := 0; offset < len(n.sockets); offset++ {
		index := n.cursor + offset
		if index >= len(n.sockets) {
			index -= len(n.sockets)
		}
		socket := n.sockets[index]
		if !socket.closed && socket.tx.count > 0 {
			selected = socket
			selectedIndex = index
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
	ipFrame.SetID(n.core.NextIPv4IDLocked())
	ipFrame.SetFlags(ipv4.FlagDontFragment)
	ipFrame.SetTTL(64)
	ipFrame.SetProtocol(lneto.IPProtoUDP)
	*ipFrame.SourceAddr() = n.core.IPv4AddressLocked().As4()
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
	n.cursor = selectedIndex + 1
	if n.cursor == len(n.sockets) {
		n.cursor = 0
	}
	return frameBytes, nil
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ethernet.BroadcastAddr() && mac[0]&1 == 0
}

func (n *Adapter) ingressLocked(frame []byte) (bool, error) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || ethernetFrame.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return false, err
	}
	if *ethernetFrame.DestinationHardwareAddr() != n.hardwareAddress {
		return false, nil
	}
	ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
	if err != nil {
		return false, err
	}
	version, headerWords := ipFrame.VersionAndIHL()
	if version != 4 || headerWords < 5 || ipFrame.Protocol() != lneto.IPProtoUDP || netip.AddrFrom4(*ipFrame.DestinationAddr()) != n.core.IPv4AddressLocked() {
		return false, nil
	}
	if !validUnicastMAC(*ethernetFrame.SourceHardwareAddr()) {
		return true, nil
	}
	var validator lneto.Validator
	ipFrame.ValidateExceptCRC(&validator)
	if err := validator.ErrPop(); err != nil {
		return true, nil
	}
	if ipFrame.CalculateHeaderCRC() != 0 || ipFrame.Flags().MoreFragments() || ipFrame.Flags().FragmentOffset() != 0 {
		return true, nil
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		return true, nil
	}
	udpFrame.ValidateSize(&validator)
	if err := validator.ErrPop(); err != nil {
		return true, nil
	}
	udpLength := udpFrame.Length()
	if udpFrame.CRC() != 0 {
		var checksum lneto.CRC791
		ipFrame.CRCWriteUDPPseudo(&checksum, udpLength)
		if checksum.PayloadSum16(udpFrame.RawData()[:udpLength]) != 0 {
			return true, nil
		}
	}
	selected := n.byPort[udpFrame.DestinationPort()]
	if selected == nil || selected.closed {
		return false, nil
	}
	sourceAddress := netip.AddrFrom4(*ipFrame.SourceAddr())
	if sourceAddress.IsUnspecified() || sourceAddress.IsMulticast() || sourceAddress == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true, nil
	}
	source := nscore.Endpoint{Address: sourceAddress, Port: udpFrame.SourcePort()}
	if !source.Valid() || source.Port == 0 {
		return true, nil
	}
	payload := udpFrame.RawData()[8:udpLength]
	_ = selected.rx.push(payload, source) // A full receive queue drops this datagram.
	return true, nil
}
