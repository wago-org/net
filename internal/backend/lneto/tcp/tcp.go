package tcp

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	lneto "github.com/soypat/lneto"
	lnetotcp "github.com/soypat/lneto/tcp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

const (
	firstEphemeralTCPPort uint16 = 49152
	closeOrder                   = 20
)

var ErrPolicyDenied = errors.New("net: endpoint policy denied operation")

// Adapter owns only TCP listeners, streams, ports, and fixed buffers while the
// protocol-neutral core owns the shared lock, stack, link, identity, policy,
// quotas, service loop, and lifecycle.
type Adapter struct {
	core        *lnetocore.Namespace
	stack       interfaceStack
	ipv4Address netip.Addr
	policy      *policy.Policy
	quotas      *quota.Account
	config      Config
	listeners   []*tcpListener
	streams     []*tcpStream
	ports       map[uint16]struct{}
	nextPort    uint16
	nextISS     lnetotcp.Value
}

type interfaceStack interface {
	RegisterListenerTCP(*lnetotcp.Listener) error
	DialTCP(*lnetotcp.Conn, uint16, netip.AddrPort) error
}

// New attaches TCP-local state to one shared core without creating another
// stack, link, lifecycle lock, policy, or quota domain.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	if common.ClosedLocked() || !ValidConfig(config, common.PolicyLocked(), common.QuotasLocked(), true) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	n := &Adapter{
		core: common, stack: common.StackLocked(), ipv4Address: common.IPv4AddressLocked(),
		policy: common.PolicyLocked(), quotas: common.QuotasLocked(), config: config,
		listeners: make([]*tcpListener, 0, config.MaxListeners),
		streams:   make([]*tcpStream, 0, int(config.MaxOutboundStreams)+int(config.MaxListeners)*int(config.AcceptBacklog)),
		ports:     make(map[uint16]struct{}, int(config.MaxListeners)+int(config.MaxOutboundStreams)),
		nextPort:  firstEphemeralTCPPort,
		nextISS:   lnetotcp.Value(common.RandSeedLocked()),
	}
	common.Unlock()
	if err := common.Install(lnetocore.Participant{CloseOrder: closeOrder, Close: n.CloseLocked}); err != nil {
		return nil, err
	}
	return n, nil
}

// ValidConfig validates TCP-local storage and authority without allocation.
func ValidConfig(config Config, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxListeners == 0 && config.MaxOutboundStreams == 0 {
		return config == (Config{})
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	if uint32(config.MaxListeners)+uint32(config.MaxOutboundStreams) > uint32(^uint16(0)) ||
		config.ReceiveBytes < 256 || config.TransmitBytes < 256 || config.TransmitPackets <= 0 || config.TransmitPackets > config.TransmitBytes {
		return false
	}
	if config.MaxListeners > 0 && config.AcceptBacklog == 0 || config.MaxListeners == 0 && config.AcceptBacklog != 0 {
		return false
	}
	stride := uint64(config.ReceiveBytes) + uint64(config.TransmitBytes)
	return stride <= uint64(^uint(0)>>1) && uint64(config.AcceptBacklog) <= uint64(^uint(0)>>1)/stride
}

// TCPConfig fixes all lneto TCP storage and registration bounds. Each listener
// owns AcceptBacklog preconfigured receive/transmit buffer pairs. Outbound
// streams allocate one pair each. Zero listeners and outbound streams disable
// TCP truthfully.
type Config struct {
	MaxListeners       uint16
	MaxOutboundStreams uint16
	AcceptBacklog      uint16
	ReceiveBytes       int
	TransmitBytes      int
	TransmitPackets    int
}

type tcpListener struct {
	owner    *Adapter
	local    nscore.Endpoint
	listener lnetotcp.Listener
	pool     tcpPool

	resource *quota.Allocation
	queued   *quota.Allocation
	closed   bool
}

type tcpStream struct {
	owner  *Adapter
	conn   *lnetotcp.Conn
	local  nscore.Endpoint
	remote nscore.Endpoint
	slot   *tcpPoolSlot

	resource  *quota.Allocation
	queued    *quota.Allocation
	connected bool
	shutdown  bool
	terminal  bool
	closed    bool
	outbound  bool
}

type tcpPool struct {
	owner   *Adapter
	slots   []tcpPoolSlot
	nextISS lnetotcp.Value
}

type tcpPoolSlot struct {
	conn     lnetotcp.Conn
	resource *quota.Allocation
	stream   *tcpStream
	inUse    bool
}

func immediateBackoff(uint) time.Duration { return 0 }

func newTCPPool(owner *Adapter, count uint16, config Config) (tcpPool, error) {
	pool := tcpPool{owner: owner, slots: make([]tcpPoolSlot, int(count)), nextISS: owner.nextISS}
	if count == 0 {
		return pool, nil
	}
	storage := make([]byte, int(count)*(config.ReceiveBytes+config.TransmitBytes))
	stride := config.ReceiveBytes + config.TransmitBytes
	for i := range pool.slots {
		start := i * stride
		rxEnd := start + config.ReceiveBytes
		if err := pool.slots[i].conn.Configure(lnetotcp.ConnConfig{
			RxBuf:             storage[start:rxEnd],
			TxBuf:             storage[rxEnd : start+stride],
			TxPacketQueueSize: config.TransmitPackets,
			RWBackoff:         immediateBackoff,
		}); err != nil {
			pool.closeLocked()
			return tcpPool{}, err
		}
	}
	return pool, nil
}

// GetTCP and PutTCP implement lneto's structural listener-pool contract. They
// run only while the namespace service lock is held. A slot reserves its TCP
// resource quota before lneto may retain it for an incoming handshake.
func (p *tcpPool) GetTCP() (*lnetotcp.Conn, any, lnetotcp.Value) {
	if p == nil || p.owner == nil || p.owner.core.ClosedLocked() {
		return nil, nil, 0
	}
	for i := range p.slots {
		slot := &p.slots[i]
		if slot.inUse {
			continue
		}
		reservation, err := p.owner.quotas.ReserveResource(quota.ResourceTCP, 1)
		if err != nil {
			return nil, nil, 0
		}
		allocation, ok := reservation.Commit()
		if !ok {
			return nil, nil, 0
		}
		slot.inUse = true
		slot.resource = allocation
		p.nextISS += 4099
		p.owner.nextISS = p.nextISS
		return &slot.conn, slot, p.nextISS
	}
	return nil, nil, 0
}

func (p *tcpPool) PutTCP(conn *lnetotcp.Conn) {
	if p == nil || conn == nil {
		return
	}
	for i := range p.slots {
		slot := &p.slots[i]
		if &slot.conn != conn {
			continue
		}
		conn.Abort()
		if slot.stream != nil {
			slot.stream.detachFromPoolLocked()
		}
		if slot.resource != nil {
			slot.resource.Release()
			slot.resource = nil
		}
		slot.stream = nil
		slot.inUse = false
		if p.owner != nil {
			p.owner.core.MarkMaintenanceLocked()
		}
		return
	}
	panic("lneto TCP listener returned a foreign connection")
}

func (p *tcpPool) closeLocked() {
	if p == nil {
		return
	}
	for i := range p.slots {
		slot := &p.slots[i]
		if slot.inUse {
			slot.conn.Abort()
		}
		if slot.stream != nil {
			slot.stream.detachFromPoolLocked()
		}
		if slot.resource != nil {
			slot.resource.Release()
		}
		*slot = tcpPoolSlot{}
	}
	p.slots = nil
	p.owner = nil
}

// TryListenTCP implements the narrow TCP namespace facet.
func (n *Adapter) TryListenTCP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.TryListen(local)
}

func (n *Adapter) TryListen(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	if n == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.core.Lock()
	defer n.core.Unlock()
	if n.core.ClosedLocked() || n.stack == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !local.Valid() || !local.Address.Is4() || local.Port == 0 {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.config.MaxListeners == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !local.Address.IsUnspecified() && local.Address != n.ipv4Address {
		return nil, 0, nscore.Fail(nscore.FailureAddressUnavailable, lneto.ErrInvalidAddr)
	}
	if !n.policy.CheckEndpoint(policy.OperationTCPListen, local.Address, local.Port) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, ErrPolicyDenied)
	}
	if len(n.listeners) == int(n.config.MaxListeners) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	if _, exists := n.ports[local.Port]; exists {
		return nil, 0, nscore.Fail(nscore.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}

	resourceReservation, err := n.quotas.ReserveResource(quota.ResourceTCP, 1)
	if err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	retained := uint64(n.config.AcceptBacklog) * uint64(n.config.ReceiveBytes+n.config.TransmitBytes)
	queuedReservation, err := n.quotas.ReserveQueuedBytes(retained)
	if err != nil {
		resourceReservation.Rollback()
		return nil, 0, lnetocore.MapError(err)
	}
	pool, err := newTCPPool(n, n.config.AcceptBacklog, n.config)
	if err != nil {
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, lnetocore.MapError(err)
	}
	listener := &tcpListener{owner: n, local: local, pool: pool}
	if err := listener.listener.Reset(local.Port, &listener.pool); err != nil {
		listener.pool.closeLocked()
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, lnetocore.MapError(err)
	}
	if err := n.stack.RegisterListenerTCP(&listener.listener); err != nil {
		_ = listener.listener.Close()
		listener.pool.closeLocked()
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, lnetocore.MapError(err)
	}
	resourceAllocation, ok := resourceReservation.Commit()
	if !ok {
		_ = listener.listener.Close()
		listener.pool.closeLocked()
		queuedReservation.Rollback()
		return nil, 0, nscore.Fail(nscore.FailureClosed, quota.ErrClosed)
	}
	queuedAllocation, ok := queuedReservation.Commit()
	if !ok {
		_ = listener.listener.Close()
		listener.pool.closeLocked()
		resourceAllocation.Release()
		return nil, 0, nscore.Fail(nscore.FailureClosed, quota.ErrClosed)
	}
	listener.resource = resourceAllocation
	listener.queued = queuedAllocation
	n.ports[local.Port] = struct{}{}
	n.listeners = append(n.listeners, listener)
	return listener, nscore.ProgressDone, nil
}

// TryConnectTCP implements the narrow TCP namespace facet.
func (n *Adapter) TryConnectTCP(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.TryConnect(remote)
}

func (n *Adapter) TryConnect(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	if n == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.core.Lock()
	defer n.core.Unlock()
	if n.core.ClosedLocked() || n.stack == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !remote.Valid() || !remote.Address.Is4() || remote.Address.IsUnspecified() || remote.Port == 0 {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.config.MaxOutboundStreams == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !n.policy.CheckEndpoint(policy.OperationTCPConnect, remote.Address, remote.Port) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, ErrPolicyDenied)
	}
	if n.outboundTCPStreamsLocked() == int(n.config.MaxOutboundStreams) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	localPort, ok := n.allocateTCPPortLocked()
	if !ok {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	resourceReservation, err := n.quotas.ReserveResource(quota.ResourceTCP, 1)
	if err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	retained := uint64(n.config.ReceiveBytes + n.config.TransmitBytes)
	queuedReservation, err := n.quotas.ReserveQueuedBytes(retained)
	if err != nil {
		resourceReservation.Rollback()
		return nil, 0, lnetocore.MapError(err)
	}
	conn := new(lnetotcp.Conn)
	storage := make([]byte, int(retained))
	if err := conn.Configure(lnetotcp.ConnConfig{
		RxBuf:             storage[:n.config.ReceiveBytes],
		TxBuf:             storage[n.config.ReceiveBytes:],
		TxPacketQueueSize: n.config.TransmitPackets,
		RWBackoff:         immediateBackoff,
	}); err != nil {
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, lnetocore.MapError(err)
	}
	if err := n.stack.DialTCP(conn, localPort, netip.AddrPortFrom(remote.Address, remote.Port)); err != nil {
		conn.Abort()
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, lnetocore.MapError(err)
	}
	resourceAllocation, ok := resourceReservation.Commit()
	if !ok {
		conn.Abort()
		queuedReservation.Rollback()
		return nil, 0, nscore.Fail(nscore.FailureClosed, quota.ErrClosed)
	}
	queuedAllocation, ok := queuedReservation.Commit()
	if !ok {
		conn.Abort()
		resourceAllocation.Release()
		return nil, 0, nscore.Fail(nscore.FailureClosed, quota.ErrClosed)
	}
	stream := &tcpStream{
		owner: n, conn: conn,
		local:  nscore.Endpoint{Address: n.ipv4Address, Port: localPort},
		remote: remote, resource: resourceAllocation, queued: queuedAllocation,
		outbound: true,
	}
	n.ports[localPort] = struct{}{}
	n.streams = append(n.streams, stream)
	return stream, nscore.ProgressInProgress, nil
}

func (l *tcpListener) LocalEndpoint() nscore.Endpoint {
	if l == nil {
		return nscore.Endpoint{}
	}
	return l.local
}

func (l *tcpListener) Readiness() nscore.Readiness {
	if l == nil || l.owner == nil {
		return nscore.ReadyClosed
	}
	l.owner.core.Lock()
	defer l.owner.core.Unlock()
	if l.closed || l.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if l.listener.NumberOfReadyToAccept() > 0 {
		return nscore.ReadyAccept
	}
	return 0
}

func (l *tcpListener) TryAccept() (nscore.Resource, nscore.Progress, error) {
	if l == nil || l.owner == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	l.owner.core.Lock()
	defer l.owner.core.Unlock()
	if l.closed || l.owner.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	conn, userData, err := l.listener.TryAccept()
	if errors.Is(err, lneto.ErrExhausted) {
		return nil, nscore.ProgressWouldBlock, nil
	}
	if err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	slot, ok := userData.(*tcpPoolSlot)
	if !ok || slot == nil || conn == nil || slot.stream != nil || slot.resource == nil {
		if conn != nil {
			conn.Abort()
		}
		return nil, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	remoteAddress := conn.RemoteAddr()
	if len(remoteAddress) != 4 || conn.RemotePort() == 0 {
		conn.Abort()
		return nil, 0, nscore.Fail(nscore.FailureIO, lneto.ErrInvalidAddr)
	}
	stream := &tcpStream{
		owner: l.owner, conn: conn, slot: slot,
		local:     l.local,
		remote:    nscore.Endpoint{Address: netip.AddrFrom4([4]byte(remoteAddress)), Port: conn.RemotePort()},
		resource:  slot.resource,
		connected: true,
	}
	slot.stream = stream
	l.owner.streams = append(l.owner.streams, stream)
	return stream, nscore.ProgressDone, nil
}

func (l *tcpListener) Close() error {
	if l == nil || l.owner == nil {
		return nil
	}
	l.owner.core.Lock()
	defer l.owner.core.Unlock()
	return l.closeLocked()
}

func (l *tcpListener) closeLocked() error {
	if l.closed {
		return nil
	}
	l.closed = true
	_ = l.listener.Close()
	l.pool.closeLocked()
	if l.owner != nil {
		delete(l.owner.ports, l.local.Port)
		removeTCPListener(l.owner, l)
	}
	if l.queued != nil {
		l.queued.Release()
		l.queued = nil
	}
	if l.resource != nil {
		l.resource.Release()
		l.resource = nil
	}
	return nil
}

func (s *tcpStream) LocalEndpoint() nscore.Endpoint {
	if s == nil {
		return nscore.Endpoint{}
	}
	return s.local
}

func (s *tcpStream) RemoteEndpoint() nscore.Endpoint {
	if s == nil {
		return nscore.Endpoint{}
	}
	return s.remote
}

func (s *tcpStream) Readiness() nscore.Readiness {
	if s == nil || s.owner == nil {
		return nscore.ReadyClosed
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() || s.terminal || s.conn == nil {
		return nscore.ReadyClosed
	}
	h := s.conn.InternalHandler()
	state := h.State()
	var ready nscore.Readiness
	if state == lnetotcp.StateEstablished || state == lnetotcp.StateCloseWait {
		s.connected = true
		ready |= nscore.ReadyConnected
	}
	if h.BufferedInput() > 0 {
		ready |= nscore.ReadyReadable
	} else if !state.RxDataOpen() {
		ready |= nscore.ReadyClosed
	}
	if !s.shutdown && state.TxDataOpen() && h.FreeOutput() > 0 {
		ready |= nscore.ReadyWritable
	}
	if state.IsClosed() && !s.connected {
		ready |= nscore.ReadyError | nscore.ReadyClosed
	}
	return ready
}

func (s *tcpStream) TryFinishConnect() (nscore.Progress, error) {
	if s == nil || s.owner == nil {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if s.terminal || s.conn == nil {
		return 0, nscore.Fail(nscore.FailureConnectionRefused, net.ErrClosed)
	}
	state := s.conn.InternalHandler().State()
	if state == lnetotcp.StateEstablished || state == lnetotcp.StateCloseWait {
		s.connected = true
		return nscore.ProgressDone, nil
	}
	if state.IsClosed() && !s.conn.InternalHandler().AwaitingSynSend() {
		return 0, nscore.Fail(nscore.FailureConnectionRefused, net.ErrClosed)
	}
	if state.IsPreestablished() || s.conn.InternalHandler().AwaitingSynSend() {
		return nscore.ProgressInProgress, nil
	}
	return 0, nscore.Fail(nscore.FailureConnectionAborted, lneto.ErrBadState)
}

func (s *tcpStream) TryRead(dst []byte) (nscore.IOResult, error) {
	if s == nil || s.owner == nil {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if len(dst) == 0 {
		return nscore.IOResult{State: nscore.IOReady}, nil
	}
	if s.terminal || s.conn == nil {
		return nscore.IOResult{State: nscore.IOEOF}, nil
	}
	h := s.conn.InternalHandler()
	if h.BufferedInput() > 0 {
		n, err := h.Read(dst)
		if err != nil && !errors.Is(err, io.EOF) {
			return nscore.IOResult{}, lnetocore.MapError(err)
		}
		result := nscore.IOResult{Bytes: n, State: nscore.IOReady}
		if !result.Valid(len(dst)) {
			return nscore.IOResult{}, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
		}
		return result, nil
	}
	state := h.State()
	if !state.RxDataOpen() {
		return nscore.IOResult{State: nscore.IOEOF}, nil
	}
	return nscore.IOResult{State: nscore.IOWouldBlock}, nil
}

func (s *tcpStream) TryWrite(src []byte) (nscore.IOResult, error) {
	if s == nil || s.owner == nil {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if s.terminal || s.conn == nil {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureConnectionBroken, net.ErrClosed)
	}
	if s.shutdown {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	if len(src) == 0 {
		return nscore.IOResult{State: nscore.IOReady}, nil
	}
	h := s.conn.InternalHandler()
	if !h.State().TxDataOpen() {
		if h.State().IsPreestablished() || h.AwaitingSynSend() {
			return nscore.IOResult{State: nscore.IOWouldBlock}, nil
		}
		return nscore.IOResult{}, nscore.Fail(nscore.FailureConnectionBroken, net.ErrClosed)
	}
	count := min(len(src), h.FreeOutput())
	if count == 0 {
		return nscore.IOResult{State: nscore.IOWouldBlock}, nil
	}
	n, err := h.Write(src[:count])
	if err != nil {
		return nscore.IOResult{}, lnetocore.MapError(err)
	}
	result := nscore.IOResult{Bytes: n, State: nscore.IOReady}
	if !result.Valid(len(src)) {
		return nscore.IOResult{}, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	return result, nil
}

func (s *tcpStream) TryShutdownWrite() (nscore.Progress, error) {
	if s == nil || s.owner == nil {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	if s.closed || s.owner.core.ClosedLocked() {
		return 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if s.terminal || s.conn == nil {
		return 0, nscore.Fail(nscore.FailureConnectionBroken, net.ErrClosed)
	}
	if s.shutdown {
		return nscore.ProgressDone, nil
	}
	if err := s.conn.InternalHandler().Close(); err != nil {
		return 0, lnetocore.MapError(err)
	}
	s.shutdown = true
	return nscore.ProgressDone, nil
}

func (s *tcpStream) Close() error {
	if s == nil || s.owner == nil {
		return nil
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	return s.closeLocked()
}

func (s *tcpStream) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn != nil {
		s.conn.Abort()
	}
	if s.outbound && s.owner != nil {
		delete(s.owner.ports, s.local.Port)
	}
	if s.resource != nil {
		s.resource.Release()
		s.resource = nil
	}
	if s.queued != nil {
		s.queued.Release()
		s.queued = nil
	}
	if s.slot != nil {
		s.slot.resource = nil
	}
	if s.owner != nil {
		removeTCPStream(s.owner, s)
	}
	return nil
}

func (s *tcpStream) detachFromPoolLocked() {
	if s == nil {
		return
	}
	s.terminal = true
	s.conn = nil
	s.slot = nil
	if s.resource != nil {
		s.resource.Release()
		s.resource = nil
	}
	if s.owner != nil {
		removeTCPStream(s.owner, s)
	}
}

func (n *Adapter) allocateTCPPortLocked() (uint16, bool) {
	attempts := int(n.config.MaxListeners) + int(n.config.MaxOutboundStreams) + 1
	port := n.nextPort
	if port < firstEphemeralTCPPort {
		port = firstEphemeralTCPPort
	}
	for range attempts {
		if _, exists := n.ports[port]; !exists {
			n.nextPort = port + 1
			if n.nextPort < firstEphemeralTCPPort {
				n.nextPort = firstEphemeralTCPPort
			}
			return port, true
		}
		port++
		if port < firstEphemeralTCPPort {
			port = firstEphemeralTCPPort
		}
	}
	return 0, false
}

func (n *Adapter) outboundTCPStreamsLocked() int {
	count := 0
	for _, stream := range n.streams {
		if stream != nil && stream.outbound && !stream.closed {
			count++
		}
	}
	return count
}

// CloseLocked releases every TCP resource. The caller must hold the shared
// core lock; core lifecycle composition invokes this exactly once.
func (n *Adapter) CloseLocked() {
	if n == nil {
		return
	}
	for len(n.listeners) > 0 {
		n.listeners[len(n.listeners)-1].closeLocked()
	}
	for len(n.streams) > 0 {
		n.streams[len(n.streams)-1].closeLocked()
	}
	clear(n.ports)
	n.ports = nil
	n.listeners = nil
	n.streams = nil
	n.stack = nil
}

func removeTCPListener(owner *Adapter, target *tcpListener) {
	if owner == nil {
		return
	}
	for i, listener := range owner.listeners {
		if listener != target {
			continue
		}
		copy(owner.listeners[i:], owner.listeners[i+1:])
		owner.listeners[len(owner.listeners)-1] = nil
		owner.listeners = owner.listeners[:len(owner.listeners)-1]
		return
	}
}

func removeTCPStream(owner *Adapter, target *tcpStream) {
	if owner == nil {
		return
	}
	for i, stream := range owner.streams {
		if stream != target {
			continue
		}
		copy(owner.streams[i:], owner.streams[i+1:])
		owner.streams[len(owner.streams)-1] = nil
		owner.streams = owner.streams[:len(owner.streams)-1]
		return
	}
}
