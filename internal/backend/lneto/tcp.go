package lnetobackend

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	lneto "github.com/soypat/lneto"
	lnetotcp "github.com/soypat/lneto/tcp"
	"github.com/wago-org/net/internal/namespace"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var (
	_ namespace.TCPListener = (*tcpListener)(nil)
	_ namespace.TCPStream   = (*tcpStream)(nil)
)

const firstEphemeralTCPPort uint16 = 49152

// TCPConfig fixes all lneto TCP storage and registration bounds. Each listener
// owns AcceptBacklog preconfigured receive/transmit buffer pairs. Outbound
// streams allocate one pair each. Zero listeners and outbound streams disable
// TCP truthfully.
type TCPConfig struct {
	MaxListeners       uint16
	MaxOutboundStreams uint16
	AcceptBacklog      uint16
	ReceiveBytes       int
	TransmitBytes      int
	TransmitPackets    int
}

type tcpListener struct {
	owner    *Namespace
	local    namespace.Endpoint
	listener lnetotcp.Listener
	pool     tcpPool

	resource *quota.Allocation
	queued   *quota.Allocation
	closed   bool
}

type tcpStream struct {
	owner  *Namespace
	conn   *lnetotcp.Conn
	local  namespace.Endpoint
	remote namespace.Endpoint
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
	owner   *Namespace
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

func newTCPPool(owner *Namespace, count uint16, config TCPConfig) (tcpPool, error) {
	pool := tcpPool{owner: owner, slots: make([]tcpPoolSlot, int(count)), nextISS: owner.nextTCPISS}
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
	if p == nil || p.owner == nil || p.owner.closed {
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
		p.owner.nextTCPISS = p.nextISS
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

func (n *Namespace) tryListenTCP(local namespace.Endpoint) (namespace.TCPListener, namespace.Progress, error) {
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
	if n.tcpConfig.MaxListeners == 0 {
		return nil, 0, namespace.Fail(namespace.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !local.Address.IsUnspecified() && local.Address != n.ipv4Address {
		return nil, 0, namespace.Fail(namespace.FailureAddressUnavailable, lneto.ErrInvalidAddr)
	}
	if !n.policy.CheckEndpoint(policy.OperationTCPListen, local.Address, local.Port) {
		return nil, 0, namespace.Fail(namespace.FailureAccessDenied, errPolicyDenied)
	}
	if len(n.tcpListeners) == int(n.tcpConfig.MaxListeners) {
		return nil, 0, namespace.Fail(namespace.FailureResourceLimit, lneto.ErrExhausted)
	}
	if _, exists := n.tcpPorts[local.Port]; exists {
		return nil, 0, namespace.Fail(namespace.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}

	resourceReservation, err := n.quotas.ReserveResource(quota.ResourceTCP, 1)
	if err != nil {
		return nil, 0, mapError(err)
	}
	retained := uint64(n.tcpConfig.AcceptBacklog) * uint64(n.tcpConfig.ReceiveBytes+n.tcpConfig.TransmitBytes)
	queuedReservation, err := n.quotas.ReserveQueuedBytes(retained)
	if err != nil {
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	pool, err := newTCPPool(n, n.tcpConfig.AcceptBacklog, n.tcpConfig)
	if err != nil {
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	listener := &tcpListener{owner: n, local: local, pool: pool}
	if err := listener.listener.Reset(local.Port, &listener.pool); err != nil {
		listener.pool.closeLocked()
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	if err := n.stack.RegisterListenerTCP(&listener.listener); err != nil {
		_ = listener.listener.Close()
		listener.pool.closeLocked()
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	resourceAllocation, ok := resourceReservation.Commit()
	if !ok {
		_ = listener.listener.Close()
		listener.pool.closeLocked()
		queuedReservation.Rollback()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	queuedAllocation, ok := queuedReservation.Commit()
	if !ok {
		_ = listener.listener.Close()
		listener.pool.closeLocked()
		resourceAllocation.Release()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	listener.resource = resourceAllocation
	listener.queued = queuedAllocation
	n.tcpPorts[local.Port] = struct{}{}
	n.tcpListeners = append(n.tcpListeners, listener)
	return listener, namespace.ProgressDone, nil
}

func (n *Namespace) tryConnectTCP(remote namespace.Endpoint) (namespace.TCPStream, namespace.Progress, error) {
	if n == nil {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.stack == nil {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if !remote.Valid() || !remote.Address.Is4() || remote.Address.IsUnspecified() || remote.Port == 0 {
		return nil, 0, namespace.Fail(namespace.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.tcpConfig.MaxOutboundStreams == 0 {
		return nil, 0, namespace.Fail(namespace.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !n.policy.CheckEndpoint(policy.OperationTCPConnect, remote.Address, remote.Port) {
		return nil, 0, namespace.Fail(namespace.FailureAccessDenied, errPolicyDenied)
	}
	if n.outboundTCPStreamsLocked() == int(n.tcpConfig.MaxOutboundStreams) {
		return nil, 0, namespace.Fail(namespace.FailureResourceLimit, lneto.ErrExhausted)
	}
	localPort, ok := n.allocateTCPPortLocked()
	if !ok {
		return nil, 0, namespace.Fail(namespace.FailureResourceLimit, lneto.ErrExhausted)
	}
	resourceReservation, err := n.quotas.ReserveResource(quota.ResourceTCP, 1)
	if err != nil {
		return nil, 0, mapError(err)
	}
	retained := uint64(n.tcpConfig.ReceiveBytes + n.tcpConfig.TransmitBytes)
	queuedReservation, err := n.quotas.ReserveQueuedBytes(retained)
	if err != nil {
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	conn := new(lnetotcp.Conn)
	storage := make([]byte, int(retained))
	if err := conn.Configure(lnetotcp.ConnConfig{
		RxBuf:             storage[:n.tcpConfig.ReceiveBytes],
		TxBuf:             storage[n.tcpConfig.ReceiveBytes:],
		TxPacketQueueSize: n.tcpConfig.TransmitPackets,
		RWBackoff:         immediateBackoff,
	}); err != nil {
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	if err := n.stack.DialTCP(conn, localPort, netip.AddrPortFrom(remote.Address, remote.Port)); err != nil {
		conn.Abort()
		queuedReservation.Rollback()
		resourceReservation.Rollback()
		return nil, 0, mapError(err)
	}
	resourceAllocation, ok := resourceReservation.Commit()
	if !ok {
		conn.Abort()
		queuedReservation.Rollback()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	queuedAllocation, ok := queuedReservation.Commit()
	if !ok {
		conn.Abort()
		resourceAllocation.Release()
		return nil, 0, namespace.Fail(namespace.FailureClosed, quota.ErrClosed)
	}
	stream := &tcpStream{
		owner: n, conn: conn,
		local:  namespace.Endpoint{Address: n.ipv4Address, Port: localPort},
		remote: remote, resource: resourceAllocation, queued: queuedAllocation,
		outbound: true,
	}
	n.tcpPorts[localPort] = struct{}{}
	n.tcpStreams = append(n.tcpStreams, stream)
	return stream, namespace.ProgressInProgress, nil
}

func (l *tcpListener) LocalEndpoint() namespace.Endpoint {
	if l == nil {
		return namespace.Endpoint{}
	}
	return l.local
}

func (l *tcpListener) Readiness() namespace.Readiness {
	if l == nil || l.owner == nil {
		return namespace.ReadyClosed
	}
	l.owner.mu.Lock()
	defer l.owner.mu.Unlock()
	if l.closed || l.owner.closed {
		return namespace.ReadyClosed
	}
	if l.listener.NumberOfReadyToAccept() > 0 {
		return namespace.ReadyAccept
	}
	return 0
}

func (l *tcpListener) TryAccept() (namespace.TCPStream, namespace.Progress, error) {
	if l == nil || l.owner == nil {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	l.owner.mu.Lock()
	defer l.owner.mu.Unlock()
	if l.closed || l.owner.closed {
		return nil, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	conn, userData, err := l.listener.TryAccept()
	if errors.Is(err, lneto.ErrExhausted) {
		return nil, namespace.ProgressWouldBlock, nil
	}
	if err != nil {
		return nil, 0, mapError(err)
	}
	slot, ok := userData.(*tcpPoolSlot)
	if !ok || slot == nil || conn == nil || slot.stream != nil || slot.resource == nil {
		if conn != nil {
			conn.Abort()
		}
		return nil, 0, namespace.Fail(namespace.FailureIO, lneto.ErrBadState)
	}
	remoteAddress := conn.RemoteAddr()
	if len(remoteAddress) != 4 || conn.RemotePort() == 0 {
		conn.Abort()
		return nil, 0, namespace.Fail(namespace.FailureIO, lneto.ErrInvalidAddr)
	}
	stream := &tcpStream{
		owner: l.owner, conn: conn, slot: slot,
		local:     l.local,
		remote:    namespace.Endpoint{Address: netip.AddrFrom4([4]byte(remoteAddress)), Port: conn.RemotePort()},
		resource:  slot.resource,
		connected: true,
	}
	slot.stream = stream
	l.owner.tcpStreams = append(l.owner.tcpStreams, stream)
	return stream, namespace.ProgressDone, nil
}

func (l *tcpListener) Close() error {
	if l == nil || l.owner == nil {
		return nil
	}
	l.owner.mu.Lock()
	defer l.owner.mu.Unlock()
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
		delete(l.owner.tcpPorts, l.local.Port)
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

func (s *tcpStream) LocalEndpoint() namespace.Endpoint {
	if s == nil {
		return namespace.Endpoint{}
	}
	return s.local
}

func (s *tcpStream) RemoteEndpoint() namespace.Endpoint {
	if s == nil {
		return namespace.Endpoint{}
	}
	return s.remote
}

func (s *tcpStream) Readiness() namespace.Readiness {
	if s == nil || s.owner == nil {
		return namespace.ReadyClosed
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed || s.terminal || s.conn == nil {
		return namespace.ReadyClosed
	}
	h := s.conn.InternalHandler()
	state := h.State()
	var ready namespace.Readiness
	if state == lnetotcp.StateEstablished || state == lnetotcp.StateCloseWait {
		s.connected = true
		ready |= namespace.ReadyConnected
	}
	if h.BufferedInput() > 0 {
		ready |= namespace.ReadyReadable
	} else if !state.RxDataOpen() {
		ready |= namespace.ReadyClosed
	}
	if !s.shutdown && state.TxDataOpen() && h.FreeOutput() > 0 {
		ready |= namespace.ReadyWritable
	}
	if state.IsClosed() && !s.connected {
		ready |= namespace.ReadyError | namespace.ReadyClosed
	}
	return ready
}

func (s *tcpStream) TryFinishConnect() (namespace.Progress, error) {
	if s == nil || s.owner == nil {
		return 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed {
		return 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if s.terminal || s.conn == nil {
		return 0, namespace.Fail(namespace.FailureConnectionRefused, net.ErrClosed)
	}
	state := s.conn.InternalHandler().State()
	if state == lnetotcp.StateEstablished || state == lnetotcp.StateCloseWait {
		s.connected = true
		return namespace.ProgressDone, nil
	}
	if state.IsClosed() && !s.conn.InternalHandler().AwaitingSynSend() {
		return 0, namespace.Fail(namespace.FailureConnectionRefused, net.ErrClosed)
	}
	if state.IsPreestablished() || s.conn.InternalHandler().AwaitingSynSend() {
		return namespace.ProgressInProgress, nil
	}
	return 0, namespace.Fail(namespace.FailureConnectionAborted, lneto.ErrBadState)
}

func (s *tcpStream) TryRead(dst []byte) (namespace.IOResult, error) {
	if s == nil || s.owner == nil {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if len(dst) == 0 {
		return namespace.IOResult{State: namespace.IOReady}, nil
	}
	if s.terminal || s.conn == nil {
		return namespace.IOResult{State: namespace.IOEOF}, nil
	}
	h := s.conn.InternalHandler()
	if h.BufferedInput() > 0 {
		n, err := h.Read(dst)
		if err != nil && !errors.Is(err, io.EOF) {
			return namespace.IOResult{}, mapError(err)
		}
		result := namespace.IOResult{Bytes: n, State: namespace.IOReady}
		if !result.Valid(len(dst)) {
			return namespace.IOResult{}, namespace.Fail(namespace.FailureIO, lneto.ErrBadState)
		}
		return result, nil
	}
	state := h.State()
	if !state.RxDataOpen() {
		return namespace.IOResult{State: namespace.IOEOF}, nil
	}
	return namespace.IOResult{State: namespace.IOWouldBlock}, nil
}

func (s *tcpStream) TryWrite(src []byte) (namespace.IOResult, error) {
	if s == nil || s.owner == nil {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if s.terminal || s.conn == nil {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureConnectionBroken, net.ErrClosed)
	}
	if s.shutdown {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureInvalidState, lneto.ErrBadState)
	}
	if len(src) == 0 {
		return namespace.IOResult{State: namespace.IOReady}, nil
	}
	h := s.conn.InternalHandler()
	if !h.State().TxDataOpen() {
		if h.State().IsPreestablished() || h.AwaitingSynSend() {
			return namespace.IOResult{State: namespace.IOWouldBlock}, nil
		}
		return namespace.IOResult{}, namespace.Fail(namespace.FailureConnectionBroken, net.ErrClosed)
	}
	count := min(len(src), h.FreeOutput())
	if count == 0 {
		return namespace.IOResult{State: namespace.IOWouldBlock}, nil
	}
	n, err := h.Write(src[:count])
	if err != nil {
		return namespace.IOResult{}, mapError(err)
	}
	result := namespace.IOResult{Bytes: n, State: namespace.IOReady}
	if !result.Valid(len(src)) {
		return namespace.IOResult{}, namespace.Fail(namespace.FailureIO, lneto.ErrBadState)
	}
	return result, nil
}

func (s *tcpStream) TryShutdownWrite() (namespace.Progress, error) {
	if s == nil || s.owner == nil {
		return 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	if s.closed || s.owner.closed {
		return 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if s.terminal || s.conn == nil {
		return 0, namespace.Fail(namespace.FailureConnectionBroken, net.ErrClosed)
	}
	if s.shutdown {
		return namespace.ProgressDone, nil
	}
	if err := s.conn.InternalHandler().Close(); err != nil {
		return 0, mapError(err)
	}
	s.shutdown = true
	return namespace.ProgressDone, nil
}

func (s *tcpStream) Close() error {
	if s == nil || s.owner == nil {
		return nil
	}
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
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
		delete(s.owner.tcpPorts, s.local.Port)
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

func (n *Namespace) allocateTCPPortLocked() (uint16, bool) {
	attempts := int(n.tcpConfig.MaxListeners) + int(n.tcpConfig.MaxOutboundStreams) + 1
	port := n.nextTCPPort
	if port < firstEphemeralTCPPort {
		port = firstEphemeralTCPPort
	}
	for range attempts {
		if _, exists := n.tcpPorts[port]; !exists {
			n.nextTCPPort = port + 1
			if n.nextTCPPort < firstEphemeralTCPPort {
				n.nextTCPPort = firstEphemeralTCPPort
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

func (n *Namespace) outboundTCPStreamsLocked() int {
	count := 0
	for _, stream := range n.tcpStreams {
		if stream != nil && stream.outbound && !stream.closed {
			count++
		}
	}
	return count
}

func removeTCPListener(owner *Namespace, target *tcpListener) {
	if owner == nil {
		return
	}
	for i, listener := range owner.tcpListeners {
		if listener != target {
			continue
		}
		copy(owner.tcpListeners[i:], owner.tcpListeners[i+1:])
		owner.tcpListeners[len(owner.tcpListeners)-1] = nil
		owner.tcpListeners = owner.tcpListeners[:len(owner.tcpListeners)-1]
		return
	}
}

func removeTCPStream(owner *Namespace, target *tcpStream) {
	if owner == nil {
		return
	}
	for i, stream := range owner.tcpStreams {
		if stream != target {
			continue
		}
		copy(owner.tcpStreams[i:], owner.tcpStreams[i+1:])
		owner.tcpStreams[len(owner.tcpStreams)-1] = nil
		owner.tcpStreams = owner.tcpStreams[:len(owner.tcpStreams)-1]
		return
	}
}
