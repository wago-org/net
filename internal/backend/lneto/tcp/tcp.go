package tcp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetotcp "github.com/soypat/lneto/tcp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	"github.com/wago-org/net/internal/checked"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

const (
	ingressOrder                    = 15
	closeOrder                      = 20
	maxEagerTCPListenerStorageBytes = 256 << 20
	maxTCPStreamCapacityHint        = 16
)

var (
	ErrPolicyDenied         = errors.New("net: endpoint policy denied operation")
	limitedBroadcastAddress = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// Adapter owns only TCP listeners, streams, ports, and fixed buffers while the
// protocol-neutral core owns the shared lock, stack, link, identity, policy,
// quotas, service loop, and lifecycle.
type Adapter struct {
	core                *lnetocore.Namespace
	stack               interfaceStack
	policy              *policy.Policy
	quotas              *quota.Account
	config              Config
	listeners           []*tcpListener
	freeListenerPools   []tcpPool
	streams             []*tcpStream
	outboundStreams     int
	freeOutboundStorage [][]byte
	portOwner           *lnetocore.TCPPortOwner
	nextISS             lnetotcp.Value
}

type interfaceStack interface {
	RegisterListenerTCP(*lnetotcp.Listener) error
	RegisterListenerTCP6(*lnetotcp.Listener) error
	DialTCP(*lnetotcp.Conn, uint16, netip.AddrPort) error
}

func (n *Adapter) ipv6ScopeMatchesLocked(endpoint nscore.Endpoint) bool {
	if n == nil || !endpoint.Address.Is6() || !n.core.IPv6EnabledLocked() {
		return false
	}
	if endpoint.Address.IsLinkLocalUnicast() {
		return endpoint.ScopeID == n.core.IPv6ScopeIDLocked()
	}
	return endpoint.ScopeID == 0
}

// New attaches TCP-local state to one shared core without creating another
// stack, link, lifecycle lock, policy, or quota domain.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	enabled := config.MaxListeners != 0 || config.MaxOutboundStreams != 0
	if common.ClosedLocked() || !ValidConfig(config, common.PolicyLocked(), common.QuotasLocked(), true) ||
		(enabled && !common.GatewayHardwareAddressUsableLocked()) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	n := &Adapter{
		core: common, stack: common.StackLocked(),
		policy: common.PolicyLocked(), quotas: common.QuotasLocked(), config: config,
		nextISS: lnetotcp.Value(common.RandSeedLocked()),
	}
	if enabled {
		n.portOwner = common.NewTCPPortOwnerLocked()
		if n.portOwner == nil {
			common.Unlock()
			return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
		}
	}
	if config.MaxListeners == 0 && config.MaxOutboundStreams == 0 {
		common.Unlock()
		return n, nil
	}
	n.listeners = make([]*tcpListener, 0, config.MaxListeners)
	n.streams = make([]*tcpStream, 0, streamCapacityHint(config))
	n.prepareReusePools()
	common.Unlock()
	if err := common.Install(lnetocore.Participant{IngressOrder: ingressOrder, Ingress: n.ingressLocked, CloseOrder: closeOrder, Close: n.CloseLocked}); err != nil {
		return nil, err
	}
	return n, nil
}

// ValidConfig validates TCP-local storage and authority without allocation.
func ValidConfig(config Config, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	return validateConfig(config, compiled, account, requireAuthority, checked.MaxInt()) == nil
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

func validateConfig(config Config, compiled *policy.Policy, account *quota.Account, requireAuthority bool, maxIntValue uint64) error {
	if config.MaxListeners == 0 && config.MaxOutboundStreams == 0 {
		if config != (Config{}) {
			return lneto.ErrInvalidConfig
		}
		return nil
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return lneto.ErrInvalidConfig
	}
	if config.ReceiveBytes < 256 || config.TransmitBytes < 256 || config.TransmitPackets <= 0 || config.TransmitPackets > config.TransmitBytes {
		return lneto.ErrInvalidConfig
	}
	if (config.MaxListeners > 0 && config.AcceptBacklog == 0) || (config.MaxListeners == 0 && config.AcceptBacklog != 0) {
		return lneto.ErrInvalidConfig
	}
	portCount := uint64(config.MaxListeners) + uint64(config.MaxOutboundStreams)
	if portCount > uint64(^uint16(0)) {
		return lneto.ErrInvalidConfig
	}
	if _, ok := checked.Uint64ToInt(portCount, maxIntValue); !ok {
		return lneto.ErrInvalidConfig
	}
	stride, ok := tcpStreamStorageBytes(config)
	if !ok {
		return lneto.ErrInvalidConfig
	}
	if _, ok := checked.Uint64ToInt(stride, maxIntValue); !ok {
		return lneto.ErrInvalidConfig
	}
	listenerBytes, ok := checked.MultiplyUint64(uint64(config.AcceptBacklog), stride)
	if !ok || listenerBytes > maxIntValue || listenerBytes > maxEagerTCPListenerStorageBytes {
		return lneto.ErrInvalidConfig
	}
	return nil
}

func tcpStreamStorageBytes(config Config) (uint64, bool) {
	if config.ReceiveBytes < 0 || config.TransmitBytes < 0 {
		return 0, false
	}
	return checked.AddUint64(uint64(config.ReceiveBytes), uint64(config.TransmitBytes))
}

func streamCapacityHint(config Config) int {
	hint := uint64(config.MaxListeners) + uint64(config.MaxOutboundStreams)
	if hint > maxTCPStreamCapacityHint {
		hint = maxTCPStreamCapacityHint
	}
	return int(hint)
}

func (n *Adapter) prepareReusePools() {
	if n == nil {
		return
	}
	if n.config.MaxListeners > 0 {
		n.freeListenerPools = make([]tcpPool, 0, n.config.MaxListeners)
	}
	if n.config.MaxOutboundStreams > 0 {
		n.freeOutboundStorage = make([][]byte, 0, n.config.MaxOutboundStreams)
	}
}

func (n *Adapter) acquireListenerLocked(local nscore.Endpoint) (*tcpListener, error) {
	if n == nil {
		return nil, lneto.ErrInvalidConfig
	}
	var pool tcpPool
	if len(n.freeListenerPools) == 0 {
		created, err := newTCPPool(n, n.config.AcceptBacklog, n.config)
		if err != nil {
			return nil, err
		}
		pool = created
	} else {
		pool = n.freeListenerPools[len(n.freeListenerPools)-1]
		n.freeListenerPools = n.freeListenerPools[:len(n.freeListenerPools)-1]
		pool.resetLocked(n)
	}
	return &tcpListener{owner: n, local: local, pool: pool}, nil
}

func (n *Adapter) recycleListenerLocked(listener *tcpListener) {
	if n == nil || listener == nil {
		return
	}
	listener.pool.releaseLocked()
	n.freeListenerPools = append(n.freeListenerPools, listener.pool)
	listener.pool = tcpPool{}
	listener.listener = lnetotcp.Listener{}
	listener.local = nscore.Endpoint{}
	listener.retained = quota.Charge{}
	listener.portLease = lnetocore.TCPPortLease{}
	listener.closed = true
}

func (n *Adapter) prepareOutboundStreamLocked(stream *tcpStream, retained uint64) error {
	if n == nil || stream == nil || stream.owner != n || stream.portLease.TCPPort() == 0 {
		return lneto.ErrInvalidConfig
	}
	if err := n.quotas.AcquireResourceAndQueuedBytes(&stream.retained, quota.ResourceTCP, 1, retained); err != nil {
		return err
	}
	stream.allocation = &stream.retained
	if len(n.freeOutboundStorage) == 0 {
		stream.storage = make([]byte, int(retained))
	} else {
		stream.storage = n.freeOutboundStorage[len(n.freeOutboundStorage)-1]
		n.freeOutboundStorage = n.freeOutboundStorage[:len(n.freeOutboundStorage)-1]
	}
	return nil
}

func (n *Adapter) recycleOutboundStreamLocked(stream *tcpStream) {
	if n == nil || stream == nil {
		return
	}
	clear(stream.storage)
	n.freeOutboundStorage = append(n.freeOutboundStorage, stream.storage)
	stream.conn = nil
	stream.connValue = lnetotcp.Conn{}
	stream.storage = nil
	stream.local = nscore.Endpoint{}
	stream.remote = nscore.Endpoint{}
	stream.portLease = lnetocore.TCPPortLease{}
	stream.slot = nil
	stream.allocation = nil
	stream.retained = quota.Charge{}
	stream.connected = false
	stream.shutdown = false
	stream.terminal = false
	stream.closed = true
	stream.outbound = true
}

type tcpListener struct {
	owner    *Adapter
	local    nscore.Endpoint
	listener lnetotcp.Listener
	pool     tcpPool

	retained  quota.Charge
	portLease lnetocore.TCPPortLease
	closed    bool
}

type tcpStream struct {
	owner     *Adapter
	conn      *lnetotcp.Conn
	connValue lnetotcp.Conn
	storage   []byte
	local     nscore.Endpoint
	remote    nscore.Endpoint
	slot      *tcpPoolSlot

	allocation *quota.Charge
	retained   quota.Charge
	portLease  lnetocore.TCPPortLease
	connected  bool
	shutdown   bool
	terminal   bool
	closed     bool
	outbound   bool
}

type tcpPool struct {
	owner   *Adapter
	slots   []tcpPoolSlot
	nextISS lnetotcp.Value
}

type tcpPoolSlot struct {
	conn       lnetotcp.Conn
	resource   quota.Charge
	stream     *tcpStream
	inUse      bool
	quotaOwned bool
}

func immediateBackoff(uint) time.Duration { return 0 }

func newTCPPool(owner *Adapter, count uint16, config Config) (tcpPool, error) {
	pool := tcpPool{owner: owner, slots: make([]tcpPoolSlot, int(count)), nextISS: owner.nextISS}
	if count == 0 {
		return pool, nil
	}
	stride, _ := tcpStreamStorageBytes(config)
	storage := make([]byte, int(uint64(count)*stride))
	strideBytes := int(stride)
	for i := range pool.slots {
		start := i * strideBytes
		rxEnd := start + config.ReceiveBytes
		if err := pool.slots[i].conn.Configure(lnetotcp.ConnConfig{
			RxBuf:             storage[start:rxEnd],
			TxBuf:             storage[rxEnd : start+strideBytes],
			TxPacketQueueSize: config.TransmitPackets,
			RWBackoff:         immediateBackoff,
		}); err != nil {
			pool.destroyLocked()
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
		if err := p.owner.quotas.AcquireResource(&slot.resource, quota.ResourceTCP, 1); err != nil {
			return nil, nil, 0
		}
		slot.inUse = true
		slot.quotaOwned = true
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
		if slot.quotaOwned {
			slot.resource.Release()
			slot.resource.ResetReleased()
			slot.quotaOwned = false
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

func (p *tcpPool) resetLocked(owner *Adapter) {
	if p == nil {
		return
	}
	p.owner = owner
	if owner != nil {
		p.nextISS = owner.nextISS
	}
}

func (p *tcpPool) releaseLocked() {
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
		if slot.quotaOwned {
			slot.resource.Release()
			slot.resource.ResetReleased()
		}
		slot.resource = quota.Charge{}
		slot.stream = nil
		slot.inUse = false
		slot.quotaOwned = false
	}
}

func (p *tcpPool) destroyLocked() {
	if p == nil {
		return
	}
	p.releaseLocked()
	p.slots = nil
	p.owner = nil
}

func (n *Adapter) ingressLocked(frame []byte) (bool, error) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || *ethernetFrame.DestinationHardwareAddr() != n.core.HardwareAddressLocked() {
		return false, nil
	}
	sourceHardwareAddress := *ethernetFrame.SourceHardwareAddr()
	switch ethernetFrame.EtherTypeOrSize() {
	case ethernet.TypeIPv4:
		return n.ingressIPv4Locked(ethernetFrame.Payload(), sourceHardwareAddress)
	case ethernet.TypeIPv6:
		return n.ingressIPv6Locked(ethernetFrame.Payload(), sourceHardwareAddress)
	default:
		return false, nil
	}
}

func (n *Adapter) ingressIPv4Locked(packet []byte, sourceHardwareAddress [6]byte) (bool, error) {
	ipFrame, err := ipv4.NewFrame(packet)
	if err != nil {
		return false, nil
	}
	version, ihl := ipFrame.VersionAndIHL()
	totalLength := int(ipFrame.TotalLength())
	headerLength := int(ihl) * 4
	if version != 4 || ihl < 5 || totalLength < 20 || headerLength > totalLength || totalLength > len(ipFrame.RawData()) || ipFrame.CalculateHeaderCRC() != 0 || ipFrame.Protocol() != lneto.IPProtoTCP {
		return false, nil
	}
	local := n.core.IPv4AddressLocked()
	if !local.IsUnspecified() && netip.AddrFrom4(*ipFrame.DestinationAddr()) != local {
		return false, nil
	}
	flags := ipFrame.Flags()
	if flags.MoreFragments() || flags.FragmentOffset() != 0 {
		return true, nil
	}
	payload := ipFrame.RawData()[headerLength:totalLength]
	var checksum lneto.CRC791
	ipFrame.CRCWriteTCPPseudo(&checksum)
	return n.ingressTCPPayloadLocked(payload, &checksum, sourceHardwareAddress, netip.AddrFrom4(*ipFrame.SourceAddr()))
}

func (n *Adapter) ingressIPv6Locked(packet []byte, sourceHardwareAddress [6]byte) (bool, error) {
	ipFrame, err := lnetoipv6.NewFrame(packet)
	if err != nil {
		return false, nil
	}
	version, _, _ := ipFrame.VersionTrafficAndFlow()
	payloadLength := int(ipFrame.PayloadLength())
	if version != 6 || payloadLength+40 > len(ipFrame.RawData()) || ipFrame.NextHeader() != lneto.IPProtoTCP {
		return false, nil
	}
	local := n.core.IPv6AddressLocked()
	if !local.IsUnspecified() && netip.AddrFrom16(*ipFrame.DestinationAddr()) != local {
		return false, nil
	}
	payload := ipFrame.RawData()[40 : 40+payloadLength]
	var checksum lneto.CRC791
	ipFrame.CRCWritePseudo(&checksum)
	return n.ingressTCPPayloadLocked(payload, &checksum, sourceHardwareAddress, netip.AddrFrom16(*ipFrame.SourceAddr()))
}

func (n *Adapter) ingressTCPPayloadLocked(payload []byte, checksum *lneto.CRC791, sourceHardwareAddress [6]byte, sourceAddress netip.Addr) (bool, error) {
	if len(payload) < 4 {
		return false, nil
	}
	if !n.core.OwnsTCPPortLocked(binary.BigEndian.Uint16(payload[2:4]), n.portOwner) {
		return false, nil
	}
	tcpFrame, err := lnetotcp.NewFrame(payload)
	if err != nil {
		return true, nil
	}
	if !validTCPSourceAddress(sourceAddress) || !validUnicastMAC(sourceHardwareAddress) {
		return true, nil
	}
	tcpHeaderLength := tcpFrame.HeaderLength()
	if tcpFrame.SourcePort() == 0 || tcpHeaderLength < 20 || tcpHeaderLength > len(payload) {
		return true, nil
	}
	if checksum.PayloadSum16(payload) != 0 {
		return true, nil
	}
	return false, nil
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
	if !local.Valid() || local.Port == 0 || (!local.Address.Is4() && !local.Address.Is6()) {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if local.Address.Is6() && !n.core.IPv6EnabledLocked() {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if n.config.MaxListeners == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if local.Address.Is4() {
		if !local.Address.IsUnspecified() && local.Address != n.core.IPv4AddressLocked() {
			return nil, 0, nscore.Fail(nscore.FailureAddressUnavailable, lneto.ErrInvalidAddr)
		}
	} else if local.FlowInfo != 0 || (!local.Address.IsUnspecified() && (local.Address != n.core.IPv6AddressLocked() || !n.ipv6ScopeMatchesLocked(local))) {
		return nil, 0, nscore.Fail(nscore.FailureAddressUnavailable, lneto.ErrInvalidAddr)
	}
	if !n.policy.CheckEndpoint(policy.OperationTCPListen, local.Address, local.Port) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, ErrPolicyDenied)
	}
	if len(n.listeners) == int(n.config.MaxListeners) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	if n.core.TCPPortLeasedLocked(local.Port) {
		return nil, 0, nscore.Fail(nscore.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}
	if n.core.TCPPortLeaseCapacityExhaustedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	retained := uint64(n.config.AcceptBacklog) * uint64(n.config.ReceiveBytes+n.config.TransmitBytes)
	listener, err := n.acquireListenerLocked(local)
	if err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if !n.core.AcquireTCPPortIntoLocked(&listener.portLease, n.portOwner, local.Port) {
		n.recycleListenerLocked(listener)
		return nil, 0, nscore.Fail(nscore.FailureAddressInUse, lneto.ErrAlreadyRegistered)
	}
	if err := n.quotas.AcquireResourceAndQueuedBytes(&listener.retained, quota.ResourceTCP, 1, retained); err != nil {
		listener.portLease.ReleaseLocked()
		n.recycleListenerLocked(listener)
		return nil, 0, lnetocore.MapError(err)
	}
	if err := listener.listener.Reset(local.Port, &listener.pool); err != nil {
		listener.retained.Release()
		listener.retained.ResetReleased()
		listener.portLease.ReleaseLocked()
		n.recycleListenerLocked(listener)
		return nil, 0, lnetocore.MapError(err)
	}
	var registerErr error
	if local.Address.Is6() {
		registerErr = n.stack.RegisterListenerTCP6(&listener.listener)
	} else {
		registerErr = n.stack.RegisterListenerTCP(&listener.listener)
	}
	if registerErr != nil {
		_ = listener.listener.Close()
		listener.retained.Release()
		listener.retained.ResetReleased()
		listener.portLease.ReleaseLocked()
		n.recycleListenerLocked(listener)
		return nil, 0, lnetocore.MapError(registerErr)
	}
	n.listeners = append(n.listeners, listener)
	return listener, nscore.ProgressDone, nil
}

// ConnectAuthorizer decides whether one structurally valid remote endpoint may
// consume this private TCP transport and returns a stable classified failure
// when denied or unsupported. It runs while the shared core lock is held and
// must not block, retain either argument, or call back into the adapter.
// Protocol adapters use this seam to apply their own authority kind without
// publishing a raw-TCP guest capability.
type ConnectAuthorizer func(*policy.Policy, nscore.Endpoint) error

// TryConnectTCP implements the narrow raw-TCP namespace facet.
func (n *Adapter) TryConnectTCP(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.TryConnect(remote)
}

// TryConnect preserves the public raw-TCP policy behavior.
func (n *Adapter) TryConnect(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.TryConnectAuthorized(remote, func(compiled *policy.Policy, endpoint nscore.Endpoint) error {
		if !compiled.CheckEndpoint(policy.OperationTCPConnect, endpoint.Address, endpoint.Port) {
			return nscore.Fail(nscore.FailureAccessDenied, ErrPolicyDenied)
		}
		return nil
	})
}

// TryConnectAuthorized creates a private outbound TCP transport only when the
// selecting protocol's authorizer permits it. The returned resource remains a
// backend-neutral TCP stream owned by the caller; this method never publishes a
// guest handle or grants raw-TCP authority.
func (n *Adapter) TryConnectAuthorized(remote nscore.Endpoint, authorize ConnectAuthorizer) (nscore.Resource, nscore.Progress, error) {
	if n == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.core.Lock()
	defer n.core.Unlock()
	if n.core.ClosedLocked() || n.stack == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !remote.Valid() || remote.Address.IsUnspecified() || remote.Port == 0 || (!remote.Address.Is4() && !remote.Address.Is6()) {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if remote.Address.Is6() && !n.core.IPv6EnabledLocked() {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if remote.Address.Is6() && (remote.FlowInfo != 0 || !n.ipv6ScopeMatchesLocked(remote)) {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	if n.config.MaxOutboundStreams == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if authorize == nil {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, ErrPolicyDenied)
	}
	if err := authorize(n.policy, remote); err != nil {
		return nil, 0, err
	}
	if n.outboundTCPStreamsLocked() >= int(n.config.MaxOutboundStreams) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	stream := &tcpStream{owner: n, remote: remote, outbound: true}
	if !n.core.AcquireTCPPortIntoLocked(&stream.portLease, n.portOwner, 0) {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	localPort := stream.portLease.TCPPort()
	retained, _ := tcpStreamStorageBytes(n.config)
	stream.local = nscore.Endpoint{Address: n.core.IPv4AddressLocked(), Port: localPort}
	if remote.Address.Is6() {
		stream.local.Address = n.core.IPv6AddressLocked()
		if stream.local.Address.IsLinkLocalUnicast() {
			stream.local.ScopeID = n.core.IPv6ScopeIDLocked()
		}
	}
	if err := n.prepareOutboundStreamLocked(stream, retained); err != nil {
		stream.portLease.ReleaseLocked()
		return nil, 0, lnetocore.MapError(err)
	}
	conn := &stream.connValue
	if err := conn.Configure(lnetotcp.ConnConfig{
		RxBuf:             stream.storage[:n.config.ReceiveBytes],
		TxBuf:             stream.storage[n.config.ReceiveBytes:],
		TxPacketQueueSize: n.config.TransmitPackets,
		RWBackoff:         immediateBackoff,
	}); err != nil {
		stream.allocation.Release()
		stream.retained.ResetReleased()
		stream.portLease.ReleaseLocked()
		n.recycleOutboundStreamLocked(stream)
		return nil, 0, lnetocore.MapError(err)
	}
	if err := n.stack.DialTCP(conn, localPort, netip.AddrPortFrom(remote.Address, remote.Port)); err != nil {
		conn.Abort()
		stream.allocation.Release()
		stream.retained.ResetReleased()
		stream.portLease.ReleaseLocked()
		n.recycleOutboundStreamLocked(stream)
		return nil, 0, lnetocore.MapError(err)
	}
	stream.conn = conn
	n.streams = append(n.streams, stream)
	n.outboundStreams++
	return stream, nscore.ProgressInProgress, nil
}

func (l *tcpListener) LocalEndpoint() nscore.Endpoint {
	if l == nil || l.owner == nil {
		return nscore.Endpoint{}
	}
	l.owner.core.Lock()
	defer l.owner.core.Unlock()
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
	if conn, _ := l.fallbackAcceptLocked(); conn != nil {
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
	conn, slot := l.fallbackAcceptLocked()
	var userData any
	var err error
	if conn != nil {
		userData = slot
	} else {
		conn, userData, err = l.listener.TryAccept()
		if errors.Is(err, lneto.ErrExhausted) {
			return nil, nscore.ProgressWouldBlock, nil
		}
	}
	if err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	slot, ok := userData.(*tcpPoolSlot)
	if !ok || slot == nil || conn == nil || slot.stream != nil || !slot.quotaOwned {
		if conn != nil {
			conn.Abort()
		}
		return nil, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	remoteAddress := conn.RemoteAddr()
	var remoteIP netip.Addr
	switch len(remoteAddress) {
	case 4:
		remoteIP = netip.AddrFrom4([4]byte(remoteAddress))
	case 16:
		remoteIP = netip.AddrFrom16([16]byte(remoteAddress))
	default:
		conn.Abort()
		return nil, 0, nscore.Fail(nscore.FailureIO, lneto.ErrInvalidAddr)
	}
	if conn.RemotePort() == 0 {
		conn.Abort()
		return nil, 0, nscore.Fail(nscore.FailureIO, lneto.ErrInvalidAddr)
	}
	remoteEndpoint := nscore.Endpoint{Address: remoteIP, Port: conn.RemotePort()}
	if remoteIP.IsLinkLocalUnicast() {
		remoteEndpoint.ScopeID = l.owner.core.IPv6ScopeIDLocked()
	}
	stream := &tcpStream{
		owner: l.owner, conn: conn, slot: slot,
		local:      l.local,
		remote:     remoteEndpoint,
		allocation: &slot.resource,
		connected:  true,
	}
	slot.stream = stream
	l.owner.streams = append(l.owner.streams, stream)
	return stream, nscore.ProgressDone, nil
}

func (l *tcpListener) fallbackAcceptLocked() (*lnetotcp.Conn, *tcpPoolSlot) {
	if l == nil {
		return nil, nil
	}
	for i := range l.pool.slots {
		slot := &l.pool.slots[i]
		if !slot.inUse || slot.stream != nil || !slot.quotaOwned || slot.conn.InternalHandler().State() != lnetotcp.StateCloseWait {
			continue
		}
		return &slot.conn, slot
	}
	return nil, nil
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
	l.portLease.ReleaseLocked()
	if l.owner != nil {
		removeTCPListener(l.owner, l)
	}
	l.retained.Release()
	l.retained.ResetReleased()
	if l.owner != nil {
		l.owner.recycleListenerLocked(l)
	} else {
		l.pool.releaseLocked()
		l.listener = lnetotcp.Listener{}
	}
	return nil
}

func (s *tcpStream) LocalEndpoint() nscore.Endpoint {
	if s == nil || s.owner == nil {
		return nscore.Endpoint{}
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
	return s.local
}

func (s *tcpStream) RemoteEndpoint() nscore.Endpoint {
	if s == nil || s.owner == nil {
		return nscore.Endpoint{}
	}
	s.owner.core.Lock()
	defer s.owner.core.Unlock()
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
	}
	if s.connected {
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
	if s.connected {
		return nscore.ProgressDone, nil
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
		if !s.connected && (h.State().IsPreestablished() || h.AwaitingSynSend()) {
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
		s.conn = nil
	}
	if s.outbound && s.owner != nil {
		s.portLease.ReleaseLocked()
		if s.owner.outboundStreams > 0 {
			s.owner.outboundStreams--
		}
	}
	if s.allocation != nil {
		s.allocation.Release()
		if s.allocation == &s.retained {
			s.retained.ResetReleased()
		}
		s.allocation = nil
	}
	if s.slot != nil {
		s.slot.resource.ResetReleased()
		s.slot.quotaOwned = false
		s.slot = nil
	}
	if s.owner != nil {
		removeTCPStream(s.owner, s)
		if s.outbound {
			s.owner.recycleOutboundStreamLocked(s)
		}
	}
	return nil
}

func (s *tcpStream) detachFromPoolLocked() {
	if s == nil {
		return
	}
	s.terminal = true
	s.conn = nil
	if s.allocation != nil {
		s.allocation.Release()
		s.allocation = nil
	}
	if s.slot != nil {
		s.slot.resource.ResetReleased()
		s.slot.quotaOwned = false
	}
	s.slot = nil
	if s.owner != nil {
		removeTCPStream(s.owner, s)
	}
}

func validTCPSourceAddress(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return false
	}
	return !address.Is4() || address != limitedBroadcastAddress
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ethernet.BroadcastAddr() && mac[0]&1 == 0
}

func (n *Adapter) outboundTCPStreamsLocked() int {
	if n == nil {
		return 0
	}
	return n.outboundStreams
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
	for i := range n.freeListenerPools {
		n.freeListenerPools[i].destroyLocked()
	}
	for i := range n.freeOutboundStorage {
		clear(n.freeOutboundStorage[i])
	}
	n.portOwner = nil
	n.freeListenerPools = nil
	n.listeners = nil
	n.freeOutboundStorage = nil
	n.streams = nil
	n.outboundStreams = 0
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
