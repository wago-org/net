// Package dhcpv6 implements the bounded initial DHCPv6 client exchange over
// direct Ethernet II, IPv6, UDP, and pinned DHCPv6 immediate codecs. It does
// not use lneto UDP connections, blocking wrappers, deadlines, sleeps,
// retry/backoff helpers, goroutines, or retained guest slices.
package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	lnetodhcp "github.com/soypat/lneto/dhcp/dhcpv6"
	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

const (
	serviceOrder            = -80
	closeOrder              = 8
	inlinePacketBytes       = 1024
	statusNoPrefixAvailable = 6
)

var (
	allServersAndRelays = netip.MustParseAddr("ff02::1:2")
	allServersMAC       = [6]byte{0x33, 0x33, 0, 1, 0, 2}
	errPolicyDenied     = errors.New("net: DHCPv6 policy denied operation")
	errPortInUse        = errors.New("net: DHCPv6 UDP port already owned")
	errCanceled         = errors.New("DHCPv6 acquisition canceled")
	errResponseLimit    = errors.New("DHCPv6 response service-attempt limit reached")
)

// Config fixes every transaction, packet, repeated-option, retry, retained
// byte, and service-attempt dimension. The zero value disables DHCPv6.
type Config struct {
	MaxLeases               uint16
	MaxPacketBytes          int
	MaxAttempts             uint16
	ResponseServiceAttempts uint16
	MaxServerDUIDBytes      uint16
	MaxDNSServers           uint8
	MaxDomainSearch         uint8
	MaxNTPServers           uint8
	MaxNTPMulticastServers  uint8
	MaxNTPServerNames       uint8
	MaxDelegatedPrefixes    uint8
}

// Adapter owns exact internal UDP port 546 only when a configured link-local
// IPv6 identity makes the pinned client subset operational.
type Adapter struct {
	core            *lnetocore.Namespace
	config          Config
	policy          *policy.Policy
	quotas          *quota.Account
	hardwareAddress [6]byte
	address         netip.Addr
	scopeID         uint32
	clientPort      lnetocore.UDPPortLease
	lease           *leaseResource
	nextXID         uint32
	closed          bool
}

var _ dhcpns.Namespace = (*Adapter)(nil)

type leaseState uint8

const (
	leaseSolicitPending leaseState = iota + 1
	leaseWaitAdvertise
	leaseRequestPending
	leaseWaitReply
	leaseBound
	leaseFailed
	leaseClosed
)

type leaseResource struct {
	owner        *Adapter
	client       lnetodhcp.Client
	state        leaseState
	xid          uint32
	iaid         [4]byte
	clientDUID   [10]byte
	serverDUID   [dhcpns.MaxServerDUIDBytes]byte
	serverLen    uint16
	serverAddr   netip.Addr
	serverMAC    [6]byte
	packet       []byte
	packetInline [inlinePacketBytes]byte
	attempts     uint16
	wait         uint16
	result       dhcpns.Configuration
	failure      error
	retained     quota.Charge
	work         quota.Charge
}

var _ dhcpns.Resource = (*leaseResource)(nil)

// ValidConfig validates finite storage and service bounds without allocating.
func ValidConfig(config Config, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config == (Config{}) {
		return true
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	return config.MaxLeases == 1 && config.MaxPacketBytes >= 256 && config.MaxPacketBytes <= mtu-48 &&
		config.MaxAttempts > 0 && config.ResponseServiceAttempts > 0 &&
		config.MaxServerDUIDBytes > 0 && config.MaxServerDUIDBytes <= dhcpns.MaxServerDUIDBytes &&
		config.MaxDNSServers > 0 && config.MaxDNSServers <= dhcpns.MaxDNSServers &&
		config.MaxDomainSearch > 0 && config.MaxDomainSearch <= dhcpns.MaxDomainSearch &&
		config.MaxNTPServers > 0 && config.MaxNTPServers <= dhcpns.MaxNTPServers &&
		config.MaxNTPMulticastServers > 0 && config.MaxNTPMulticastServers <= dhcpns.MaxNTPMulticastServers &&
		config.MaxNTPServerNames > 0 && config.MaxNTPServerNames <= dhcpns.MaxNTPServerNames &&
		config.MaxDelegatedPrefixes > 0 && config.MaxDelegatedPrefixes <= dhcpns.MaxDelegatedPrefixes
}

func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil || !ValidConfig(config, 1500, nil, nil, false) {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	validationMTU := common.RequiredFrameBytesLocked() - 14
	if !common.IPv6EnabledLocked() && validationMTU < 1280 {
		validationMTU = 1280
	}
	if common.ClosedLocked() || !ValidConfig(config, validationMTU, common.PolicyLocked(), common.QuotasLocked(), true) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	a := &Adapter{
		core: common, config: config, policy: common.PolicyLocked(), quotas: common.QuotasLocked(),
		hardwareAddress: common.HardwareAddressLocked(), address: common.IPv6AddressLocked(), scopeID: common.IPv6ScopeIDLocked(),
		nextXID: uint32(common.RandSeedLocked()) & 0x00ff_ffff,
	}
	if a.nextXID == 0 {
		a.nextXID = 1
	}
	if config == (Config{}) || !a.operationalAddress() {
		common.Unlock()
		return a, nil
	}
	if !a.policy.CheckEndpoint(policy.OperationDHCPv6ClientBind, a.address, dhcpns.ClientPort) ||
		!a.policy.CheckEndpoint(policy.OperationDHCPv6ClientSend, allServersAndRelays, dhcpns.ServerPort) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if !common.TryLeaseUDPPortIntoLocked(&a.clientPort, dhcpns.ClientPort) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureAddressInUse, errPortInUse)
	}
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

func (a *Adapter) operationalAddress() bool {
	return a.config != (Config{}) && a.address.IsValid() && a.address.Is6() && !a.address.Is4In6() && a.address.Zone() == "" && a.address.IsLinkLocalUnicast() && a.scopeID != 0
}

func (a *Adapter) enabledLocked() bool {
	return a != nil && !a.closed && a.operationalAddress() && a.clientPort.UDPPort() == dhcpns.ClientPort
}

func (a *Adapter) Operations() dhcpns.Operations {
	if a == nil {
		return 0
	}
	a.core.Lock()
	defer a.core.Unlock()
	if !a.enabledLocked() || a.core.ClosedLocked() {
		return 0
	}
	return dhcpns.SupportedOperations
}

func retainedBytes(config Config) uint64 {
	// Account both the Wago-owned packet/result and the pinned client's bounded
	// repeated-option backing arrays and copied DUID storage conservatively.
	packetBytes := inlinePacketBytes
	if config.MaxPacketBytes > inlinePacketBytes {
		packetBytes += config.MaxPacketBytes
	}
	return uint64(packetBytes+2*dhcpns.FixedResultRetainedBytes) +
		uint64(config.MaxServerDUIDBytes) + uint64(config.MaxDNSServers+config.MaxNTPServers+config.MaxNTPMulticastServers)*16 +
		uint64(config.MaxDomainSearch+config.MaxNTPServerNames)*256 + uint64(config.MaxDelegatedPrefixes)*32
}

func (a *Adapter) TryAcquire() (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() || a.closed {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !a.enabledLocked() {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if a.lease != nil {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	xid := a.nextTransactionIDLocked()
	r := &leaseResource{owner: a, state: leaseSolicitPending, xid: xid, iaid: [4]byte(a.hardwareAddress[:4])}
	if duid := lnetodhcp.AppendDUIDLL(r.clientDUID[:0], a.hardwareAddress); len(duid) != len(r.clientDUID) {
		return nil, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	if err := a.quotas.AcquireResourceAndQueuedBytes(&r.retained, quota.ResourceDHCPv6, 1, retainedBytes(a.config)); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireDHCPv6Work(&r.work, 1); err != nil {
		r.retained.Release()
		r.retained.ResetReleased()
		return nil, 0, lnetocore.MapError(err)
	}
	if a.config.MaxPacketBytes <= len(r.packetInline) {
		r.packet = r.packetInline[:a.config.MaxPacketBytes]
	} else {
		r.packet = make([]byte, a.config.MaxPacketBytes)
	}
	if err := r.client.BeginRequest(xid, lnetodhcp.RequestConfig{
		ClientHardwareAddr: a.hardwareAddress,
		Limits: lnetodhcp.Limits{
			MaxDNSServers: int(a.config.MaxDNSServers), MaxDomainSearch: int(a.config.MaxDomainSearch),
			MaxNTPServers: int(a.config.MaxNTPServers), MaxNTPMulticastServers: int(a.config.MaxNTPMulticastServers),
			MaxNTPServerNames: int(a.config.MaxNTPServerNames), MaxDelegatedPrefixes: int(a.config.MaxDelegatedPrefixes),
		},
	}); err != nil {
		r.releaseQuotaLocked()
		clear(r.packet)
		return nil, 0, lnetocore.MapError(err)
	}
	if err := r.preparePacketLocked(lnetodhcp.MsgSolicit); err != nil {
		r.client.Reset()
		r.releaseQuotaLocked()
		clear(r.packet)
		return nil, 0, err
	}
	a.lease = r
	return r, nscore.ProgressInProgress, nil
}

func (a *Adapter) nextTransactionIDLocked() uint32 {
	for {
		xid := a.nextXID & 0x00ff_ffff
		a.nextXID = (a.nextXID + 1) & 0x00ff_ffff
		if xid != 0 {
			return xid
		}
	}
}

func (r *leaseResource) preparePacketLocked(want lnetodhcp.MsgType) error {
	n, err := r.client.Encapsulate(r.packet[:cap(r.packet)], -1, 0)
	if err != nil || n <= 0 || n > cap(r.packet) {
		return lnetocore.MapError(firstError(err, lneto.ErrBadState))
	}
	r.packet = r.packet[:n]
	frame, err := lnetodhcp.NewFrame(r.packet)
	if err != nil || frame.MsgType() != want || frame.TransactionID() != r.xid || frame.ValidateSize() != nil {
		return nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	// The pinned client emits Reconfigure Accept even though its reconfigure
	// lifecycle is not safe enough for this bounded guest contract. Remove that
	// option so the wire advertisement matches the truthful operation bitset.
	r.packet = stripOption(r.packet, lnetodhcp.OptReconfAccept)
	return nil
}

func stripOption(packet []byte, remove lnetodhcp.OptCode) []byte {
	write := lnetodhcp.OptionsOffset
	for read := lnetodhcp.OptionsOffset; read < len(packet); {
		length := int(binary.BigEndian.Uint16(packet[read+2 : read+4]))
		next := read + 4 + length
		if lnetodhcp.OptCode(binary.BigEndian.Uint16(packet[read:read+2])) != remove {
			write += copy(packet[write:], packet[read:next])
		}
		read = next
	}
	clear(packet[write:])
	return packet[:write]
}

func firstError(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

func (r *leaseResource) Readiness() nscore.Readiness {
	if r == nil || r.owner == nil {
		return nscore.ReadyClosed
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == leaseClosed || r.owner.closed || r.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if r.state == leaseFailed {
		return nscore.ReadyError
	}
	if r.state == leaseBound {
		return nscore.ReadyDHCPv6Result
	}
	return 0
}

func (r *leaseResource) TryResult() (dhcpns.Configuration, dhcpns.ResultState, error) {
	if r == nil || r.owner == nil {
		return dhcpns.Configuration{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	switch r.state {
	case leaseBound:
		if !r.result.Valid() {
			return dhcpns.Configuration{}, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
		}
		return r.result, dhcpns.ResultReady, nil
	case leaseFailed:
		return dhcpns.Configuration{}, 0, r.failure
	case leaseClosed:
		return dhcpns.Configuration{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	default:
		return dhcpns.Configuration{}, dhcpns.ResultWouldBlock, nil
	}
}

func (r *leaseResource) Cancel() error {
	if r == nil || r.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	switch r.state {
	case leaseSolicitPending, leaseWaitAdvertise, leaseRequestPending, leaseWaitReply:
		r.failLocked(nscore.FailureCanceled, errCanceled)
		return nil
	case leaseClosed:
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	default:
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
}

func (r *leaseResource) Close() error {
	if r == nil || r.owner == nil {
		return nil
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	return r.closeLocked()
}

func (r *leaseResource) closeLocked() error {
	if r.state == leaseClosed {
		return nil
	}
	r.state = leaseClosed
	r.client.Reset()
	r.client = lnetodhcp.Client{}
	if r.packet != nil {
		clear(r.packet[:cap(r.packet)])
	}
	r.packet = nil
	clear(r.packetInline[:])
	r.xid = 0
	r.iaid = [4]byte{}
	clear(r.clientDUID[:])
	clear(r.serverDUID[:])
	r.serverLen = 0
	r.serverAddr = netip.Addr{}
	r.serverMAC = [6]byte{}
	r.attempts = 0
	r.wait = 0
	r.result = dhcpns.Configuration{}
	r.failure = nil
	r.releaseQuotaLocked()
	if r.owner != nil && r.owner.lease == r {
		r.owner.lease = nil
	}
	r.owner = nil
	return nil
}

func (r *leaseResource) failLocked(failure nscore.Failure, cause error) {
	if r.state == leaseBound || r.state == leaseFailed || r.state == leaseClosed {
		return
	}
	r.state = leaseFailed
	r.failure = nscore.Fail(failure, cause)
	r.wait = 0
	r.releaseWorkLocked()
}

func (r *leaseResource) releaseWorkLocked() {
	r.work.Release()
	r.work.ResetReleased()
}

func (r *leaseResource) releaseQuotaLocked() {
	r.releaseWorkLocked()
	r.retained.Release()
	r.retained.ResetReleased()
}

func (a *Adapter) hasWorkLocked() bool {
	if a == nil || a.closed || a.lease == nil {
		return false
	}
	switch a.lease.state {
	case leaseSolicitPending, leaseWaitAdvertise, leaseRequestPending, leaseWaitReply:
		return true
	default:
		return false
	}
}

func (a *Adapter) egressLocked(dst []byte) (int, bool, error) {
	r := a.lease
	if r == nil {
		return 0, false, nil
	}
	switch r.state {
	case leaseWaitAdvertise, leaseWaitReply:
		if r.wait > 1 {
			r.wait--
			return 0, true, nil
		}
		if r.attempts >= a.config.MaxAttempts {
			r.failLocked(nscore.FailureTimedOut, errResponseLimit)
			return 0, true, nil
		}
		if r.state == leaseWaitAdvertise {
			r.state = leaseSolicitPending
		} else {
			r.state = leaseRequestPending
		}
		return 0, true, nil
	case leaseSolicitPending, leaseRequestPending:
		n, err := a.writeClientFrameLocked(dst, r.packet)
		if err != nil {
			return 0, false, err
		}
		r.attempts++
		r.wait = a.config.ResponseServiceAttempts
		if r.state == leaseSolicitPending {
			r.state = leaseWaitAdvertise
		} else {
			r.state = leaseWaitReply
		}
		return n, true, nil
	default:
		return 0, false, nil
	}
}

func (a *Adapter) writeClientFrameLocked(dst, payload []byte) (int, error) {
	frameBytes := 14 + 40 + 8 + len(payload)
	if len(dst) < frameBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:frameBytes]
	clear(frame)
	eth, _ := ethernet.NewFrame(frame)
	*eth.DestinationHardwareAddr() = allServersMAC
	*eth.SourceHardwareAddr() = a.hardwareAddress
	eth.SetEtherType(ethernet.TypeIPv6)
	ip, _ := lnetoipv6.NewFrame(frame[14:])
	ip.SetVersionTrafficAndFlow(6, 0, 0)
	ip.SetPayloadLength(uint16(8 + len(payload)))
	ip.SetNextHeader(lneto.IPProtoUDP)
	ip.SetHopLimit(1)
	*ip.SourceAddr() = a.address.As16()
	*ip.DestinationAddr() = allServersAndRelays.As16()
	udp, _ := lnetoudp.NewFrame(frame[54:])
	udp.SetSourcePort(dhcpns.ClientPort)
	udp.SetDestinationPort(dhcpns.ServerPort)
	udp.SetLength(uint16(8 + len(payload)))
	copy(udp.RawData()[8:], payload)
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWritePseudo(&checksum)
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData())))
	return frameBytes, nil
}

func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	payload, source, srcMAC, matched := a.validateFrameLocked(frame)
	if !matched {
		return false, nil
	}
	if payload == nil {
		return true, nil
	}
	r := a.lease
	if r == nil || (r.state != leaseWaitAdvertise && r.state != leaseWaitReply) {
		return true, nil
	}
	want := lnetodhcp.MsgAdvertise
	if r.state == leaseWaitReply {
		want = lnetodhcp.MsgReply
	}
	info, ok := inspectMessage(payload, want, r.xid, r.clientDUID[:], r.iaid, a.config, r.serverDUID[:r.serverLen])
	if !ok {
		return true, nil
	}
	if r.state == leaseWaitReply && (source != r.serverAddr || srcMAC != r.serverMAC) {
		return true, nil
	}
	if err := r.client.Demux(payload, 0); err != nil {
		return true, nil
	}
	if r.state == leaseWaitAdvertise {
		r.serverAddr, r.serverMAC, r.serverLen = source, srcMAC, uint16(len(info.serverDUID))
		copy(r.serverDUID[:], info.serverDUID)
		r.attempts, r.wait = 0, 0
		r.packet = r.packet[:cap(r.packet)]
		if err := r.preparePacketLocked(lnetodhcp.MsgRequest); err != nil {
			r.failLocked(nscore.FailureIO, err)
			return true, nil
		}
		r.state = leaseRequestPending
		return true, nil
	}
	configuration, ok := info.configuration(r.xid, r.iaid, source, a.scopeID, r.serverDUID[:r.serverLen])
	assigned, assignedOK := r.client.AssignedAddr()
	if !ok || !assignedOK || netip.AddrFrom16(assigned) != configuration.AssignedAddr || r.client.State() != lnetodhcp.StateBound {
		r.failLocked(nscore.FailureIO, lneto.ErrBadState)
		return true, nil
	}
	r.result = configuration
	r.state = leaseBound
	r.wait = 0
	r.releaseWorkLocked()
	clear(r.packet)
	r.packet = r.packet[:0]
	return true, nil
}

func (a *Adapter) validateFrameLocked(frame []byte) ([]byte, netip.Addr, [6]byte, bool) {
	eth, err := ethernet.NewFrame(frame)
	if err != nil || eth.EtherTypeOrSize() != ethernet.TypeIPv6 {
		return nil, netip.Addr{}, [6]byte{}, false
	}
	if *eth.DestinationHardwareAddr() != a.hardwareAddress {
		return nil, netip.Addr{}, [6]byte{}, false
	}
	if !validUnicastMAC(*eth.SourceHardwareAddr()) {
		return nil, netip.Addr{}, [6]byte{}, true
	}
	ip, err := lnetoipv6.NewFrame(eth.Payload())
	if err != nil {
		return nil, netip.Addr{}, [6]byte{}, true
	}
	version, _, _ := ip.VersionTrafficAndFlow()
	if version != 6 || ip.NextHeader() != lneto.IPProtoUDP || ip.HopLimit() == 0 || int(ip.PayloadLength())+40 > len(eth.Payload()) {
		return nil, netip.Addr{}, [6]byte{}, true
	}
	source := netip.AddrFrom16(*ip.SourceAddr())
	destination := netip.AddrFrom16(*ip.DestinationAddr())
	if !validServerAddress(source, a.scopeID) || destination != a.address || !a.policy.CheckEndpoint(policy.OperationDHCPv6ClientReceive, source, dhcpns.ServerPort) {
		return nil, netip.Addr{}, [6]byte{}, true
	}
	udpPayload := ip.Payload()
	udp, err := lnetoudp.NewFrame(udpPayload)
	if err != nil || udp.SourcePort() != dhcpns.ServerPort || udp.DestinationPort() != dhcpns.ClientPort || udp.CRC() == 0 {
		return nil, netip.Addr{}, [6]byte{}, true
	}
	var validator lneto.Validator
	udp.ValidateSize(&validator)
	if validator.ErrPop() != nil || int(udp.Length()) != len(udpPayload) || int(udp.Length())-8 > a.config.MaxPacketBytes {
		return nil, netip.Addr{}, [6]byte{}, true
	}
	var checksum lneto.CRC791
	ip.CRCWritePseudo(&checksum)
	if checksum.PayloadSum16(udp.RawData()) != 0 {
		return nil, netip.Addr{}, [6]byte{}, true
	}
	return udp.RawData()[8:], source, *eth.SourceHardwareAddr(), true
}

func validServerAddress(address netip.Addr, scopeID uint32) bool {
	if !address.IsValid() || !address.Is6() || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return false
	}
	return !address.IsLinkLocalUnicast() || scopeID != 0
}

func validResultUnicast(address netip.Addr) bool {
	return address.IsValid() && address.Is6() && !address.Is4In6() && address.Zone() == "" && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && !address.IsLinkLocalUnicast()
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != ([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) && mac[0]&1 == 0
}

type packetInfo struct {
	serverDUID               []byte
	assigned                 netip.Addr
	t1, t2, preferred, valid uint32
	pdT1, pdT2               uint32
	dns                      [dhcpns.MaxDNSServers]netip.Addr
	dnsCount                 uint8
	domains                  [dhcpns.MaxDomainSearch]dhcpns.Name
	domainCount              uint8
	ntp                      [dhcpns.MaxNTPServers]netip.Addr
	ntpCount                 uint8
	ntpMulticast             [dhcpns.MaxNTPMulticastServers]netip.Addr
	ntpMulticastCount        uint8
	ntpNames                 [dhcpns.MaxNTPServerNames]dhcpns.Name
	ntpNameCount             uint8
	prefixes                 [dhcpns.MaxDelegatedPrefixes]dhcpns.DelegatedPrefix
	prefixCount              uint8
}

func inspectMessage(payload []byte, want lnetodhcp.MsgType, xid uint32, clientDUID []byte, iaid [4]byte, config Config, selectedServerDUID []byte) (packetInfo, bool) {
	frame, err := lnetodhcp.NewFrame(payload)
	if err != nil || frame.MsgType() != want || frame.TransactionID() != xid || frame.ValidateSize() != nil {
		return packetInfo{}, false
	}
	var info packetInfo
	var clientIDs, serverIDs, statuses, ianas, iapds, dnsOptions, domainOptions, ntpOptions int
	ok := true
	err = frame.ForEachOption(func(_ int, code lnetodhcp.OptCode, data []byte) error {
		switch code {
		case lnetodhcp.OptClientID:
			clientIDs++
			ok = ok && clientIDs == 1 && bytes.Equal(data, clientDUID)
		case lnetodhcp.OptServerID:
			serverIDs++
			ok = ok && serverIDs == 1 && len(data) > 0 && len(data) <= int(config.MaxServerDUIDBytes)
			if len(selectedServerDUID) != 0 {
				ok = ok && bytes.Equal(data, selectedServerDUID)
			}
			if ok {
				info.serverDUID = data
			}
		case lnetodhcp.OptStatusCode:
			statuses++
			ok = ok && statuses == 1 && successStatus(data)
		case lnetodhcp.OptIANA:
			ianas++
			ok = ok && ianas == 1 && parseIANA(data, iaid, &info)
		case lnetodhcp.OptIAPD:
			iapds++
			ok = ok && iapds == 1 && parseIAPD(data, iaid, config.MaxDelegatedPrefixes, &info)
		case lnetodhcp.OptDNSServers:
			dnsOptions++
			ok = ok && dnsOptions == 1 && parseAddresses(data, info.dns[:], config.MaxDNSServers, false, &info.dnsCount)
		case lnetodhcp.OptDomainList:
			domainOptions++
			ok = ok && domainOptions == 1 && parseNames(data, info.domains[:], config.MaxDomainSearch, &info.domainCount)
		case lnetodhcp.OptNTPServer:
			ntpOptions++
			ok = ok && ntpOptions == 1 && parseNTP(data, config, &info)
		}
		if !ok {
			return lneto.ErrPacketDrop
		}
		return nil
	})
	return info, err == nil && ok && clientIDs == 1 && serverIDs == 1 && ianas == 1 && info.assigned.IsValid()
}

func successStatus(data []byte) bool {
	status, ok := parseStatus(data)
	return ok && status == uint16(lnetodhcp.StatusSuccess)
}

func parseStatus(data []byte) (uint16, bool) {
	if len(data) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[:2]), true
}

func parseIANA(data []byte, iaid [4]byte, info *packetInfo) bool {
	if len(data) < 12 || [4]byte(data[:4]) != iaid {
		return false
	}
	info.t1, info.t2 = binary.BigEndian.Uint32(data[4:8]), binary.BigEndian.Uint32(data[8:12])
	found := false
	statuses := 0
	for ptr := 12; ptr < len(data); {
		code, sub, next, ok := nextOption(data, ptr)
		if !ok {
			return false
		}
		switch code {
		case lnetodhcp.OptIAAddr:
			if found || len(sub) < 24 || !validIAValueOptions(sub[24:]) {
				return false
			}
			address := netip.AddrFrom16([16]byte(sub[:16]))
			preferred, valid := binary.BigEndian.Uint32(sub[16:20]), binary.BigEndian.Uint32(sub[20:24])
			if !validResultUnicast(address) || valid == 0 || preferred > valid || !validTimers(info.t1, info.t2, valid) {
				return false
			}
			info.assigned, info.preferred, info.valid, found = address, preferred, valid, true
		case lnetodhcp.OptStatusCode:
			statuses++
			if statuses != 1 || !successStatus(sub) {
				return false
			}
		}
		ptr = next
	}
	return found
}

func parseIAPD(data []byte, iaid [4]byte, limit uint8, info *packetInfo) bool {
	if len(data) < 12 || [4]byte(data[:4]) != iaid {
		return false
	}
	info.pdT1, info.pdT2 = binary.BigEndian.Uint32(data[4:8]), binary.BigEndian.Uint32(data[8:12])
	initialCount := info.prefixCount
	var maximum uint32
	var status uint16
	statuses := 0
	for ptr := 12; ptr < len(data); {
		code, sub, next, ok := nextOption(data, ptr)
		if !ok {
			return false
		}
		switch code {
		case lnetodhcp.OptIAPrefix:
			if len(sub) < 25 || !validIAValueOptions(sub[25:]) || info.prefixCount >= limit {
				return false
			}
			preferred, valid, bits := binary.BigEndian.Uint32(sub[:4]), binary.BigEndian.Uint32(sub[4:8]), int(sub[8])
			prefix := netip.PrefixFrom(netip.AddrFrom16([16]byte(sub[9:25])), bits)
			value := dhcpns.DelegatedPrefix{Prefix: prefix.Masked(), PreferredLifetime: preferred, ValidLifetime: valid}
			if !value.Valid() {
				return false
			}
			info.prefixes[info.prefixCount] = value
			info.prefixCount++
			if valid > maximum {
				maximum = valid
			}
		case lnetodhcp.OptStatusCode:
			statuses++
			var valid bool
			status, valid = parseStatus(sub)
			if statuses != 1 || !valid {
				return false
			}
		}
		ptr = next
	}
	if info.prefixCount == initialCount {
		if statuses != 1 || status != statusNoPrefixAvailable {
			return false
		}
		// NoPrefixAvail is local to IA_PD and does not invalidate a usable
		// IA_NA. An absent delegation has no renewal or rebinding timers.
		info.pdT1, info.pdT2 = 0, 0
		return true
	}
	return (statuses == 0 || status == uint16(lnetodhcp.StatusSuccess)) && validTimers(info.pdT1, info.pdT2, maximum)
}

func parseAddresses(data []byte, destination []netip.Addr, limit uint8, multicast bool, count *uint8) bool {
	if len(data) == 0 || len(data)%16 != 0 || len(data)/16 > int(limit) {
		return false
	}
	for off := 0; off < len(data); off += 16 {
		address := netip.AddrFrom16([16]byte(data[off : off+16]))
		if multicast {
			if !address.Is6() || !address.IsMulticast() || address.Is4In6() {
				return false
			}
		} else if !validResultUnicast(address) {
			return false
		}
		destination[*count] = address
		(*count)++
	}
	return true
}

func parseNames(data []byte, destination []dhcpns.Name, limit uint8, count *uint8) bool {
	if len(data) == 0 {
		return false
	}
	for offset := 0; offset < len(data); {
		if *count >= limit {
			return false
		}
		start := offset
		var dotted [dhcpns.MaxNameBytes]byte
		written := 0
		for {
			if offset >= len(data) {
				return false
			}
			length := int(data[offset])
			offset++
			if length == 0 {
				break
			}
			separator := 0
			if written != 0 {
				separator = 1
			}
			if length > 63 || offset+length > len(data) || written+separator+length > len(dotted) {
				return false
			}
			if separator != 0 {
				dotted[written] = '.'
				written++
			}
			for _, value := range data[offset : offset+length] {
				if value >= 'A' && value <= 'Z' {
					value += 'a' - 'A'
				}
				dotted[written] = value
				written++
			}
			offset += length
		}
		if offset == start+1 {
			return false
		}
		name, ok := dhcpns.NewNameBytes(dotted[:written])
		if !ok {
			return false
		}
		destination[*count] = name
		(*count)++
	}
	return true
}

func parseNTP(data []byte, config Config, info *packetInfo) bool {
	if len(data) == 0 {
		return false
	}
	for ptr := 0; ptr < len(data); {
		if ptr+4 > len(data) {
			return false
		}
		code := binary.BigEndian.Uint16(data[ptr : ptr+2])
		length := int(binary.BigEndian.Uint16(data[ptr+2 : ptr+4]))
		if ptr+4+length > len(data) {
			return false
		}
		sub := data[ptr+4 : ptr+4+length]
		switch code {
		case 1:
			if length != 16 || info.ntpCount >= config.MaxNTPServers {
				return false
			}
			address := netip.AddrFrom16([16]byte(sub))
			if !validResultUnicast(address) {
				return false
			}
			info.ntp[info.ntpCount], info.ntpCount = address, info.ntpCount+1
		case 2:
			if length != 16 || info.ntpMulticastCount >= config.MaxNTPMulticastServers {
				return false
			}
			address := netip.AddrFrom16([16]byte(sub))
			if !address.Is6() || !address.IsMulticast() || address.Is4In6() {
				return false
			}
			info.ntpMulticast[info.ntpMulticastCount], info.ntpMulticastCount = address, info.ntpMulticastCount+1
		case 3:
			var names [1]dhcpns.Name
			var count uint8
			if info.ntpNameCount >= config.MaxNTPServerNames || !parseNames(sub, names[:], 1, &count) || count != 1 {
				return false
			}
			info.ntpNames[info.ntpNameCount], info.ntpNameCount = names[0], info.ntpNameCount+1
		default:
			return false
		}
		ptr += 4 + length
	}
	return true
}

func validIAValueOptions(data []byte) bool {
	statuses := 0
	for ptr := 0; ptr < len(data); {
		code, sub, next, ok := nextOption(data, ptr)
		if !ok {
			return false
		}
		if code == lnetodhcp.OptStatusCode {
			statuses++
			if statuses != 1 || !successStatus(sub) {
				return false
			}
		}
		ptr = next
	}
	return true
}

func nextOption(data []byte, ptr int) (lnetodhcp.OptCode, []byte, int, bool) {
	if ptr+4 > len(data) {
		return 0, nil, ptr, false
	}
	code := lnetodhcp.OptCode(binary.BigEndian.Uint16(data[ptr : ptr+2]))
	length := int(binary.BigEndian.Uint16(data[ptr+2 : ptr+4]))
	next := ptr + 4 + length
	if next > len(data) {
		return 0, nil, ptr, false
	}
	return code, data[ptr+4 : next], next, true
}

func validTimers(t1, t2, lifetime uint32) bool {
	return (t1 == 0 || t1 <= lifetime) && (t2 == 0 || t2 <= lifetime) && (t1 == 0 || t2 == 0 || t1 <= t2)
}

func (info *packetInfo) configuration(xid uint32, iaid [4]byte, server netip.Addr, scopeID uint32, serverDUID []byte) (dhcpns.Configuration, bool) {
	configuration := dhcpns.Configuration{
		TransactionID: xid, IAID: iaid, AssignedAddr: info.assigned, ServerAddr: server,
		RenewalSeconds: info.t1, RebindingSeconds: info.t2, PreferredLifetimeSeconds: info.preferred, ValidLifetimeSeconds: info.valid,
		PrefixRenewalSeconds: info.pdT1, PrefixRebindingSeconds: info.pdT2,
		DNSCount: info.dnsCount, DNSServers: info.dns, DomainCount: info.domainCount, DomainSearch: info.domains,
		NTPCount: info.ntpCount, NTPServers: info.ntp, NTPMulticastCount: info.ntpMulticastCount, NTPMulticastServers: info.ntpMulticast,
		NTPNameCount: info.ntpNameCount, NTPServerNames: info.ntpNames, PrefixCount: info.prefixCount, DelegatedPrefixes: info.prefixes,
		ServerDUIDLength: uint16(len(serverDUID)),
	}
	if server.IsLinkLocalUnicast() {
		configuration.ServerScopeID = scopeID
	}
	copy(configuration.ServerDUID[:], serverDUID)
	return configuration, configuration.Valid()
}

// CloseLocked synchronously cancels the exact acquisition, clears retained
// packet/configuration data, releases work/resource/byte quota and UDP 546.
func (a *Adapter) CloseLocked() {
	if a == nil || a.closed {
		return
	}
	a.closed = true
	if a.lease != nil {
		_ = a.lease.closeLocked()
	}
	a.clientPort.ReleaseLocked()
}
