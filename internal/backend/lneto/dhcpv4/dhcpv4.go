// Package dhcpv4 implements bounded immediate DHCPv4 DORA client leases and
// explicitly configured finite server operation over one shared lneto core.
package dhcpv4

import (
	"errors"
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	lnetodhcp "github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ dhcpns.Resource = (*leaseResource)(nil)

const (
	serviceOrder = 7
	closeOrder   = 7
)

var (
	limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	broadcastMAC     = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	errPolicyDenied  = errors.New("net: DHCPv4 policy denied operation")
	errPortInUse     = errors.New("net: DHCPv4 UDP port already owned")
	errCanceled      = errors.New("DHCPv4 acquisition canceled")
	errResponseLimit = errors.New("DHCPv4 response service-attempt limit reached")
)

// ServerConfig enables one finite automatic DHCPv4 server. It is disabled by
// the zero value and never inherits ordinary UDP authority.
type ServerConfig struct {
	ServerAddr   netip.Addr
	Gateway      netip.Addr
	DNS          netip.Addr
	Subnet       netip.Prefix
	LeaseSeconds uint32
	MaxClients   uint16
}

// Config bounds every client/server, packet, option, and service-attempt
// dimension. MaxLeases is currently limited to one because DHCP clients share
// the exact well-known UDP port 68.
type Config struct {
	MaxLeases               uint16
	MaxPacketBytes          int
	ResponseServiceAttempts uint16
	MaxDNSServers           uint8
	ApplyLease              bool
	Server                  ServerConfig
}

type Adapter struct {
	core            *lnetocore.Namespace
	config          Config
	hardwareAddress [6]byte
	policy          *policy.Policy
	quotas          *quota.Account
	clientPort      lnetocore.UDPPortLease
	serverPort      lnetocore.UDPPortLease
	lease           *leaseResource
	nextXID         uint32

	server           lnetodhcp.Server
	serverEnabled    bool
	serverClients    []serverClientKey
	serverPending    uint16
	clientEgressTurn bool
}

type leaseState uint8

const (
	leaseDiscover leaseState = iota + 1
	leaseWaitOffer
	leaseRequest
	leaseWaitACK
	leaseBound
	leaseFailed
	leaseReleased
	leaseClosed
)

type leaseResource struct {
	owner    *Adapter
	client   lnetodhcp.Client
	request  dhcpns.Request
	result   dhcpns.Lease
	state    leaseState
	wait     uint16
	failure  error
	identity lnetocore.IPv4IdentityLease
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
	a := &Adapter{core: common, config: config, hardwareAddress: common.HardwareAddressLocked(), policy: common.PolicyLocked(), quotas: common.QuotasLocked(), nextXID: uint32(common.RandSeedLocked()) | 1}
	if config == (Config{}) {
		common.Unlock()
		return a, nil
	}
	if config.MaxLeases != 0 {
		if !common.TryLeaseUDPPortIntoLocked(&a.clientPort, dhcpns.ClientPort) {
			common.Unlock()
			return nil, nscore.Fail(nscore.FailureAddressInUse, errPortInUse)
		}
	}
	if serverConfigured(config.Server) {
		if config.Server.ServerAddr != common.IPv4AddressLocked() {
			a.clientPort.ReleaseLocked()
			common.Unlock()
			return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
		}
		if !a.policy.CheckEndpoint(policy.OperationDHCPv4ServerBind, config.Server.ServerAddr, dhcpns.ServerPort) {
			a.clientPort.ReleaseLocked()
			common.Unlock()
			return nil, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
		}
		if !common.TryLeaseUDPPortIntoLocked(&a.serverPort, dhcpns.ServerPort) {
			a.clientPort.ReleaseLocked()
			common.Unlock()
			return nil, nscore.Fail(nscore.FailureAddressInUse, errPortInUse)
		}
		sv := config.Server
		serverAddr := sv.ServerAddr.As4()
		serverConfig := lnetodhcp.ServerConfig{ServerAddr: serverAddr, Subnet: ipv4.PrefixFromNetip(sv.Subnet), LeaseSeconds: sv.LeaseSeconds}
		if sv.Gateway.IsValid() {
			serverConfig.Gateway = sv.Gateway.As4()
		}
		if sv.DNS.IsValid() {
			serverConfig.DNS = sv.DNS.As4()
		}
		if err := a.server.Configure(serverConfig); err != nil {
			a.serverPort.ReleaseLocked()
			a.clientPort.ReleaseLocked()
			common.Unlock()
			return nil, lnetocore.MapError(err)
		}
		a.serverEnabled = true
		a.serverClients = make([]serverClientKey, 0, sv.MaxClients)
	}
	common.Unlock()
	if err := common.Install(lnetocore.Participant{IngressOrder: serviceOrder, Ingress: a.ingressLocked, EgressOrder: serviceOrder, HasEgress: a.hasWorkLocked, Egress: a.egressLocked, CloseOrder: closeOrder, Close: a.CloseLocked}); err != nil {
		common.Lock()
		a.CloseLocked()
		common.Unlock()
		return nil, err
	}
	return a, nil
}

func ValidConfig(config Config, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxLeases == 0 && !serverConfigured(config.Server) {
		return config == (Config{})
	}
	if requireAuthority && (compiled == nil || account == nil) {
		return false
	}
	if config.MaxLeases > 1 || config.MaxPacketBytes < lnetodhcp.OptionsOffset+1 || config.MaxPacketBytes > mtu-28 || config.ResponseServiceAttempts == 0 || config.MaxDNSServers == 0 || config.MaxDNSServers > dhcpns.MaxDNSServers {
		return false
	}
	if config.MaxLeases == 0 && config.ApplyLease {
		return false
	}
	return !serverConfigured(config.Server) || validServer(config.Server)
}

func serverConfigured(config ServerConfig) bool { return config != (ServerConfig{}) }

func validServer(config ServerConfig) bool {
	return validIPv4(config.ServerAddr) && config.Subnet.IsValid() && config.Subnet.Addr().Is4() && config.Subnet.Contains(config.ServerAddr) && config.LeaseSeconds > 0 && config.MaxClients > 0 && validOptionalAdvertisedIPv4(config.Gateway) && validOptionalAdvertisedIPv4(config.DNS)
}

func validIPv4(address netip.Addr) bool {
	return address.Is4() && !address.Is4In6() && address.Zone() == "" && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && address != limitedBroadcast
}

func validOptionalAdvertisedIPv4(address netip.Addr) bool {
	return !address.IsValid() || validIPv4(address)
}

func (a *Adapter) TryAcquire(request dhcpns.Request) (nscore.Resource, nscore.Progress, error) {
	if a == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.core.ClosedLocked() {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if a.config.MaxLeases == 0 {
		return nil, 0, nscore.Fail(nscore.FailureNotSupported, lneto.ErrUnsupported)
	}
	if !request.Valid() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	if a.lease != nil {
		return nil, 0, nscore.Fail(nscore.FailureResourceLimit, lneto.ErrExhausted)
	}
	if !a.policy.CheckEndpoint(policy.OperationDHCPv4ClientBind, netip.IPv4Unspecified(), dhcpns.ClientPort) || !a.policy.CheckEndpoint(policy.OperationDHCPv4ClientSend, limitedBroadcast, dhcpns.ServerPort) {
		return nil, 0, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	if a.config.ApplyLease && !a.core.IPv4AddressLocked().IsUnspecified() {
		return nil, 0, nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	r := &leaseResource{owner: a, request: request, state: leaseDiscover}
	xid := a.nextXID
	a.nextXID += 2
	var requested [4]byte
	if request.RequestedAddr.IsValid() {
		requested = request.RequestedAddr.As4()
	}
	if err := r.client.BeginRequest(xid, lnetodhcp.RequestConfig{RequestedAddr: requested, ClientHardwareAddr: a.hardwareAddress, Hostname: request.HostnameString(), ClientID: request.ClientIDString()}); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireResourceAndQueuedBytes(&r.retained, quota.ResourceDHCPv4, 1, uint64(a.config.MaxPacketBytes)); err != nil {
		return nil, 0, lnetocore.MapError(err)
	}
	if err := a.quotas.AcquireDHCPv4Work(&r.work, 1); err != nil {
		r.retained.Release()
		r.retained.ResetReleased()
		return nil, 0, lnetocore.MapError(err)
	}
	a.lease = r
	return r, nscore.ProgressInProgress, nil
}

func (r *leaseResource) Readiness() nscore.Readiness {
	if r == nil || r.owner == nil {
		return nscore.ReadyClosed
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == leaseClosed || r.owner.core.ClosedLocked() {
		return nscore.ReadyClosed
	}
	if r.state == leaseFailed {
		return nscore.ReadyError
	}
	if r.state == leaseBound || r.state == leaseReleased {
		return nscore.ReadyDHCPv4Lease
	}
	return 0
}

func (r *leaseResource) TryResult() (dhcpns.Lease, dhcpns.ResultState, error) {
	if r == nil || r.owner == nil {
		return dhcpns.Lease{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	switch r.state {
	case leaseBound, leaseReleased:
		if !r.result.Valid() {
			return dhcpns.Lease{}, 0, nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
		}
		return r.result, dhcpns.ResultReady, nil
	case leaseFailed:
		return dhcpns.Lease{}, 0, r.failure
	case leaseClosed:
		return dhcpns.Lease{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	default:
		return dhcpns.Lease{}, dhcpns.ResultWouldBlock, nil
	}
}

func (r *leaseResource) Cancel() error {
	if r == nil || r.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == leaseDiscover || r.state == leaseWaitOffer || r.state == leaseRequest || r.state == leaseWaitACK {
		r.failLocked(nscore.FailureCanceled, errCanceled)
		return nil
	}
	if r.state == leaseClosed {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
}

// Release deterministically rolls back an applied identity. The pinned client
// has no immediate DHCPRELEASE operation, so this is explicitly local release.
func (r *leaseResource) Release() error {
	if r == nil || r.owner == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	r.owner.core.Lock()
	defer r.owner.core.Unlock()
	if r.state == leaseReleased {
		return nil
	}
	if r.state != leaseBound {
		return nscore.Fail(nscore.FailureInvalidState, lneto.ErrBadState)
	}
	if r.identity.Active() && !r.identity.ReleaseLocked() {
		return nscore.Fail(nscore.FailureIO, lneto.ErrBadState)
	}
	r.result.Applied = false
	r.state = leaseReleased
	return nil
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
	if r.identity.Active() {
		_ = r.identity.ReleaseLocked()
	}
	r.state = leaseClosed
	r.client.Reset()
	r.request = dhcpns.Request{}
	r.result = dhcpns.Lease{}
	r.failure = nil
	r.releaseWorkLocked()
	r.retained.Release()
	r.retained.ResetReleased()
	if r.owner != nil && r.owner.lease == r {
		r.owner.lease = nil
	}
	return nil
}

func (r *leaseResource) failLocked(failure nscore.Failure, cause error) {
	if r.state == leaseBound || r.state == leaseReleased || r.state == leaseFailed || r.state == leaseClosed {
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

func (a *Adapter) clientHasWorkLocked() bool {
	return a.lease != nil && (a.lease.state == leaseDiscover || a.lease.state == leaseWaitOffer || a.lease.state == leaseRequest || a.lease.state == leaseWaitACK)
}

func (a *Adapter) hasWorkLocked() bool {
	return a.serverPending != 0 || a.clientHasWorkLocked()
}

func (a *Adapter) egressLocked(dst []byte) (int, bool, error) {
	clientWork := a.clientHasWorkLocked()
	if a.serverPending != 0 && (!clientWork || !a.clientEgressTurn) {
		n, err := a.writeServerFrame(dst)
		if err == nil {
			if a.serverPending != 0 {
				a.serverPending--
			}
			a.clientEgressTurn = true
		}
		return n, true, err
	}
	if !clientWork {
		return 0, false, nil
	}
	n, worked, err := a.egressClientLocked(dst)
	if err == nil && worked {
		a.clientEgressTurn = false
	}
	return n, worked, err
}

func (a *Adapter) egressClientLocked(dst []byte) (int, bool, error) {
	r := a.lease
	if r.state == leaseWaitOffer || r.state == leaseWaitACK {
		if r.wait > 1 {
			r.wait--
			return 0, true, nil
		}
		r.failLocked(nscore.FailureTimedOut, errResponseLimit)
		return 0, true, nil
	}
	n, err := a.writeClientFrame(dst, r)
	if err != nil {
		return 0, false, err
	}
	if n == 0 {
		r.failLocked(nscore.FailureIO, lneto.ErrBadState)
		return 0, true, nil
	}
	if r.state == leaseDiscover {
		r.state = leaseWaitOffer
	} else {
		r.state = leaseWaitACK
	}
	r.wait = a.config.ResponseServiceAttempts
	return n, true, nil
}

func (a *Adapter) writeClientFrame(dst []byte, r *leaseResource) (int, error) {
	if len(dst) < 14+20+8+a.config.MaxPacketBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:14+20+8+a.config.MaxPacketBytes]
	clear(frame)
	eth, _ := ethernet.NewFrame(frame)
	*eth.DestinationHardwareAddr() = broadcastMAC
	*eth.SourceHardwareAddr() = a.hardwareAddress
	eth.SetEtherType(ethernet.TypeIPv4)
	ip, _ := ipv4.NewFrame(frame[14:])
	ip.SetVersionAndIHL(4, 5)
	ip.SetTTL(64)
	ip.SetProtocol(lneto.IPProtoUDP)
	udp, _ := lnetoudp.NewFrame(frame[34:])
	udp.SetSourcePort(dhcpns.ClientPort)
	udp.SetDestinationPort(dhcpns.ServerPort)
	payloadBytes, err := r.client.Encapsulate(frame, 14, 42)
	if err != nil || payloadBytes == 0 {
		return 0, err
	}
	frameBytes := 14 + 20 + 8 + payloadBytes
	ip.SetTotalLength(uint16(20 + 8 + payloadBytes))
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp.SetLength(uint16(8 + payloadBytes))
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frameBytes, nil
}

func (a *Adapter) writeServerFrame(dst []byte) (int, error) {
	if len(dst) < 14+20+8+a.config.MaxPacketBytes {
		return 0, lneto.ErrShortBuffer
	}
	frame := dst[:14+20+8+a.config.MaxPacketBytes]
	clear(frame)
	eth, _ := ethernet.NewFrame(frame)
	*eth.DestinationHardwareAddr() = broadcastMAC
	*eth.SourceHardwareAddr() = a.hardwareAddress
	eth.SetEtherType(ethernet.TypeIPv4)
	ip, _ := ipv4.NewFrame(frame[14:])
	ip.SetVersionAndIHL(4, 5)
	ip.SetTTL(64)
	ip.SetProtocol(lneto.IPProtoUDP)
	udp, _ := lnetoudp.NewFrame(frame[34:])
	udp.SetSourcePort(dhcpns.ServerPort)
	udp.SetDestinationPort(dhcpns.ClientPort)
	payloadBytes, err := a.server.Encapsulate(frame, 14, 42)
	if err != nil || payloadBytes == 0 {
		return 0, err
	}
	if payloadBytes > len(frame)-42 {
		clear(frame)
		return 0, lneto.ErrBadState
	}
	payload, err := lnetodhcp.NewFrame(frame[42 : 42+payloadBytes])
	if err != nil {
		clear(frame)
		return 0, err
	}
	// This server never accepts or emits relayed exchanges. The pinned codec
	// also uses Gateway for giaddr; keep the advertised router option but clear
	// the relay-only header field on direct OFFER and ACK responses.
	*payload.GIAddr() = [4]byte{}
	destination := netip.AddrFrom4(*ip.DestinationAddr())
	if !a.policy.CheckEndpoint(policy.OperationDHCPv4ServerSend, destination, dhcpns.ClientPort) {
		clear(frame)
		return 0, nil
	}
	frameBytes := 14 + 20 + 8 + payloadBytes
	ip.SetTotalLength(uint16(20 + 8 + payloadBytes))
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp.SetLength(uint16(8 + payloadBytes))
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frameBytes, nil
}

func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	payload, source, sourcePort, destinationPort, matched, err := a.validateFrame(frame)
	if !matched {
		return false, err
	}
	if err != nil {
		return true, nil
	}
	if destinationPort == dhcpns.ClientPort && sourcePort == dhcpns.ServerPort {
		a.acceptClientLocked(payload, source)
		return true, nil
	}
	if destinationPort == dhcpns.ServerPort && sourcePort == dhcpns.ClientPort && a.serverEnabled {
		a.acceptServerLocked(payload)
		return true, nil
	}
	return false, nil
}

func (a *Adapter) validateFrame(frame []byte) ([]byte, netip.Addr, uint16, uint16, bool, error) {
	eth, err := ethernet.NewFrame(frame)
	if err != nil || eth.EtherTypeOrSize() != ethernet.TypeIPv4 {
		return nil, netip.Addr{}, 0, 0, false, err
	}
	destinationMAC := *eth.DestinationHardwareAddr()
	if destinationMAC != a.hardwareAddress && destinationMAC != broadcastMAC {
		return nil, netip.Addr{}, 0, 0, false, nil
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		return nil, netip.Addr{}, 0, 0, false, err
	}
	version, ihl := ip.VersionAndIHL()
	if version != 4 || ihl < 5 || ip.Protocol() != lneto.IPProtoUDP {
		return nil, netip.Addr{}, 0, 0, false, nil
	}
	var validator lneto.Validator
	ip.ValidateSize(&validator)
	if validator.ErrPop() != nil {
		return nil, netip.Addr{}, 0, 0, false, nil
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		return nil, netip.Addr{}, 0, 0, false, err
	}
	sourcePort, destinationPort := udp.SourcePort(), udp.DestinationPort()
	portsMatch := sourcePort == dhcpns.ServerPort && destinationPort == dhcpns.ClientPort || sourcePort == dhcpns.ClientPort && destinationPort == dhcpns.ServerPort
	if !portsMatch {
		return nil, netip.Addr{}, 0, 0, false, nil
	}
	if !validUnicastMAC(*eth.SourceHardwareAddr()) {
		return nil, netip.Addr{}, 0, 0, true, nil
	}
	ip.ValidateExceptCRC(&validator)
	if validator.ErrPop() != nil || ip.CalculateHeaderCRC() != 0 || ip.Flags().MoreFragments() || ip.Flags().FragmentOffset() != 0 {
		return nil, netip.Addr{}, 0, 0, true, lneto.ErrBadCRC
	}
	udp.ValidateSize(&validator)
	if err := validator.ErrPop(); err != nil {
		return nil, netip.Addr{}, 0, 0, true, err
	}
	length := udp.Length()
	if int(length)-8 > a.config.MaxPacketBytes {
		return nil, netip.Addr{}, 0, 0, true, lneto.ErrShortBuffer
	}
	if udp.CRC() != 0 {
		var checksum lneto.CRC791
		ip.CRCWriteUDPPseudo(&checksum, length)
		if checksum.PayloadSum16(udp.RawData()[:length]) != 0 {
			return nil, netip.Addr{}, 0, 0, true, lneto.ErrBadCRC
		}
	}
	return udp.RawData()[8:length], netip.AddrFrom4(*ip.SourceAddr()), sourcePort, destinationPort, true, nil
}

func (a *Adapter) acceptClientLocked(payload []byte, source netip.Addr) {
	r := a.lease
	if r == nil || (r.state != leaseWaitOffer && r.state != leaseWaitACK) {
		return
	}
	frame, err := lnetodhcp.NewFrame(payload)
	if err != nil || frame.MagicCookie() != lnetodhcp.MagicCookie || *frame.CHAddrAs6() != a.hardwareAddress {
		return
	}
	message, server, dnsCount, ok := inspectPacket(frame)
	if !ok || dnsCount > int(a.config.MaxDNSServers) {
		return
	}
	if r.state == leaseWaitOffer {
		if message != lnetodhcp.MsgOffer || !validIPv4(server) || source != server {
			return
		}
	} else {
		selected, valid := r.client.ServerAddr()
		if (message != lnetodhcp.MsgAck && message != lnetodhcp.MsgNack) || !valid || source != netip.AddrFrom4(selected) || server != source {
			return
		}
	}
	if err := r.client.Demux(payload, 0); err != nil {
		if message == lnetodhcp.MsgNack {
			r.failLocked(nscore.FailureTemporary, err)
		}
		return
	}
	if r.state == leaseWaitOffer {
		r.state = leaseRequest
		r.wait = 0
		return
	}
	lease, ok := a.clientLeaseLocked(r)
	if !ok {
		r.failLocked(nscore.FailureIO, lneto.ErrInvalidField)
		return
	}
	if a.config.ApplyLease {
		if !a.core.TryApplyIPv4IdentityLocked(&r.identity, lease.AssignedAddr, lease.Subnet) {
			r.failLocked(nscore.FailureInvalidState, lneto.ErrBadState)
			return
		}
		lease.Applied = true
	}
	r.result = lease
	r.state = leaseBound
	r.wait = 0
	r.releaseWorkLocked()
}

func (a *Adapter) clientLeaseLocked(r *leaseResource) (dhcpns.Lease, bool) {
	assigned, assignedOK := r.client.AssignedAddr()
	server, serverOK := r.client.ServerAddr()
	if !assignedOK || !serverOK {
		return dhcpns.Lease{}, false
	}
	lease := dhcpns.Lease{AssignedAddr: netip.AddrFrom4(assigned), ServerAddr: netip.AddrFrom4(server), Subnet: r.client.SubnetPrefix().NetipPrefix().Masked(), LeaseSeconds: r.client.IPLeaseSeconds(), RenewalSeconds: r.client.RenewalSeconds(), RebindSeconds: r.client.RebindingSeconds()}
	if router, ok := r.client.RouterAddr(); ok && router != ([4]byte{}) {
		lease.RouterAddr = netip.AddrFrom4(router)
	}
	if broadcast, ok := r.client.BroadcastAddr(); ok && broadcast != ([4]byte{}) {
		lease.BroadcastAddr = netip.AddrFrom4(broadcast)
	}
	dns := r.client.AppendDNSServers(nil)
	if len(dns) > int(a.config.MaxDNSServers) {
		return dhcpns.Lease{}, false
	}
	lease.DNSCount = uint8(len(dns))
	copy(lease.DNSServers[:], dns)
	return lease, lease.Valid()
}

func inspectPacket(frame lnetodhcp.Frame) (lnetodhcp.MessageType, netip.Addr, int, bool) {
	var message lnetodhcp.MessageType
	var server netip.Addr
	var dnsCount int
	var messageSeen, serverSeen bool
	err := frame.ForEachOption(func(_ int, option lnetodhcp.OptNum, data []byte) error {
		switch option {
		case lnetodhcp.OptMessageType:
			if messageSeen || len(data) != 1 {
				return lneto.ErrInvalidField
			}
			messageSeen = true
			message = lnetodhcp.MessageType(data[0])
		case lnetodhcp.OptServerIdentification:
			if serverSeen || len(data) != 4 {
				return lneto.ErrInvalidField
			}
			serverSeen = true
			server = netip.AddrFrom4([4]byte(data))
			if !validIPv4(server) {
				return lneto.ErrInvalidField
			}
		case lnetodhcp.OptRouter:
			if len(data) == 0 || len(data)%4 != 0 {
				return lneto.ErrInvalidLengthField
			}
			if containsInvalidAdvertisedIPv4(data) {
				return lneto.ErrInvalidField
			}
		case lnetodhcp.OptBroadcastAddress:
			if len(data) != 4 {
				return lneto.ErrInvalidLengthField
			}
			if containsInvalidAdvertisedIPv4(data) {
				return lneto.ErrInvalidField
			}
		case lnetodhcp.OptDNSServers:
			if len(data) == 0 || len(data)%4 != 0 {
				return lneto.ErrInvalidLengthField
			}
			if containsInvalidAdvertisedIPv4(data) {
				return lneto.ErrInvalidField
			}
			dnsCount += len(data) / 4
		}
		return nil
	})
	return message, server, dnsCount, err == nil && messageSeen && message != 0
}

func containsInvalidAdvertisedIPv4(data []byte) bool {
	for len(data) >= 4 {
		if !validIPv4(netip.AddrFrom4([4]byte(data[:4]))) {
			return true
		}
		data = data[4:]
	}
	return false
}

func (a *Adapter) acceptServerLocked(payload []byte) {
	frame, err := lnetodhcp.NewFrame(payload)
	if err != nil || frame.MagicCookie() != lnetodhcp.MagicCookie || !validUnicastMAC(*frame.CHAddrAs6()) {
		return
	}
	message, _, _, ok := inspectPacket(frame)
	if !ok {
		return
	}
	key, canonicalOffset, identityOK := serverClientIdentity(frame)
	if !identityOK {
		return
	}
	known := keyIndex(a.serverClients, key) >= 0
	newClient := message == lnetodhcp.MsgDiscover && !known
	if newClient && len(a.serverClients) == cap(a.serverClients) {
		return
	}
	if !known && message != lnetodhcp.MsgDiscover {
		return
	}
	if canonicalOffset >= 0 {
		// The pinned server still recognizes its legacy option 60 spelling.
		// Temporarily bridge standard option 61 in the consumed packet buffer;
		// restore it immediately so no retained or shared input is changed.
		payload[canonicalOffset] = byte(lnetodhcp.OptClientIdentifier)
	}
	err = a.server.Demux(payload, 0)
	if canonicalOffset >= 0 {
		payload[canonicalOffset] = byte(lnetodhcp.OptClientIdentifier1)
	}
	if err != nil {
		return
	}
	if newClient {
		a.serverClients = append(a.serverClients, key)
	}
	switch message {
	case lnetodhcp.MsgDiscover, lnetodhcp.MsgRequest:
		if a.serverPending < a.config.Server.MaxClients {
			a.serverPending++
		}
	case lnetodhcp.MsgRelease:
		if index := keyIndex(a.serverClients, key); index >= 0 {
			copy(a.serverClients[index:], a.serverClients[index+1:])
			a.serverClients = a.serverClients[:len(a.serverClients)-1]
		}
	}
}

type serverClientKey struct {
	value      [36]byte
	length     uint8
	identifier bool
}

func clientKey(frame lnetodhcp.Frame) serverClientKey {
	var canonical, legacy serverClientKey
	_ = frame.ForEachOption(func(_ int, option lnetodhcp.OptNum, data []byte) error {
		if len(data) == 0 || len(data) > len(canonical.value) {
			return nil
		}
		var key *serverClientKey
		switch option {
		case lnetodhcp.OptClientIdentifier1:
			key = &canonical
		case lnetodhcp.OptClientIdentifier:
			key = &legacy
		default:
			return nil
		}
		*key = serverClientKey{length: uint8(len(data)), identifier: true}
		copy(key.value[:], data)
		return nil
	})
	if canonical.identifier {
		return canonical
	}
	if legacy.identifier {
		return legacy
	}
	key := serverClientKey{length: 6}
	copy(key.value[:], frame.CHAddrAs6()[:])
	return key
}

func serverClientIdentity(frame lnetodhcp.Frame) (serverClientKey, int, bool) {
	var key serverClientKey
	canonicalOffset := -1
	options := frame.OptionsPayload()
	if len(options) == 0 {
		return serverClientKey{}, -1, false
	}
	for offset := 0; offset < len(options); {
		option := lnetodhcp.OptNum(options[offset])
		switch option {
		case lnetodhcp.OptEnd:
			offset = len(options)
			continue
		case lnetodhcp.OptWordAligned:
			offset++
			continue
		}
		if offset+1 >= len(options) {
			return serverClientKey{}, -1, false
		}
		length := int(options[offset+1])
		next := offset + 2 + length
		if next > len(options) {
			return serverClientKey{}, -1, false
		}
		if option == lnetodhcp.OptClientIdentifier1 || option == lnetodhcp.OptClientIdentifier {
			if key.identifier || length == 0 || length > len(key.value) {
				return serverClientKey{}, -1, false
			}
			key = serverClientKey{length: uint8(length), identifier: true}
			copy(key.value[:], options[offset+2:next])
			if option == lnetodhcp.OptClientIdentifier1 {
				canonicalOffset = lnetodhcp.OptionsOffset + offset
			}
		}
		offset = next
	}
	if key.identifier {
		return key, canonicalOffset, true
	}
	key = serverClientKey{length: 6}
	copy(key.value[:], frame.CHAddrAs6()[:])
	return key, -1, true
}

func validUnicastMAC(mac [6]byte) bool {
	return mac != ([6]byte{}) && mac != broadcastMAC && mac[0]&1 == 0
}

func keyIndex(keys []serverClientKey, key serverClientKey) int {
	for i := range keys {
		if keys[i] == key {
			return i
		}
	}
	return -1
}

func (a *Adapter) CloseLocked() {
	if a == nil {
		return
	}
	if a.lease != nil {
		_ = a.lease.closeLocked()
	}
	clear(a.serverClients)
	a.serverClients = nil
	a.serverPending = 0
	a.clientEgressTurn = false
	a.server = lnetodhcp.Server{}
	a.clientPort.ReleaseLocked()
	a.serverPort.ReleaseLocked()
}
