// Package lnetobackend adapts one lneto StackAsync to the backend-neutral
// namespace contract without using lneto's blocking or backoff wrappers.
package lnetobackend

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	lnetotcp "github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/xnet"
	"github.com/wago-org/net/internal/namespace"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ namespace.Namespace = (*Namespace)(nil)

// UDPConfig fixes all storage allocated for each nonblocking UDP socket. The
// lneto registration bound is finite and zero disables UDP.
type UDPConfig struct {
	MaxSockets        uint16
	ReceiveBytes      int
	TransmitBytes     int
	ReceiveDatagrams  int
	TransmitDatagrams int
	MaxPayloadBytes   int
}

// Config fixes all memory, authority, accounting, and identity used by one
// static IPv4 lneto namespace.
type Config struct {
	Hostname               string
	RandSeed               int64
	HardwareAddress        [6]byte
	GatewayHardwareAddress [6]byte
	IPv4Address            netip.Addr
	MTU                    uint16
	Link                   packetlink.Config
	UDP                    UDPConfig
	TCP                    TCPConfig
	DNS                    DNSConfig
	Policy                 *policy.Policy
	Quotas                 *quota.Account
}

// Namespace owns exactly one lneto stack and one deterministic packet link.
type Namespace struct {
	mu sync.Mutex

	stack                  *xnet.StackAsync
	link                   *packetlink.Link
	scratch                []byte
	requiredFrameBytes     int
	nextIngress            bool
	nextUDPEgress          bool
	nextDNSEgress          bool
	nextIPv4ID             uint16
	ipv4Address            netip.Addr
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte
	udpConfig              UDPConfig
	policy                 *policy.Policy
	quotas                 *quota.Account
	udpByPort              map[uint16]*udpSocket
	udpOrder               []*udpSocket
	udpCursor              int
	tcpConfig              TCPConfig
	tcpListeners           []*tcpListener
	tcpStreams             []*tcpStream
	tcpPorts               map[uint16]struct{}
	tcpMaintenanceEpoch    uint64
	nextTCPPort            uint16
	nextTCPISS             lnetotcp.Value
	dnsConfig              DNSConfig
	dnsQueries             []*dnsQuery
	dnsByPort              map[uint16]*dnsQuery
	dnsCursor              int
	nextDNSPort            uint16
	nextDNSTxID            uint16
	closed                 bool
}

// ValidateConfig reports whether config can construct a static IPv4 namespace
// without allocating backend state.
func ValidateConfig(config Config) error {
	if !validConfig(config, false) {
		return namespace.Fail(namespace.FailureInvalidArgument, packetlink.ErrInvalidConfig)
	}
	return nil
}

// New creates one static IPv4 namespace. Link frame storage must accommodate a
// complete Ethernet frame for the configured MTU.
func New(config Config) (*Namespace, error) {
	if !validConfig(config, true) {
		return nil, namespace.Fail(namespace.FailureInvalidArgument, packetlink.ErrInvalidConfig)
	}
	link, err := packetlink.New(config.Link)
	if err != nil {
		return nil, namespace.Fail(namespace.FailureInvalidArgument, err)
	}
	stack := new(xnet.StackAsync)
	stackConfig := xnet.StackConfig{
		HardwareAddress:   config.HardwareAddress,
		StaticAddress4:    config.IPv4Address.As4(),
		RandSeed:          config.RandSeed,
		Hostname:          config.Hostname,
		MTU:               config.MTU,
		MaxActiveTCPPorts: config.TCP.MaxListeners + config.TCP.MaxOutboundStreams,
	}
	if err := stack.Reset(stackConfig); err != nil {
		_ = link.Close()
		return nil, mapError(err)
	}
	stack.SetGatewayHardwareAddr(config.GatewayHardwareAddress)
	requiredFrameBytes := int(config.MTU) + 14
	return &Namespace{
		stack:                  stack,
		link:                   link,
		scratch:                make([]byte, config.Link.MaxFrameBytes),
		requiredFrameBytes:     requiredFrameBytes,
		nextIngress:            true,
		nextUDPEgress:          true,
		nextDNSEgress:          true,
		nextIPv4ID:             uint16(config.RandSeed),
		ipv4Address:            config.IPv4Address,
		hardwareAddress:        config.HardwareAddress,
		gatewayHardwareAddress: config.GatewayHardwareAddress,
		udpConfig:              config.UDP,
		policy:                 config.Policy,
		quotas:                 config.Quotas,
		udpByPort:              make(map[uint16]*udpSocket, config.UDP.MaxSockets),
		udpOrder:               make([]*udpSocket, 0, config.UDP.MaxSockets),
		tcpConfig:              config.TCP,
		tcpListeners:           make([]*tcpListener, 0, config.TCP.MaxListeners),
		tcpStreams:             make([]*tcpStream, 0, int(config.TCP.MaxOutboundStreams)+int(config.TCP.MaxListeners)*int(config.TCP.AcceptBacklog)),
		tcpPorts:               make(map[uint16]struct{}, int(config.TCP.MaxListeners)+int(config.TCP.MaxOutboundStreams)),
		nextTCPPort:            firstEphemeralTCPPort,
		nextTCPISS:             lnetotcp.Value(config.RandSeed),
		dnsConfig:              config.DNS,
		dnsQueries:             make([]*dnsQuery, 0, config.DNS.MaxQueries),
		dnsByPort:              make(map[uint16]*dnsQuery, config.DNS.MaxQueries),
		nextDNSPort:            firstEphemeralDNSPort,
		nextDNSTxID:            uint16(config.RandSeed) | 1,
	}, nil
}

// Link returns the namespace-owned packet link. It remains safe to inspect
// after namespace close, but all link operations then return packetlink.ErrClosed.
func (n *Namespace) Link() *packetlink.Link {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.link
}

// Readiness returns a level-triggered link snapshot without servicing packets.
func (n *Namespace) Readiness() namespace.Readiness {
	if n == nil {
		return namespace.ReadyClosed
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.link == nil {
		return namespace.ReadyClosed
	}
	snapshot := n.link.Snapshot()
	if snapshot.Closed {
		return namespace.ReadyClosed
	}
	var ready namespace.Readiness
	if snapshot.EgressFrames > 0 {
		ready |= namespace.ReadyReadable
	}
	if snapshot.IngressFrames < snapshot.IngressCapacity {
		ready |= namespace.ReadyWritable
	}
	return ready
}

// Close immediately detaches the stack, clears service scratch memory, and
// closes the packet link. It never waits for network progress and is idempotent.
func (n *Namespace) Close() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	for len(n.dnsQueries) > 0 {
		n.dnsQueries[len(n.dnsQueries)-1].closeLocked()
	}
	clear(n.dnsByPort)
	n.dnsByPort = nil
	n.dnsQueries = nil
	n.dnsCursor = 0
	for len(n.tcpListeners) > 0 {
		n.tcpListeners[len(n.tcpListeners)-1].closeLocked()
	}
	for len(n.tcpStreams) > 0 {
		n.tcpStreams[len(n.tcpStreams)-1].closeLocked()
	}
	clear(n.tcpPorts)
	n.tcpPorts = nil
	n.tcpListeners = nil
	n.tcpStreams = nil
	for len(n.udpOrder) > 0 {
		n.udpOrder[len(n.udpOrder)-1].closeLocked()
	}
	clear(n.udpByPort)
	n.udpByPort = nil
	n.udpOrder = nil
	n.udpCursor = 0
	n.stack = nil
	clear(n.scratch)
	n.scratch = nil
	if n.link != nil {
		return n.link.Close()
	}
	return nil
}

func (n *Namespace) TryBindUDP(local namespace.Endpoint) (namespace.UDPSocket, namespace.Progress, error) {
	return n.tryBindUDP(local)
}

func (n *Namespace) TryListenTCP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.tryListenTCP(local)
}

func (n *Namespace) TryConnectTCP(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.tryConnectTCP(remote)
}

func (n *Namespace) TryResolve(request namespace.DNSRequest) (namespace.DNSQuery, namespace.Progress, error) {
	return n.tryResolve(request)
}

// TryService performs bounded, nonblocking packet transfer plus TCP and DNS
// maintenance. Each direction probe consumes the private attempt bound.
// Completed packet, accepted-slot reclamation, or DNS state-transition work
// increments Operations; only frames increment Packets and Bytes. Empty probes
// remain unreported.
func (n *Namespace) TryService(budget namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	if n == nil {
		return namespace.ServiceReport{}, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.stack == nil || n.link == nil {
		return namespace.ServiceReport{}, 0, namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if !budget.Valid() {
		return namespace.ServiceReport{}, 0, namespace.Fail(namespace.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}

	var report namespace.ServiceReport
	var attempts uint32
	for report.Packets < budget.Packets && attempts < budget.Operations && report.Bytes <= budget.Bytes {
		remainingBytes := budget.Bytes - report.Bytes
		ingress := n.nextIngress
		n.nextIngress = !n.nextIngress
		attempts++
		var worked, packet bool
		var frameBytes int
		var err error
		if ingress {
			worked, packet, frameBytes, err = n.tryIngress(remainingBytes)
		} else {
			worked, packet, frameBytes, err = n.tryEgress(remainingBytes)
		}
		if worked {
			report.Operations++
			if packet {
				report.Packets++
				report.Bytes += uint32(frameBytes)
			}
		}
		if err != nil {
			progress := namespace.ProgressWouldBlock
			if report != (namespace.ServiceReport{}) {
				progress = namespace.ProgressDone
			}
			return report, progress, err
		}
	}
	if report == (namespace.ServiceReport{}) {
		return report, namespace.ProgressWouldBlock, nil
	}
	return report, namespace.ProgressDone, nil
}

func (n *Namespace) tryIngress(remainingBytes uint32) (bool, bool, int, error) {
	result, err := n.link.TryDequeueWithin(packetlink.Ingress, n.scratch, int(remainingBytes))
	if errors.Is(err, packetlink.ErrFrameBudget) {
		return false, false, 0, nil
	}
	if err != nil {
		return false, false, 0, mapError(err)
	}
	if !result.Ready {
		return false, false, 0, nil
	}
	frame := n.scratch[:result.FrameBytes]
	handled, protocolErr := n.ingressDNSLocked(frame)
	if !handled {
		handled, protocolErr = n.ingressUDPLocked(frame)
	}
	if handled {
		err = protocolErr
	} else {
		err = n.stack.IngressEthernet(frame)
	}
	clear(frame)
	if errors.Is(err, lneto.ErrPacketDrop) {
		err = nil
	}
	if err != nil {
		return true, true, result.FrameBytes, mapError(err)
	}
	return true, true, result.FrameBytes, nil
}

func (n *Namespace) tryEgress(remainingBytes uint32) (bool, bool, int, error) {
	if remainingBytes < uint32(n.requiredFrameBytes) {
		return false, false, 0, nil
	}
	var dnsWorked, tcpWorked bool
	result, err := n.link.TryFill(packetlink.Egress, func(dst []byte) (int, error) {
		hasDNS := n.hasDNSWorkLocked()
		if hasDNS && n.nextDNSEgress {
			n.nextDNSEgress = false
			written, worked, dnsErr := n.egressDNSLocked(dst[:n.requiredFrameBytes])
			dnsWorked = worked
			if written != 0 || worked || dnsErr != nil {
				return written, dnsErr
			}
		}

		hasUDP := n.hasUDPEgressLocked()
		if hasUDP && n.nextUDPEgress {
			n.nextUDPEgress = false
			written, udpErr := n.egressUDPLocked(dst[:n.requiredFrameBytes])
			if written != 0 || udpErr != nil {
				if hasDNS {
					n.nextDNSEgress = true
				}
				return written, udpErr
			}
		}
		maintenanceEpoch := n.tcpMaintenanceEpoch
		written, stackErr := n.stack.EgressEthernet(dst[:n.requiredFrameBytes])
		tcpWorked = n.tcpMaintenanceEpoch != maintenanceEpoch
		if written != 0 || stackErr != nil {
			if hasUDP {
				n.nextUDPEgress = true
			}
			if hasDNS {
				n.nextDNSEgress = true
			}
			return written, stackErr
		}
		if hasUDP {
			n.nextUDPEgress = true
			written, udpErr := n.egressUDPLocked(dst[:n.requiredFrameBytes])
			if written != 0 || udpErr != nil {
				if hasDNS {
					n.nextDNSEgress = true
				}
				return written, udpErr
			}
		}
		if hasDNS {
			n.nextDNSEgress = true
			written, worked, dnsErr := n.egressDNSLocked(dst[:n.requiredFrameBytes])
			dnsWorked = worked
			return written, dnsErr
		}
		return 0, nil
	})
	if errors.Is(err, packetlink.ErrQueueFull) {
		return false, false, 0, nil
	}
	if err != nil {
		return dnsWorked || tcpWorked, false, 0, mapError(err)
	}
	if !result.Ready {
		return dnsWorked || tcpWorked, false, 0, nil
	}
	return true, true, result.FrameBytes, nil
}

func (n *Namespace) checkEndpoint(endpoint namespace.Endpoint) error {
	if n == nil {
		return namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return namespace.Fail(namespace.FailureClosed, net.ErrClosed)
	}
	if !endpoint.Valid() {
		return namespace.Fail(namespace.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	return nil
}

func validConfig(config Config, requireAuthority bool) bool {
	if config.Hostname == "" || config.RandSeed == 0 || !config.IPv4Address.Is4() || config.IPv4Address.Is4In6() || config.IPv4Address.Zone() != "" {
		return false
	}
	if config.MTU < ethernet.MinimumMTU || config.MTU > ethernet.MaxMTU {
		return false
	}
	requiredFrameBytes := int(config.MTU) + 14
	if config.Link.MaxFrameBytes < requiredFrameBytes || config.Link.IngressFrames <= 0 || config.Link.EgressFrames <= 0 {
		return false
	}
	return validUDPConfig(config.UDP, int(config.MTU), config.Policy, config.Quotas, requireAuthority) &&
		validTCPConfig(config.TCP, config.Policy, config.Quotas, requireAuthority) &&
		validDNSConfig(config.DNS, int(config.MTU), config.Policy, config.Quotas, requireAuthority)
}

func validTCPConfig(config TCPConfig, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxListeners == 0 && config.MaxOutboundStreams == 0 {
		return config == (TCPConfig{})
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

func validUDPConfig(config UDPConfig, mtu int, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config.MaxSockets == 0 {
		return config == (UDPConfig{})
	}
	if (requireAuthority && (compiled == nil || account == nil)) || config.ReceiveDatagrams <= 0 || config.TransmitDatagrams <= 0 ||
		config.MaxPayloadBytes < 0 || config.MaxPayloadBytes > mtu-28 || config.MaxPayloadBytes > int(^uint16(0)) {
		return false
	}
	if config.MaxPayloadBytes != 0 && (config.ReceiveDatagrams > int(^uint(0)>>1)/config.MaxPayloadBytes || config.TransmitDatagrams > int(^uint(0)>>1)/config.MaxPayloadBytes) {
		return false
	}
	return config.ReceiveBytes >= config.ReceiveDatagrams*config.MaxPayloadBytes &&
		config.TransmitBytes >= config.TransmitDatagrams*config.MaxPayloadBytes
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	failure := namespace.FailureIO
	switch {
	case errors.Is(err, net.ErrClosed), errors.Is(err, packetlink.ErrClosed), errors.Is(err, quota.ErrClosed):
		failure = namespace.FailureClosed
	case errors.Is(err, context.Canceled):
		failure = namespace.FailureCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		failure = namespace.FailureTimedOut
	case errors.Is(err, lneto.ErrUnsupported):
		failure = namespace.FailureNotSupported
	case errors.Is(err, lneto.ErrExhausted), errors.Is(err, lneto.ErrBufferFull), errors.Is(err, packetlink.ErrQueueFull), errors.Is(err, quota.ErrLimit):
		failure = namespace.FailureResourceLimit
	case errors.Is(err, lneto.ErrAlreadyRegistered):
		failure = namespace.FailureAddressInUse
	case errors.Is(err, lneto.ErrBadState):
		failure = namespace.FailureInvalidState
	case errors.Is(err, lneto.ErrShortBuffer), errors.Is(err, io.ErrShortBuffer), errors.Is(err, packetlink.ErrFrameTooLarge):
		failure = namespace.FailureMessageTooLarge
	case errors.Is(err, lneto.ErrInvalidAddr), errors.Is(err, lneto.ErrInvalidConfig),
		errors.Is(err, lneto.ErrInvalidField), errors.Is(err, lneto.ErrInvalidLengthField),
		errors.Is(err, lneto.ErrMismatchLen), errors.Is(err, lneto.ErrTruncatedFrame),
		errors.Is(err, lneto.ErrZeroSource), errors.Is(err, lneto.ErrZeroDestination),
		errors.Is(err, lneto.ErrBadCRC), errors.Is(err, packetlink.ErrInvalidQueue),
		errors.Is(err, packetlink.ErrInvalidFill), errors.Is(err, packetlink.ErrFrameBudget), errors.Is(err, quota.ErrInvalidUnits):
		failure = namespace.FailureInvalidArgument
	case errors.Is(err, lneto.ErrPacketDrop), errors.Is(err, lneto.ErrMismatch):
		failure = namespace.FailureTemporary
	}
	return namespace.Fail(failure, err)
}
