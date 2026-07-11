// Package lnetobackend composes protocol adapters over one protocol-neutral
// lneto stack/link owner without using lneto's blocking or backoff wrappers.
package lnetobackend

import (
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xnet"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ nscore.Namespace = (*Namespace)(nil)

const (
	dnsServiceOrder = 10
	udpServiceOrder = 20
	dnsCloseOrder   = 10
	tcpCloseOrder   = 20
	udpCloseOrder   = 30
)

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

// TCPConfig is the TCP adapter's finite listener/stream storage contract.
type TCPConfig = tcpbackend.Config

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

// Namespace composes protocol state over exactly one shared core owner. The
// stack and frame-size aliases are temporary compatibility details for focused
// same-package tests; ownership remains in core.
type Namespace struct {
	core                   *lnetocore.Namespace
	stack                  *xnet.StackAsync
	requiredFrameBytes     int
	ipv4Address            netip.Addr
	hardwareAddress        [6]byte
	gatewayHardwareAddress [6]byte

	udpConfig UDPConfig
	policy    *policy.Policy
	quotas    *quota.Account
	udpByPort map[uint16]*udpSocket
	udpOrder  []*udpSocket
	udpCursor int

	tcp         *tcpbackend.Adapter
	dnsConfig   DNSConfig
	dnsQueries  []*dnsQuery
	dnsByPort   map[uint16]*dnsQuery
	dnsCursor   int
	nextDNSPort uint16
	nextDNSTxID uint16
}

// ValidateConfig reports whether config can construct a static IPv4 namespace
// without allocating backend state.
func ValidateConfig(config Config) error {
	if !validConfig(config, false) {
		return nscore.Fail(nscore.FailureInvalidArgument, packetlink.ErrInvalidConfig)
	}
	return nil
}

// New creates one shared static IPv4 core and installs the aggregate adapters
// in their historical service and teardown order.
func New(config Config) (*Namespace, error) {
	if !validConfig(config, true) {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, packetlink.ErrInvalidConfig)
	}
	common, err := lnetocore.New(coreConfig(config))
	if err != nil {
		return nil, err
	}
	common.Lock()
	stack := common.StackLocked()
	common.Unlock()
	tcpAdapter, err := tcpbackend.New(common, config.TCP)
	if err != nil {
		_ = common.Close()
		return nil, err
	}
	n := &Namespace{
		core:                   common,
		stack:                  stack,
		requiredFrameBytes:     int(config.MTU) + 14,
		ipv4Address:            config.IPv4Address,
		hardwareAddress:        config.HardwareAddress,
		gatewayHardwareAddress: config.GatewayHardwareAddress,
		udpConfig:              config.UDP,
		policy:                 config.Policy,
		quotas:                 config.Quotas,
		udpByPort:              make(map[uint16]*udpSocket, config.UDP.MaxSockets),
		udpOrder:               make([]*udpSocket, 0, config.UDP.MaxSockets),
		tcp:                    tcpAdapter,
		dnsConfig:              config.DNS,
		dnsQueries:             make([]*dnsQuery, 0, config.DNS.MaxQueries),
		dnsByPort:              make(map[uint16]*dnsQuery, config.DNS.MaxQueries),
		nextDNSPort:            firstEphemeralDNSPort,
		nextDNSTxID:            uint16(config.RandSeed) | 1,
	}
	participants := []lnetocore.Participant{
		{
			IngressOrder: dnsServiceOrder,
			Ingress:      n.ingressDNSLocked,
			EgressOrder:  dnsServiceOrder,
			HasEgress:    n.hasDNSWorkLocked,
			Egress:       n.egressDNSLocked,
			CloseOrder:   dnsCloseOrder,
			Close:        n.closeDNSLocked,
		},
		{
			CloseOrder: tcpCloseOrder,
			Close:      tcpAdapter.CloseLocked,
		},
		{
			IngressOrder: udpServiceOrder,
			Ingress:      n.ingressUDPLocked,
			EgressOrder:  udpServiceOrder,
			HasEgress:    n.hasUDPEgressLocked,
			Egress: func(dst []byte) (int, bool, error) {
				written, err := n.egressUDPLocked(dst)
				return written, written != 0, err
			},
			CloseOrder: udpCloseOrder,
			Close:      n.closeUDPLocked,
		},
	}
	for _, participant := range participants {
		if err := common.Install(participant); err != nil {
			_ = common.Close()
			return nil, err
		}
	}
	return n, nil
}

func coreConfig(config Config) lnetocore.Config {
	return lnetocore.Config{
		Hostname:               config.Hostname,
		RandSeed:               config.RandSeed,
		HardwareAddress:        config.HardwareAddress,
		GatewayHardwareAddress: config.GatewayHardwareAddress,
		IPv4Address:            config.IPv4Address,
		MTU:                    config.MTU,
		Link:                   config.Link,
		MaxActiveTCPPorts:      config.TCP.MaxListeners + config.TCP.MaxOutboundStreams,
		Policy:                 config.Policy,
		Quotas:                 config.Quotas,
	}
}

func (n *Namespace) Link() *packetlink.Link {
	if n == nil || n.core == nil {
		return nil
	}
	return n.core.Link()
}

func (n *Namespace) Readiness() nscore.Readiness {
	if n == nil || n.core == nil {
		return nscore.ReadyClosed
	}
	return n.core.Readiness()
}

func (n *Namespace) Close() error {
	if n == nil || n.core == nil {
		return nil
	}
	err := n.core.Close()
	n.core.Lock()
	n.stack = nil
	n.core.Unlock()
	return err
}

func (n *Namespace) closeDNSLocked() {
	for len(n.dnsQueries) > 0 {
		n.dnsQueries[len(n.dnsQueries)-1].closeLocked()
	}
	clear(n.dnsByPort)
	n.dnsByPort = nil
	n.dnsQueries = nil
	n.dnsCursor = 0
}

func (n *Namespace) closeUDPLocked() {
	for len(n.udpOrder) > 0 {
		n.udpOrder[len(n.udpOrder)-1].closeLocked()
	}
	clear(n.udpByPort)
	n.udpByPort = nil
	n.udpOrder = nil
	n.udpCursor = 0
}

func (n *Namespace) TryBindUDP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	return n.tryBindUDP(local)
}

func (n *Namespace) TryListenTCP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	if n == nil || n.tcp == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return n.tcp.TryListen(local)
}

func (n *Namespace) TryConnectTCP(remote nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	if n == nil || n.tcp == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return n.tcp.TryConnect(remote)
}

func (n *Namespace) TryResolve(request dnsns.Request) (nscore.Resource, nscore.Progress, error) {
	return n.tryResolve(request)
}

func (n *Namespace) TryService(budget nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	if n == nil || n.core == nil {
		return nscore.ServiceReport{}, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return n.core.TryService(budget)
}

func (n *Namespace) checkEndpoint(endpoint nscore.Endpoint) error {
	if n == nil || n.core == nil {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	n.core.Lock()
	defer n.core.Unlock()
	if n.core.ClosedLocked() {
		return nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	if !endpoint.Valid() {
		return nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidAddr)
	}
	return nil
}

func validConfig(config Config, requireAuthority bool) bool {
	if tcpbackend.ValidConfig(config.TCP, config.Policy, config.Quotas, requireAuthority) == false ||
		validUDPConfig(config.UDP, int(config.MTU), config.Policy, config.Quotas, requireAuthority) == false ||
		validDNSConfig(config.DNS, int(config.MTU), config.Policy, config.Quotas, requireAuthority) == false {
		return false
	}
	return lnetocore.ValidateConfig(coreConfig(config)) == nil
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

func mapError(err error) error { return lnetocore.MapError(err) }
