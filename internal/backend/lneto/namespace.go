// Package lnetobackend composes protocol adapters over one protocol-neutral
// lneto stack/link owner without using lneto's blocking or backoff wrappers.
package lnetobackend

import (
	"net"
	"net/netip"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xnet"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	dnsbackend "github.com/wago-org/net/internal/backend/lneto/dns"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	udpbackend "github.com/wago-org/net/internal/backend/lneto/udp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

var _ nscore.Namespace = (*Namespace)(nil)

const tcpCloseOrder = 20

// UDPConfig is the UDP adapter's finite socket and datagram storage contract.
type UDPConfig = udpbackend.Config

// TCPConfig is the TCP adapter's finite listener/stream storage contract.
type TCPConfig = tcpbackend.Config

// DNSConfig is the DNS adapter's finite query and retry storage contract.
type DNSConfig = dnsbackend.Config

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
	core               *lnetocore.Namespace
	stack              *xnet.StackAsync
	requiredFrameBytes int
	tcp                *tcpbackend.Adapter
	udp                *udpbackend.Adapter
	dns                *dnsbackend.Adapter
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
	udpAdapter, err := udpbackend.New(common, config.UDP)
	if err != nil {
		_ = common.Close()
		return nil, err
	}
	dnsAdapter, err := dnsbackend.New(common, config.DNS)
	if err != nil {
		_ = common.Close()
		return nil, err
	}
	n := &Namespace{
		core: common, stack: stack, requiredFrameBytes: int(config.MTU) + 14,
		tcp: tcpAdapter, udp: udpAdapter, dns: dnsAdapter,
	}
	participants := []lnetocore.Participant{{
		CloseOrder: tcpCloseOrder,
		Close:      tcpAdapter.CloseLocked,
	}}
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

func (n *Namespace) TryBindUDP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error) {
	if n == nil || n.udp == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return n.udp.TryBind(local)
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
	if n == nil || n.dns == nil {
		return nil, 0, nscore.Fail(nscore.FailureClosed, net.ErrClosed)
	}
	return n.dns.TryResolve(request)
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
		udpbackend.ValidConfig(config.UDP, int(config.MTU), config.Policy, config.Quotas, requireAuthority) == false ||
		dnsbackend.ValidConfig(config.DNS, int(config.MTU), config.Policy, config.Quotas, requireAuthority) == false {
		return false
	}
	return lnetocore.ValidateConfig(coreConfig(config)) == nil
}

func mapError(err error) error { return lnetocore.MapError(err) }
