// Package ipv6 installs the bounded static IPv6 contribution on one shared
// lneto namespace. Raw IPv6 frames remain internal infrastructure.
package ipv6

import (
	"errors"
	"net/netip"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

const (
	ingressOrder = -100
	closeOrder   = 5
)

var errPolicyDenied = errors.New("net: IPv6 namespace policy denied configured identity")

// Config is the finite backend contribution configured before shared stack
// construction. The zero value disables IPv6 truthfully.
type Config struct {
	Address    netip.Addr
	PrefixBits uint8
	ScopeID    uint32
}

// Adapter exposes immutable checked configuration and owns its exact quota
// charge plus strict base-header ingress validation.
type Adapter struct {
	core          *lnetocore.Namespace
	configuration ipv6ns.Configuration
	retained      quota.Charge
	closed        bool
}

var _ ipv6ns.Namespace = (*Adapter)(nil)

// ValidConfig validates the selected static single-interface contribution.
func ValidConfig(config Config, mtu uint16, compiled *policy.Policy, account *quota.Account, requireAuthority bool) bool {
	if config == (Config{}) {
		return true
	}
	configuration := configurationFrom(config, mtu)
	return configuration.Valid() && (!requireAuthority || (compiled != nil && account != nil && compiled.CheckAddress(policy.OperationIPv6Enable, config.Address)))
}

// New attaches the already configured core IPv6 stack to its selective service.
func New(common *lnetocore.Namespace, config Config) (*Adapter, error) {
	if common == nil || config == (Config{}) {
		return nil, nscore.Fail(nscore.FailureInvalidArgument, lneto.ErrInvalidConfig)
	}
	common.Lock()
	configuration := configurationFrom(config, uint16(common.RequiredFrameBytesLocked()-14))
	if common.ClosedLocked() || !common.IPv6EnabledLocked() || common.IPv6AddressLocked() != config.Address ||
		common.IPv6PrefixBitsLocked() != config.PrefixBits || common.IPv6ScopeIDLocked() != config.ScopeID ||
		!configuration.Valid() || !common.PolicyLocked().CheckAddress(policy.OperationIPv6Enable, config.Address) {
		common.Unlock()
		return nil, nscore.Fail(nscore.FailureAccessDenied, errPolicyDenied)
	}
	adapter := &Adapter{core: common, configuration: configuration}
	if err := common.QuotasLocked().AcquireResource(&adapter.retained, quota.ResourceIPv6, 1); err != nil {
		common.Unlock()
		return nil, lnetocore.MapError(err)
	}
	common.Unlock()
	if err := common.Install(lnetocore.Participant{
		IngressOrder: ingressOrder,
		Ingress:      adapter.ingressLocked,
		CloseOrder:   closeOrder,
		Close:        adapter.CloseLocked,
	}); err != nil {
		adapter.retained.Release()
		return nil, err
	}
	return adapter, nil
}

func configurationFrom(config Config, mtu uint16) ipv6ns.Configuration {
	return ipv6ns.Configuration{
		Address: config.Address, PrefixBits: config.PrefixBits, ScopeID: config.ScopeID, MTU: mtu,
		MaxExtensionHeaders: 0,
		Transports:          ipv6ns.TransportTCPConnect | ipv6ns.TransportTCPListen,
	}
}

// Configuration returns the immutable selected contribution.
func (a *Adapter) Configuration() ipv6ns.Configuration {
	if a == nil || a.core == nil {
		return ipv6ns.Configuration{}
	}
	a.core.Lock()
	defer a.core.Unlock()
	if a.closed || a.core.ClosedLocked() {
		return ipv6ns.Configuration{}
	}
	return a.configuration
}

// CloseLocked releases exact namespace quota during shared deterministic close.
func (a *Adapter) CloseLocked() {
	if a == nil || a.closed {
		return
	}
	a.closed = true
	a.retained.Release()
	a.retained.ResetReleased()
	a.configuration = ipv6ns.Configuration{}
}

// ingressLocked drops malformed IPv6 and every extension-header packet before
// the pinned direct-next-header demultiplexer sees it. Valid base-header packets
// continue to the selected transport/ICMP participants.
func (a *Adapter) ingressLocked(frame []byte) (bool, error) {
	relevant, valid := ValidateIngressFrame(frame)
	return relevant && !valid, nil
}

// ValidateIngressFrame reports whether frame is IPv6 and whether its complete
// base-header shape is accepted. The finite extension-header scan bound is zero.
func ValidateIngressFrame(frame []byte) (relevant, valid bool) {
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || ethernetFrame.EtherTypeOrSize() != ethernet.TypeIPv6 {
		return false, err == nil
	}
	relevant = true
	ipFrame, err := lnetoipv6.NewFrame(ethernetFrame.Payload())
	if err != nil {
		return true, false
	}
	version, _, _ := ipFrame.VersionTrafficAndFlow()
	if version != 6 || int(ipFrame.PayloadLength())+40 > len(ethernetFrame.Payload()) || isExtensionHeader(ipFrame.NextHeader()) {
		return true, false
	}
	source, destination := netip.AddrFrom16(*ipFrame.SourceAddr()), netip.AddrFrom16(*ipFrame.DestinationAddr())
	if source.Is4In6() || destination.Is4In6() || source.IsUnspecified() || source.IsLoopback() || source.IsMulticast() || destination.IsUnspecified() || destination.IsLoopback() {
		return true, false
	}
	return true, true
}

func isExtensionHeader(proto lneto.IPProto) bool {
	switch uint8(proto) {
	case 0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254:
		return true
	default:
		return false
	}
}
