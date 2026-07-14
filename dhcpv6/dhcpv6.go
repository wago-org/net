// Package dhcpv6 selectively registers the bounded initial DHCPv6 client
// acquisition subset implemented by the pinned lneto revision.
package dhcpv6

import (
	"errors"
	"net/netip"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	dhcpbackend "github.com/wago-org/net/internal/backend/lneto/dhcpv6"
	dhcpbinding "github.com/wago-org/net/internal/binding/dhcpv6"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var (
	ErrInvalidOption = errors.New("wagonet/dhcpv6: invalid option")
	ErrInvalidConfig = errors.New("wagonet/dhcpv6: invalid finite configuration")
)

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

func DefaultConfig() Config {
	return Config{MaxLeases: 1, MaxPacketBytes: 1024, MaxAttempts: 2, ResponseServiceAttempts: 32, MaxServerDUIDBytes: dhcpns.MaxServerDUIDBytes, MaxDNSServers: dhcpns.MaxDNSServers, MaxDomainSearch: dhcpns.MaxDomainSearch, MaxNTPServers: dhcpns.MaxNTPServers, MaxNTPMulticastServers: dhcpns.MaxNTPMulticastServers, MaxNTPServerNames: dhcpns.MaxNTPServerNames, MaxDelegatedPrefixes: dhcpns.MaxDelegatedPrefixes}
}

type Option interface{ applyDHCPv6(*registration) error }
type optionFunc func(*registration) error

func (f optionFunc) applyDHCPv6(r *registration) error { return f(r) }

type registration struct {
	config             Config
	defaultAuthority   bool
	authorityAdditions policy.Config
}

func WithConfig(config Config) Option {
	return optionFunc(func(r *registration) error { r.config = config; return nil })
}
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(r *registration) error {
		r.authorityAdditions = policy.Merge(r.authorityAdditions, config)
		return nil
	})
}
func WithoutDefaultAuthority() Option {
	return optionFunc(func(r *registration) error { r.defaultAuthority = false; return nil })
}

func Register(network *wagonet.Network, options ...Option) error {
	r := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyDHCPv6(&r); err != nil {
			return err
		}
	}
	backendConfig := r.config.backend()
	if !dhcpbackend.ValidConfig(backendConfig, 65535, nil, nil, false) {
		return ErrInvalidConfig
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common, ok := base.(*lnetocore.Namespace)
		if !ok {
			return nscore.Service{}, plugin.ErrInvalidBackend
		}
		adapter, err := dhcpbackend.New(common, backendConfig)
		if err != nil {
			return nscore.Service{}, err
		}
		return nscore.Service{Key: dhcpns.ServiceKey, Value: adapter}, nil
	})
	return network.RegisterModule(dhcpbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(r.authority())))
}

func (c Config) backend() dhcpbackend.Config {
	return dhcpbackend.Config{MaxLeases: c.MaxLeases, MaxPacketBytes: c.MaxPacketBytes, MaxAttempts: c.MaxAttempts, ResponseServiceAttempts: c.ResponseServiceAttempts, MaxServerDUIDBytes: c.MaxServerDUIDBytes, MaxDNSServers: c.MaxDNSServers, MaxDomainSearch: c.MaxDomainSearch, MaxNTPServers: c.MaxNTPServers, MaxNTPMulticastServers: c.MaxNTPMulticastServers, MaxNTPServerNames: c.MaxNTPServerNames, MaxDelegatedPrefixes: c.MaxDelegatedPrefixes}
}
func (r registration) authority() policy.Config {
	if !r.defaultAuthority || r.config == (Config{}) {
		return policy.Merge(r.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(), r.authorityAdditions)
}
func defaultAuthority() policy.Config {
	all := netip.MustParsePrefix("::/0")
	multicast := netip.PrefixFrom(netip.MustParseAddr("ff02::1:2"), 128)
	return policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{all}, Ports: []policy.PortRange{{First: dhcpns.ClientPort, Last: dhcpns.ClientPort}}},
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{all}, Ports: []policy.PortRange{{First: dhcpns.ServerPort, Last: dhcpns.ServerPort}}},
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{multicast}, Ports: []policy.PortRange{{First: dhcpns.ServerPort, Last: dhcpns.ServerPort}}},
	}, MulticastTransports: []policy.Transport{policy.TransportDHCPv6}, PrivilegedBindTransports: []policy.Transport{policy.TransportDHCPv6}}
}
