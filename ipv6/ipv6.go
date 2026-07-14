// Package ipv6 selectively enables one bounded static IPv6 namespace and the
// pinned immediate TCP transport family without exposing raw IPv6 packets.
package ipv6

import (
	"errors"
	"net/netip"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	ipv6backend "github.com/wago-org/net/internal/backend/lneto/ipv6"
	ipv6binding "github.com/wago-org/net/internal/binding/ipv6"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var (
	ErrInvalidOption = errors.New("wagonet/ipv6: invalid option")
	ErrInvalidConfig = errors.New("wagonet/ipv6: invalid static IPv6 configuration")
)

// Config fixes the single static IPv6 identity, prefix, and numeric interface
// scope. The zero value leaves the independently registered module truthfully
// disabled. Link-local unicast requires a nonzero ScopeID; global addresses
// require zero. The pinned path supports no extension headers or flow labels.
type Config struct {
	Address    netip.Addr
	PrefixBits uint8
	ScopeID    uint32
}

// DefaultConfig returns the finite static single-interface configuration.
func DefaultConfig(address netip.Addr, prefixBits uint8, scopeID uint32) Config {
	return Config{Address: address, PrefixBits: prefixBits, ScopeID: scopeID}
}

type Option interface{ applyIPv6(*registration) error }
type optionFunc func(*registration) error

func (f optionFunc) applyIPv6(target *registration) error { return f(target) }

type registration struct {
	config             Config
	defaultAuthority   bool
	authorityAdditions policy.Config
}

func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		return nil
	})
}

// WithPolicy adds advanced protocol-local configured-identity authority.
// Caller and option denies always win over the exact default grant.
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error {
		target.defaultAuthority = false
		return nil
	})
}

// Register selects only net.ipv6, wago_net_ipv6, and the static IPv6 backend
// contribution. TCP remains separately selectable and capability-gated.
func Register(network *wagonet.Network, options ...Option) error {
	registration := registration{defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyIPv6(&registration); err != nil {
			return err
		}
	}
	if registration.config != (Config{}) && !validConfig(registration.config) {
		return ErrInvalidConfig
	}
	var descriptor plugin.Module
	if registration.config == (Config{}) {
		descriptor = ipv6binding.Descriptor()
	} else {
		backendConfig := ipv6backend.Config(registration.config)
		backend := plugin.NewBackend(plugin.BackendLnetoV1,
			func(target any) error {
				common, ok := target.(*lnetocore.Config)
				if !ok || common.IPv6Address.IsValid() || common.IPv6PrefixBits != 0 || common.IPv6ScopeID != 0 {
					return plugin.ErrInvalidBackend
				}
				common.IPv6Address = registration.config.Address
				common.IPv6PrefixBits = registration.config.PrefixBits
				common.IPv6ScopeID = registration.config.ScopeID
				return nil
			},
			func(base any) (nscore.Service, error) {
				common, ok := base.(*lnetocore.Namespace)
				if !ok {
					return nscore.Service{}, plugin.ErrInvalidBackend
				}
				adapter, err := ipv6backend.New(common, backendConfig)
				if err != nil {
					return nscore.Service{}, err
				}
				return nscore.Service{Key: ipv6ns.ServiceKey, Value: adapter}, nil
			},
		)
		descriptor = ipv6binding.Descriptor(backend)
	}
	return network.RegisterModule(descriptor.WithAuthority(plugin.NewAuthority(registration.authority())))
}

func validConfig(config Config) bool {
	configuration := ipv6ns.Configuration{
		Address: config.Address, PrefixBits: config.PrefixBits, ScopeID: config.ScopeID, MTU: 1280,
		Transports: ipv6ns.TransportTCPConnect | ipv6ns.TransportTCPListen,
	}
	return configuration.Valid()
}

func (r registration) authority() policy.Config {
	if !r.defaultAuthority || r.config == (Config{}) {
		return policy.Merge(r.authorityAdditions)
	}
	defaults := policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(r.config.Address, 128)},
	}}}
	return policy.Merge(defaults, r.authorityAdditions)
}
