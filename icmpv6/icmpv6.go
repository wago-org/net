// Package icmpv6 selectively registers bounded ICMPv6 echo and Neighbor
// Discovery. Router discovery, redirects, DAD, SLAAC, and raw packet access are
// not part of this module.
package icmpv6

import (
	"errors"
	"net/netip"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	icmpbackend "github.com/wago-org/net/internal/backend/lneto/icmpv6"
	icmpbinding "github.com/wago-org/net/internal/binding/icmpv6"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var ErrInvalidOption = errors.New("wagonet/icmpv6: invalid option")

type Config = icmpbackend.Config

func DefaultConfig() Config {
	return Config{MaxEchoes: 8, MaxPayloadBytes: 256, MaxNeighbors: 16, MaxResolutions: 8, MaxQueuedResponses: 8, MaxAttempts: 2, RetryServiceAttempts: 32}
}

type Option interface{ applyICMPv6(*registration) error }
type optionFunc func(*registration) error

func (option optionFunc) applyICMPv6(target *registration) error { return option(target) }

type registration struct {
	config             Config
	defaultAuthority   bool
	authorityAdditions policy.Config
}

func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error { target.config = config; return nil })
}

func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error { target.defaultAuthority = false; return nil })
}

// AllowDestinations grants echo, neighbor resolution, and explicit cache
// operations for each supplied IPv6 prefix. Automatic replies remain covered by
// the same exact source-prefix authority and caller denies always win.
func AllowDestinations(prefixes ...netip.Prefix) Option {
	if len(prefixes) == 0 {
		return optionFunc(func(*registration) error { return ErrInvalidOption })
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return optionFunc(func(*registration) error { return ErrInvalidOption })
		}
	}
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv6},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound, wagonet.PolicyOutbound}, Prefixes: append([]netip.Prefix(nil), prefixes...),
	}}})
}

// AllowAll grants every structurally valid unicast IPv6 address. Multicast,
// unspecified, loopback, mapped, raw-packet, router, DAD, and SLAAC operations
// remain unavailable, and all storage/work bounds remain finite.
func AllowAll() Option {
	return AllowDestinations(netip.MustParsePrefix("::/0"))
}

func defaultAuthority() policy.Config {
	return policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportICMPv6},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("::/0")},
	}}}
}

func (registration registration) authority() policy.Config {
	if !registration.defaultAuthority {
		return policy.Merge(registration.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(), registration.authorityAdditions)
}

func Register(network *wagonet.Network, options ...Option) error {
	registration := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyICMPv6(&registration); err != nil {
			return err
		}
	}
	if !icmpbackend.ValidConfig(registration.config, 1500, nil, nil, false) {
		return ErrInvalidOption
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common, ok := base.(*lnetocore.Namespace)
		if !ok {
			return nscore.Service{}, plugin.ErrInvalidBackend
		}
		adapter, err := icmpbackend.New(common, registration.config)
		if err != nil {
			return nscore.Service{}, err
		}
		return nscore.Service{Key: icmpns.ServiceKey, Value: adapter}, nil
	})
	module := icmpbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(registration.authority()))
	return network.RegisterModule(module)
}
