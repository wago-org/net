// Package icmpv4 selectively registers Wago's checked bounded ICMPv4 echo
// capability, imports, instance operations, namespace facet, and lneto adapter.
package icmpv4

import (
	"errors"
	"net/netip"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	icmpbackend "github.com/wago-org/net/internal/backend/lneto/icmpv4"
	icmpbinding "github.com/wago-org/net/internal/binding/icmpv4"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv4"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var ErrInvalidOption = errors.New("wagonet/icmpv4: invalid option")

// Config fixes concurrent echo resources, copied payload bytes, transmission
// attempts, and deterministic service-attempt retry bounds. The zero value
// disables backend ICMPv4 resources when supplied explicitly through WithConfig.
type Config = icmpbackend.Config

// DefaultConfig returns finite client-only echo storage and retry work.
func DefaultConfig() Config {
	return Config{MaxEchoes: 8, MaxPayloadBytes: 256, MaxAttempts: 2, RetryServiceAttempts: 32}
}

// Option configures ICMPv4-local authority and finite resources.
type Option interface {
	applyICMPv4(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyICMPv4(config *registration) error { return option(config) }

type registration struct {
	config             Config
	defaultAuthority   bool
	authorityAdditions policy.Config
}

// WithConfig supplies the advanced exact ICMPv4 resource and work bounds.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		return nil
	})
}

// WithPolicy adds advanced raw ICMPv4 address policy rules. Caller and option
// deny rules always win after shared composition.
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

// WithoutDefaultAuthority suppresses the ordinary outbound IPv4 echo grant.
func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error {
		target.defaultAuthority = false
		return nil
	})
}

// AllowDestinations grants echo requests to each supplied IPv4 prefix. Empty
// input is rejected; use AllowAll for every structurally valid address class.
func AllowDestinations(prefixes ...netip.Prefix) Option {
	if len(prefixes) == 0 {
		return optionFunc(func(*registration) error { return ErrInvalidOption })
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
			return optionFunc(func(*registration) error { return ErrInvalidOption })
		}
	}
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: append([]netip.Prefix(nil), prefixes...),
	}}})
}

// AllowLoopback grants loopback policy authority. The physical link-backed
// adapter still rejects loopback as a non-wire destination.
func AllowLoopback() Option {
	return WithPolicy(wagonet.PolicyConfig{LoopbackTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4}})
}

// AllowMulticast permits otherwise granted multicast echo destinations.
func AllowMulticast() Option {
	return WithPolicy(wagonet.PolicyConfig{MulticastTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4}})
}

// AllowBroadcast permits otherwise granted limited-broadcast echo destinations.
func AllowBroadcast() Option {
	return WithPolicy(wagonet.PolicyConfig{BroadcastTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4}})
}

// AllowAll conspicuously grants policy authority for every structurally valid
// IPv4 destination class. The physical link-backed adapter still rejects
// loopback; payloads, resources, retries, service, and quotas remain finite.
func AllowAll() Option {
	return WithPolicy(wagonet.PolicyConfig{
		Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound},
		}},
		LoopbackTransports:  []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4},
		MulticastTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4},
		BroadcastTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportICMPv4},
	})
}

func defaultAuthority() policy.Config {
	return policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportICMPv4},
		Directions: []policy.Direction{policy.DirectionOutbound},
	}}}
}

func (r registration) authority() policy.Config {
	if !r.defaultAuthority {
		return policy.Merge(r.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(), r.authorityAdditions)
}

// Register selects only the ICMPv4 capability, wago_net_icmpv4 import table,
// and ICMPv4 backend contribution on network.
func Register(network *wagonet.Network, options ...Option) error {
	config := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyICMPv4(&config); err != nil {
			return err
		}
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil,
		func(base any) (nscore.Service, error) {
			common, ok := base.(*lnetocore.Namespace)
			if !ok {
				return nscore.Service{}, plugin.ErrInvalidBackend
			}
			adapter, err := icmpbackend.New(common, config.config)
			if err != nil {
				return nscore.Service{}, err
			}
			return nscore.Service{Key: icmpns.ServiceKey, Value: adapter}, nil
		},
	)
	module := icmpbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(config.authority()))
	return network.RegisterModule(module)
}
