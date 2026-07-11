// Package tcp selectively registers Wago's checked nonblocking TCP guest
// capability, imports, instance operations, namespace facet, and lneto adapter.
package tcp

import (
	"errors"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	tcpbinding "github.com/wago-org/net/internal/binding/tcp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var ErrInvalidOption = errors.New("wagonet/tcp: invalid option")

// Config fixes TCP-local listeners, outbound streams, buffers, packet tracking,
// and backlog storage. The zero value disables backend TCP resources when
// supplied explicitly through WithConfig.
type Config = tcpbackend.Config

// DefaultConfig returns finite outbound-client storage with no listener pool.
func DefaultConfig() Config {
	return Config{
		MaxOutboundStreams: 8,
		ReceiveBytes:       16 << 10,
		TransmitBytes:      16 << 10,
		TransmitPackets:    16,
	}
}

// Option configures TCP-local authority and finite resources.
type Option interface {
	applyTCP(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyTCP(config *registration) error { return option(config) }

type registration struct {
	config             Config
	defaultAuthority   bool
	authorityAdditions policy.Config
}

// WithConfig supplies the advanced exact TCP storage configuration.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		return nil
	})
}

// WithPolicy adds advanced raw TCP policy rules and special-class grants.
// Caller and option deny rules always win after shared composition.
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

// WithoutDefaultAuthority suppresses the ordinary outbound-client grant. It is
// intended for compatibility and advanced callers supplying the complete raw
// network policy themselves.
func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error {
		target.defaultAuthority = false
		return nil
	})
}

// AllowListeners explicitly grants TCP listen authority for the supplied local
// port ranges. An empty range list means every nonprivileged local port. Finite
// listener storage must still be supplied with WithConfig.
func AllowListeners(ports ...wagonet.PolicyPortRange) Option {
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportTCP},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound}, Ports: append([]wagonet.PolicyPortRange(nil), ports...),
	}}})
}

// AllowWildcardBind permits explicitly granted listeners to use an unspecified
// local address. It does not add listener storage or an inbound allow rule.
func AllowWildcardBind() Option {
	return WithPolicy(wagonet.PolicyConfig{AllowWildcardBind: true})
}

// AllowPrivilegedBind permits explicitly granted listeners on ports 1..1023.
func AllowPrivilegedBind() Option {
	return WithPolicy(wagonet.PolicyConfig{AllowPrivilegedBind: true})
}

// AllowLoopback permits otherwise granted loopback connections and listeners.
func AllowLoopback() Option {
	return WithPolicy(wagonet.PolicyConfig{AllowLoopback: true})
}

// AllowAll conspicuously grants TCP authority in both directions and every
// special endpoint class. Storage and quotas remain finite and independently
// configurable.
func AllowAll() Option {
	return WithPolicy(wagonet.PolicyConfig{
		Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportTCP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound, wagonet.PolicyOutbound},
		}},
		AllowWildcardBind: true, AllowLoopback: true, AllowMulticast: true,
		AllowBroadcast: true, AllowPrivilegedBind: true,
	})
}

func defaultAuthority() policy.Config {
	return policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP},
		Directions: []policy.Direction{policy.DirectionOutbound},
	}}}
}

func (r registration) authority() policy.Config {
	if !r.defaultAuthority {
		return policy.Merge(r.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(), r.authorityAdditions)
}

// Register selects only the TCP capability, wago_net_tcp import table, and TCP
// backend contribution on network. Shared wago_net.abi_version registration is
// added by the root when the first protocol is selected.
func Register(network *wagonet.Network, options ...Option) error {
	config := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyTCP(&config); err != nil {
			return err
		}
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1,
		func(target any) error {
			common, ok := target.(*lnetocore.Config)
			if !ok {
				return plugin.ErrInvalidBackend
			}
			ports := uint32(config.config.MaxListeners) + uint32(config.config.MaxOutboundStreams)
			if ports > uint32(^uint16(0))-uint32(common.MaxActiveTCPPorts) {
				return plugin.ErrInvalidBackend
			}
			common.MaxActiveTCPPorts += uint16(ports)
			return nil
		},
		func(base any) (nscore.Service, error) {
			common, ok := base.(*lnetocore.Namespace)
			if !ok {
				return nscore.Service{}, plugin.ErrInvalidBackend
			}
			adapter, err := tcpbackend.New(common, config.config)
			if err != nil {
				return nscore.Service{}, err
			}
			return nscore.Service{Key: tcpns.ServiceKey, Value: adapter}, nil
		},
	)
	module := tcpbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(config.authority()))
	return network.RegisterModule(module)
}
