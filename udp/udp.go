// Package udp selectively registers Wago's checked nonblocking UDP guest
// capability, imports, instance operations, namespace facet, and lneto adapter.
package udp

import (
	"errors"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	udpbackend "github.com/wago-org/net/internal/backend/lneto/udp"
	udpbinding "github.com/wago-org/net/internal/binding/udp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var ErrInvalidOption = errors.New("wagonet/udp: invalid option")

// Config fixes UDP-local socket, queue, payload, and retained-byte bounds. The
// zero value disables backend UDP resources when supplied through WithConfig.
type Config = udpbackend.Config

// DefaultConfig returns finite client datagram storage.
func DefaultConfig() Config {
	return Config{
		MaxSockets: 8, ReceiveBytes: 32 << 10, TransmitBytes: 32 << 10,
		ReceiveDatagrams: 8, TransmitDatagrams: 8, MaxPayloadBytes: 1200,
	}
}

// Option configures UDP-local authority and finite resources.
type Option interface {
	applyUDP(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyUDP(config *registration) error { return option(config) }

type registration struct {
	config             Config
	defaultAuthority   bool
	authorityAdditions policy.Config
}

// WithConfig supplies the advanced exact UDP storage configuration.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		return nil
	})
}

// WithPolicy adds advanced raw UDP policy rules and special-class grants.
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

// WithoutDefaultAuthority suppresses ephemeral-client bind and outbound-unicast
// grants for compatibility or fully caller-authored policy.
func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error {
		target.defaultAuthority = false
		return nil
	})
}

// AllowServer explicitly grants binds to the supplied local port ranges on the
// configured local address. An empty range list grants all nonprivileged ports.
func AllowServer(ports ...wagonet.PolicyPortRange) Option {
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportUDP},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound}, Ports: append([]wagonet.PolicyPortRange(nil), ports...),
	}}})
}

// AllowWildcardBind permits explicitly granted non-ephemeral server binds to
// use an unspecified local address.
func AllowWildcardBind() Option { return WithPolicy(wagonet.PolicyConfig{AllowWildcardBind: true}) }

// AllowPrivilegedBind permits explicitly granted binds on ports 1..1023.
func AllowPrivilegedBind() Option {
	return WithPolicy(wagonet.PolicyConfig{AllowPrivilegedBind: true})
}

// AllowLoopback permits otherwise granted loopback destinations.
func AllowLoopback() Option { return WithPolicy(wagonet.PolicyConfig{AllowLoopback: true}) }

// AllowMulticast permits otherwise granted multicast destinations.
func AllowMulticast() Option { return WithPolicy(wagonet.PolicyConfig{AllowMulticast: true}) }

// AllowBroadcast permits otherwise granted limited-broadcast destinations.
func AllowBroadcast() Option { return WithPolicy(wagonet.PolicyConfig{AllowBroadcast: true}) }

// AllowAll conspicuously grants UDP authority in both directions and every
// special endpoint class. Storage and quotas remain finite.
func AllowAll() Option {
	return WithPolicy(wagonet.PolicyConfig{
		Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportUDP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound, wagonet.PolicyOutbound},
		}},
		AllowWildcardBind: true, AllowLoopback: true, AllowMulticast: true,
		AllowBroadcast: true, AllowPrivilegedBind: true,
	})
}

func defaultAuthority() policy.Config {
	return policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionInbound}, Ports: []policy.PortRange{{First: 0, Last: 0}}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionOutbound}},
		},
		AllowWildcardBind: true,
	}
}

func (r registration) authority() policy.Config {
	if !r.defaultAuthority {
		return policy.Merge(r.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(), r.authorityAdditions)
}

// Register selects only the UDP capability, wago_net_udp import table, and UDP
// backend contribution on network. Shared wago_net.abi_version registration is
// added by the root when the first protocol is selected.
func Register(network *wagonet.Network, options ...Option) error {
	config := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyUDP(&config); err != nil {
			return err
		}
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil,
		func(base any) (nscore.Service, error) {
			common, ok := base.(*lnetocore.Namespace)
			if !ok {
				return nscore.Service{}, plugin.ErrInvalidBackend
			}
			adapter, err := udpbackend.New(common, config.config)
			if err != nil {
				return nscore.Service{}, err
			}
			return nscore.Service{Key: udpns.ServiceKey, Value: adapter}, nil
		},
	)
	module := udpbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(config.authority()))
	return network.RegisterModule(module)
}
