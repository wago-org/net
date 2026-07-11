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
)

var ErrInvalidOption = errors.New("wagonet/udp: invalid option")

// Config fixes UDP-local socket, queue, payload, and retained-byte bounds.
// Finite client-oriented defaults are added in the next policy/defaults stage;
// zero currently disables backend UDP resources.
type Config = udpbackend.Config

// Option configures UDP-local authority and finite resources.
type Option interface {
	applyUDP(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyUDP(config *registration) error { return option(config) }

type registration struct {
	config Config
}

// WithConfig supplies the advanced exact UDP storage configuration.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		return nil
	})
}

// Register selects only the UDP capability, wago_net_udp import table, and UDP
// backend contribution on network. Shared wago_net.abi_version registration is
// added by the root when the first protocol is selected.
func Register(network *wagonet.Network, options ...Option) error {
	var config registration
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
	return network.RegisterModule(udpbinding.Descriptor(backend))
}
