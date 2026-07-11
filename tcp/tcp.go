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
)

var ErrInvalidOption = errors.New("wagonet/tcp: invalid option")

// Config fixes TCP-local listeners, outbound streams, buffers, packet tracking,
// and backlog storage. Finite client-oriented defaults are added in the next
// policy/defaults stage; zero currently disables backend TCP resources.
type Config = tcpbackend.Config

// Option configures TCP-local authority and finite resources.
type Option interface {
	applyTCP(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyTCP(config *registration) error { return option(config) }

type registration struct {
	config Config
}

// WithConfig supplies the advanced exact TCP storage configuration.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		return nil
	})
}

// Register selects only the TCP capability, wago_net_tcp import table, and TCP
// backend contribution on network. Shared wago_net.abi_version registration is
// added by the root when the first protocol is selected.
func Register(network *wagonet.Network, options ...Option) error {
	var config registration
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
	return network.RegisterModule(tcpbinding.Descriptor(backend))
}
