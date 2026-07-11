// Package dns selectively registers Wago's checked bounded DNS guest
// capability, imports, instance operations, namespace facet, and lneto adapter.
package dns

import (
	"errors"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	dnsbackend "github.com/wago-org/net/internal/backend/lneto/dns"
	dnsbinding "github.com/wago-org/net/internal/binding/dns"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	"github.com/wago-org/net/internal/plugin"
)

var ErrInvalidOption = errors.New("wagonet/dns: invalid option")

// Config fixes DNS resolver authority, concurrent queries, retained records,
// response bytes, and deterministic retry bounds. Finite client-oriented
// defaults are added in the next policy/defaults stage; zero disables queries.
type Config = dnsbackend.Config

// Option configures DNS-local authority and finite resources.
type Option interface {
	applyDNS(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyDNS(config *registration) error { return option(config) }

type registration struct {
	config Config
}

// WithConfig supplies the advanced exact DNS resolver and storage configuration.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		return nil
	})
}

// Register selects only the DNS capability, wago_net_dns import table, and DNS
// backend contribution on network. Shared wago_net.abi_version registration is
// added by the root when the first protocol is selected.
func Register(network *wagonet.Network, options ...Option) error {
	var config registration
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyDNS(&config); err != nil {
			return err
		}
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil,
		func(base any) (nscore.Service, error) {
			common, ok := base.(*lnetocore.Namespace)
			if !ok {
				return nscore.Service{}, plugin.ErrInvalidBackend
			}
			adapter, err := dnsbackend.New(common, config.config)
			if err != nil {
				return nscore.Service{}, err
			}
			return nscore.Service{Key: dnsns.ServiceKey, Value: adapter}, nil
		},
	)
	return network.RegisterModule(dnsbinding.Descriptor(backend))
}
