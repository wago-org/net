// Package dns selectively registers Wago's checked bounded DNS guest
// capability, imports, instance operations, namespace facet, and lneto adapter.
package dns

import (
	"errors"
	"net/netip"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	dnsbackend "github.com/wago-org/net/internal/backend/lneto/dns"
	dnsbinding "github.com/wago-org/net/internal/binding/dns"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dnsns "github.com/wago-org/net/internal/namespace/dns"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var (
	ErrInvalidOption   = errors.New("wagonet/dns: invalid option")
	ErrInvalidResolver = errors.New("wagonet/dns: invalid IPv4 resolver")
)

// Config fixes DNS resolver authority, concurrent queries, retained records,
// response bytes, and deterministic retry bounds. MaxQueries limits live guest
// query handles until close even after a terminal query has retired its
// transport state. Zero disables queries.
type Config = dnsbackend.Config

// DefaultConfig returns finite A/AAAA client storage for one explicit resolver.
func DefaultConfig(server netip.Addr) Config {
	return Config{
		Server: server, MaxQueries: 8, MaxRecords: 16, MaxResponseBytes: 1232,
		MaxAttempts: 2, RetryServiceAttempts: 32,
	}
}

// Option configures DNS-local authority and finite resources.
type Option interface {
	applyDNS(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyDNS(config *registration) error { return option(config) }

type registration struct {
	config             Config
	configSet          bool
	resolver           netip.Addr
	resolverSet        bool
	defaultAuthority   bool
	authorityAdditions policy.Config
}

// WithConfig supplies the advanced exact DNS resolver and storage configuration.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		target.configSet = true
		return nil
	})
}

// Resolver selects one explicit wire-routable IPv4 recursive resolver. If no
// exact storage override has been supplied, finite client defaults are installed
// with it.
func Resolver(server string) Option {
	return optionFunc(func(target *registration) error {
		address, err := netip.ParseAddr(server)
		if err != nil || !address.Is4() || address.Is4In6() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return ErrInvalidResolver
		}
		target.resolver = address
		target.resolverSet = true
		return nil
	})
}

// WithPolicy adds advanced raw DNS-name policy rules.
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

// WithoutDefaultAuthority suppresses the ordinary valid-name query grant for
// compatibility or caller-authored suffix policy.
func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error {
		target.defaultAuthority = false
		return nil
	})
}

// AllowSuffixes explicitly grants exact names and subdomains of each suffix.
// Empty input is rejected; use AllowAll to grant every structurally valid DNS
// name.
func AllowSuffixes(suffixes ...string) Option {
	if len(suffixes) == 0 {
		return optionFunc(func(*registration) error { return ErrInvalidOption })
	}
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportDNS},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, DNSSuffixes: append([]string(nil), suffixes...),
	}}})
}

// AllowAll conspicuously grants every structurally valid DNS name. Query types,
// storage, retries, records, bytes, work, and service remain finite.
func AllowAll() Option { return WithPolicy(defaultAuthority()) }

func defaultAuthority() policy.Config {
	return policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDNS},
		Directions: []policy.Direction{policy.DirectionOutbound},
	}}}
}

func (r registration) authority() policy.Config {
	if !r.defaultAuthority {
		return policy.Merge(r.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(), r.authorityAdditions)
}

func (r registration) finalConfig() Config {
	config := r.config
	if !r.resolverSet {
		return config
	}
	if !r.configSet {
		return DefaultConfig(r.resolver)
	}
	config.Server = r.resolver
	return config
}

// Register selects only the DNS capability, wago_net_dns import table, and DNS
// backend contribution on network. Shared wago_net.abi_version registration is
// added by the root when the first protocol is selected.
func Register(network *wagonet.Network, options ...Option) error {
	config := registration{defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyDNS(&config); err != nil {
			return err
		}
	}
	resolvedConfig := config.finalConfig()
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil,
		func(base any) (nscore.Service, error) {
			common, ok := base.(*lnetocore.Namespace)
			if !ok {
				return nscore.Service{}, plugin.ErrInvalidBackend
			}
			adapter, err := dnsbackend.New(common, resolvedConfig)
			if err != nil {
				return nscore.Service{}, err
			}
			return nscore.Service{Key: dnsns.ServiceKey, Value: adapter}, nil
		},
	)
	module := dnsbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(config.authority()))
	return network.RegisterModule(module)
}
