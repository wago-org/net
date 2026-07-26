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
// UDP/TCP response bytes, and deterministic retry bounds. MaxQueries limits live
// guest query handles until close even after a terminal query has retired its
// transport state. TCP fallback is disabled unless both TCP fields are nonzero.
// Zero MaxQueries disables queries.
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
	config                Config
	configSet             bool
	resolver              netip.Addr
	resolverSet           bool
	tcpFallbackSet        bool
	maxTCPResponseBytes   int
	maxTCPServiceAttempts uint16
	defaultAuthority      bool
	authorityAdditions    policy.Config
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

// EnableTCPFallback permits one private, non-guest-visible TCP connection to
// the configured resolver after a valid correlated UDP response sets the DNS
// truncation bit. Response retention and maintenance attempts remain exact and
// finite; raw-TCP allow authority is not granted and raw-TCP denies still apply.
func EnableTCPFallback(maxResponseBytes int, maxServiceAttempts uint16) Option {
	return optionFunc(func(target *registration) error {
		if target.tcpFallbackSet || maxResponseBytes < 12 || maxResponseBytes > dnsbackend.MaximumTCPResponseBytes ||
			maxServiceAttempts == 0 || maxServiceAttempts > dnsbackend.MaximumTCPServiceAttempts {
			return ErrInvalidOption
		}
		target.tcpFallbackSet = true
		target.maxTCPResponseBytes = maxResponseBytes
		target.maxTCPServiceAttempts = maxServiceAttempts
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
	if r.resolverSet {
		if !r.configSet {
			config = DefaultConfig(r.resolver)
		} else {
			config.Server = r.resolver
		}
	}
	if r.tcpFallbackSet {
		config.MaxTCPResponseBytes = r.maxTCPResponseBytes
		config.MaxTCPServiceAttempts = r.maxTCPServiceAttempts
	}
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
	if config.tcpFallbackSet && !config.resolverSet && (!config.configSet || !resolvedConfig.Server.IsValid()) {
		return ErrInvalidResolver
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1, func(base any) error {
		common, ok := base.(*lnetocore.Config)
		if !ok {
			return plugin.ErrInvalidBackend
		}
		if resolvedConfig.MaxTCPResponseBytes != 0 {
			ports := uint32(common.MaxActiveTCPPorts) + uint32(resolvedConfig.MaxQueries)
			if ports > uint32(^uint16(0)) {
				return plugin.ErrInvalidBackend
			}
			common.MaxActiveTCPPorts = uint16(ports)
		}
		return nil
	},
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
