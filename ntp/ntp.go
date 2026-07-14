// Package ntp selectively registers Wago's checked bounded NTP client
// capability, imports, instance operations, namespace facet, and lneto adapter.
package ntp

import (
	"errors"
	"net/netip"
	"time"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	ntpbackend "github.com/wago-org/net/internal/backend/lneto/ntp"
	ntpbinding "github.com/wago-org/net/internal/binding/ntp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ntpns "github.com/wago-org/net/internal/namespace/ntp"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var (
	ErrInvalidOption    = errors.New("wagonet/ntp: invalid option")
	ErrInvalidServer    = errors.New("wagonet/ntp: invalid IPv4 server")
	ErrIncompleteConfig = errors.New("wagonet/ntp: server and explicit clock are both required")
	ErrInvalidConfig    = errors.New("wagonet/ntp: invalid finite configuration")
)

// Clock is the explicit host wall-clock authority used for NTP timestamps. It
// must return promptly and must not reenter networking operations.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts one explicit host function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Config fixes one server, explicit clock, concurrent synchronizations,
// attempts, retry spacing, and NTP precision. Zero disables NTP operations.
type Config struct {
	Server               netip.Addr
	Clock                Clock
	MaxSyncs             uint16
	MaxAttempts          uint16
	RetryServiceAttempts uint16
	Precision            int8
}

// DefaultConfig returns finite two-exchange client bounds for one explicit
// server and host clock.
func DefaultConfig(server netip.Addr, clock Clock) Config {
	return Config{Server: server, Clock: clock, MaxSyncs: 4, MaxAttempts: 2, RetryServiceAttempts: 32, Precision: -20}
}

// Option configures NTP-local authority and finite resources.
type Option interface {
	applyNTP(*registration) error
}

type optionFunc func(*registration) error

func (option optionFunc) applyNTP(config *registration) error { return option(config) }

type registration struct {
	config             Config
	configSet          bool
	server             netip.Addr
	serverSet          bool
	clock              Clock
	clockSet           bool
	defaultAuthority   bool
	authorityAdditions policy.Config
}

// WithConfig supplies the advanced exact NTP configuration.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		target.configSet = true
		return nil
	})
}

// Server selects one explicit unicast IPv4 NTP server. Pair it with WithClock;
// finite defaults are installed when both are supplied.
func Server(server string) Option {
	return optionFunc(func(target *registration) error {
		address, err := netip.ParseAddr(server)
		if err != nil || !validServer(address) {
			return ErrInvalidServer
		}
		target.server = address
		target.serverSet = true
		return nil
	})
}

// WithClock injects the only wall-clock authority used by the NTP adapter.
func WithClock(clock Clock) Option {
	return optionFunc(func(target *registration) error {
		if clock == nil {
			return ErrInvalidOption
		}
		target.clock = clock
		target.clockSet = true
		return nil
	})
}

// WithPolicy adds advanced raw NTP endpoint policy rules. Caller and option
// deny rules always win after shared composition.
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

// WithoutDefaultAuthority suppresses the exact configured server grant.
func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error {
		target.defaultAuthority = false
		return nil
	})
}

// AllowServers grants NTP synchronization to port 123 in each supplied IPv4
// prefix. Empty input is rejected.
func AllowServers(prefixes ...netip.Prefix) Option {
	if len(prefixes) == 0 {
		return optionFunc(func(*registration) error { return ErrInvalidOption })
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
			return optionFunc(func(*registration) error { return ErrInvalidOption })
		}
	}
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportNTP},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: append([]netip.Prefix(nil), prefixes...),
		Ports: []wagonet.PolicyPortRange{{First: 123, Last: 123}},
	}}})
}

// AllowLoopback grants loopback policy authority. NTP server configuration
// still rejects loopback as a non-wire identity.
func AllowLoopback() Option {
	return WithPolicy(wagonet.PolicyConfig{LoopbackTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportNTP}})
}

// AllowAll conspicuously grants policy authority for port 123 on every
// structurally valid unicast IPv4 destination class. NTP server configuration
// still rejects loopback; resources, attempts, and service remain finite and
// the adapter still uses only its one configured server.
func AllowAll() Option {
	return WithPolicy(wagonet.PolicyConfig{
		Rules: []wagonet.PolicyRule{{
			Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportNTP},
			Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Ports: []wagonet.PolicyPortRange{{First: 123, Last: 123}},
		}},
		LoopbackTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportNTP},
	})
}

func (r registration) finalConfig() (Config, error) {
	if !r.configSet && !r.serverSet && !r.clockSet {
		return Config{}, nil
	}
	config := r.config
	if !r.configSet {
		if !r.serverSet || !r.clockSet {
			return Config{}, ErrIncompleteConfig
		}
		config = DefaultConfig(r.server, r.clock)
	} else {
		if r.serverSet {
			config.Server = r.server
		}
		if r.clockSet {
			config.Clock = r.clock
		}
	}
	backendConfig := config.backend()
	if !ntpbackend.ValidConfig(backendConfig, nil, nil, false) {
		return Config{}, ErrInvalidConfig
	}
	return config, nil
}

func (c Config) backend() ntpbackend.Config {
	var clock ntpns.Clock
	if c.Clock != nil {
		clock = c.Clock
	}
	return ntpbackend.Config{
		Server: c.Server, Clock: clock, MaxSyncs: c.MaxSyncs, MaxAttempts: c.MaxAttempts,
		RetryServiceAttempts: c.RetryServiceAttempts, Precision: c.Precision,
	}
}

func (r registration) authority(config Config) policy.Config {
	additions := r.authorityAdditions
	if !r.defaultAuthority || config.MaxSyncs == 0 {
		return policy.Merge(additions)
	}
	prefix := netip.PrefixFrom(config.Server, 32)
	defaults := policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportNTP},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{prefix},
		Ports: []policy.PortRange{{First: 123, Last: 123}},
	}}}
	return policy.Merge(defaults, additions)
}

// Register selects only the NTP capability, wago_net_ntp import table, and NTP
// backend contribution on network. Registration without options is a truthful
// disabled module; Server plus WithClock installs finite usable defaults.
func Register(network *wagonet.Network, options ...Option) error {
	config := registration{defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyNTP(&config); err != nil {
			return err
		}
	}
	resolvedConfig, err := config.finalConfig()
	if err != nil {
		return err
	}
	backendConfig := resolvedConfig.backend()
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil,
		func(base any) (nscore.Service, error) {
			common, ok := base.(*lnetocore.Namespace)
			if !ok {
				return nscore.Service{}, plugin.ErrInvalidBackend
			}
			adapter, err := ntpbackend.New(common, backendConfig)
			if err != nil {
				return nscore.Service{}, err
			}
			return nscore.Service{Key: ntpns.ServiceKey, Value: adapter}, nil
		},
	)
	module := ntpbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(config.authority(resolvedConfig)))
	return network.RegisterModule(module)
}

func validServer(address netip.Addr) bool {
	return address.Is4() && !address.Is4In6() && !address.IsUnspecified() && !address.IsLoopback() && address.Zone() == "" &&
		!address.IsMulticast() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
