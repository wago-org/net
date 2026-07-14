// Package linklocal4 selectively registers bounded IPv4 link-local/APIPA
// claim-and-defend service.
package linklocal4

import (
	"errors"
	"net/netip"
	"reflect"
	"time"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	linklocalbackend "github.com/wago-org/net/internal/backend/lneto/linklocal4"
	linklocalbinding "github.com/wago-org/net/internal/binding/linklocal4"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var (
	ErrInvalidOption    = errors.New("wagonet/linklocal4: invalid option")
	ErrIncompleteConfig = errors.New("wagonet/linklocal4: explicit clock and nonzero seed are both required")
	ErrInvalidConfig    = errors.New("wagonet/linklocal4: invalid finite configuration")
)

// Clock is the explicit host monotonic clock authority used for RFC 3927
// scheduling. It must return promptly and must not reenter networking calls.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts one explicit function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Config fixes every live claim, conflict sequence, service attempt, candidate
// sequence, and scheduling authority. The zero value disables operations.
type Config struct {
	MaxClaims          uint16
	MaxConflicts       uint8
	MaxServiceAttempts uint16
	Seed               uint64
	Clock              Clock
}

// DefaultConfig returns finite bounds for one explicit deterministic seed and
// clock. The seed should derive from stable host identity such as the MAC.
func DefaultConfig(seed uint64, clock Clock) Config {
	return Config{MaxClaims: 1, MaxConflicts: 16, MaxServiceAttempts: 256, Seed: seed, Clock: clock}
}

type Option interface{ applyLinkLocal4(*registration) error }
type optionFunc func(*registration) error

func (f optionFunc) applyLinkLocal4(target *registration) error { return f(target) }

type registration struct {
	config             Config
	configSet          bool
	seed               uint64
	seedSet            bool
	clock              Clock
	clockSet           bool
	defaultAuthority   bool
	authorityAdditions policy.Config
}

func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = config
		target.configSet = true
		return nil
	})
}

// WithSeed injects the deterministic finite candidate sequence seed. Pair it
// with WithClock; finite defaults activate when both are supplied.
func WithSeed(seed uint64) Option {
	return optionFunc(func(target *registration) error {
		if seed == 0 {
			return ErrInvalidOption
		}
		target.seed, target.seedSet = seed, true
		return nil
	})
}

// WithClock injects the only scheduling time authority used by the adapter.
func WithClock(clock Clock) Option {
	return optionFunc(func(target *registration) error {
		if !usableClock(clock) {
			return ErrInvalidOption
		}
		target.clock, target.clockSet = clock, true
		return nil
	})
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

// AllowCandidates grants candidate and defense authority in copied IPv4
// prefixes. Structural RFC 3927 validation still restricts actual addresses.
func AllowCandidates(prefixes ...netip.Prefix) Option {
	if len(prefixes) == 0 {
		return optionFunc(func(*registration) error { return ErrInvalidOption })
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
			return optionFunc(func(*registration) error { return ErrInvalidOption })
		}
	}
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{{
		Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportLinkLocal4},
		Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, Prefixes: append([]netip.Prefix(nil), prefixes...),
	}}})
}

func Register(network *wagonet.Network, options ...Option) error {
	registration := registration{defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyLinkLocal4(&registration); err != nil {
			return err
		}
	}
	config, err := registration.finalConfig()
	if err != nil {
		return err
	}
	backendConfig := config.backend()
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common, ok := base.(*lnetocore.Namespace)
		if !ok {
			return nscore.Service{}, plugin.ErrInvalidBackend
		}
		adapter, err := linklocalbackend.New(common, backendConfig)
		if err != nil {
			return nscore.Service{}, err
		}
		return nscore.Service{Key: linklocalns.ServiceKey, Value: adapter}, nil
	})
	module := linklocalbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(registration.authority(config)))
	return network.RegisterModule(module)
}

func (r registration) finalConfig() (Config, error) {
	if !r.configSet && !r.seedSet && !r.clockSet {
		return Config{}, nil
	}
	config := r.config
	if !r.configSet {
		if !r.seedSet || !r.clockSet {
			return Config{}, ErrIncompleteConfig
		}
		config = DefaultConfig(r.seed, r.clock)
	} else {
		if r.seedSet {
			config.Seed = r.seed
		}
		if r.clockSet {
			config.Clock = r.clock
		}
	}
	if (config.MaxClaims != 0 && !usableClock(config.Clock)) || !linklocalbackend.ValidConfig(config.backend(), nil, nil, false) {
		return Config{}, ErrInvalidConfig
	}
	return config, nil
}

func usableClock(clock Clock) bool {
	if clock == nil {
		return false
	}
	value := reflect.ValueOf(clock)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

func (c Config) backend() linklocalbackend.Config {
	var clock linklocalns.Clock
	if c.Clock != nil {
		clock = linklocalns.ClockFunc(c.Clock.Now)
	}
	return linklocalbackend.Config{MaxClaims: c.MaxClaims, MaxConflicts: c.MaxConflicts, MaxServiceAttempts: c.MaxServiceAttempts, Seed: c.Seed, Clock: clock}
}

func (r registration) authority(config Config) policy.Config {
	if !r.defaultAuthority || config.MaxClaims == 0 {
		return policy.Merge(r.authorityAdditions)
	}
	defaults := policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportLinkLocal4},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{linklocalns.Prefix},
	}}}
	return policy.Merge(defaults, r.authorityAdditions)
}
