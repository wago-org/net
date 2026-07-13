// Package mdns selectively registers bounded multicast DNS query, configured
// response, and service-announcement operations.
package mdns

import (
	"errors"
	"net/netip"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	mdnsbackend "github.com/wago-org/net/internal/backend/lneto/mdns"
	mdnsbinding "github.com/wago-org/net/internal/binding/mdns"
	nscore "github.com/wago-org/net/internal/namespace/core"
	mdnsns "github.com/wago-org/net/internal/namespace/mdns"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var (
	ErrInvalidOption  = errors.New("wagonet/mdns: invalid option")
	ErrInvalidConfig  = errors.New("wagonet/mdns: invalid finite configuration")
	ErrInvalidService = errors.New("wagonet/mdns: invalid service")
)

// Service is copied during registration. Names are lowercase ASCII .local
// names; service labels may contain underscores. TXT is raw DNS TXT RDATA.
type Service struct {
	Name       string
	Host       string
	Address    netip.Addr
	TTLSeconds uint32
	Port       uint16
	TXT        []byte
}

// Config bounds every service, operation, packet, parse, queue, and retry
// dimension. The zero value truthfully disables operations when supplied via
// WithConfig.
type Config struct {
	Services              []Service
	MaxServices           uint16
	MaxQueries            uint16
	MaxAnnouncements      uint16
	MaxRecords            uint16
	MaxPacketBytes        int
	MaxQueuedResponses    uint16
	MaxQuestionsPerPacket uint16
	MaxRecordsPerPacket   uint16
	MaxAttempts           uint16
	RetryServiceAttempts  uint16
}

func DefaultConfig() Config {
	return Config{
		MaxQueries: 8, MaxRecords: 16, MaxPacketBytes: 1200,
		MaxQuestionsPerPacket: 8, MaxRecordsPerPacket: 32,
		MaxAttempts: 2, RetryServiceAttempts: 32,
	}
}

type Option interface{ applyMDNS(*registration) error }
type optionFunc func(*registration) error

func (f optionFunc) applyMDNS(r *registration) error { return f(r) }

type registration struct {
	config             Config
	defaultAuthority   bool
	authorityAdditions policy.Config
}

func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error {
		target.config = cloneConfig(config)
		return nil
	})
}

// WithServices installs a copied finite service set. Incoming matching
// questions are answered automatically and guests may announce a service by
// its zero-based registration index.
func WithServices(services ...Service) Option {
	if len(services) == 0 || len(services) > int(^uint16(0)) {
		return optionFunc(func(*registration) error { return ErrInvalidService })
	}
	copied := cloneServices(services)
	return optionFunc(func(target *registration) error {
		target.config.Services = copied
		target.config.MaxServices = uint16(len(copied))
		if target.config.MaxAnnouncements == 0 {
			target.config.MaxAnnouncements = 4
		}
		if target.config.MaxQueuedResponses == 0 {
			target.config.MaxQueuedResponses = 4
		}
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
	return optionFunc(func(target *registration) error {
		target.defaultAuthority = false
		return nil
	})
}

// AllowSuffixes adds mDNS name authority without widening general DNS or UDP.
func AllowSuffixes(suffixes ...string) Option {
	if len(suffixes) == 0 {
		return optionFunc(func(*registration) error { return ErrInvalidOption })
	}
	rules := []wagonet.PolicyRule{
		{Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportMDNS}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}, DNSSuffixes: append([]string(nil), suffixes...)},
		{Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportMDNS}, Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound}, DNSSuffixes: append([]string(nil), suffixes...)},
	}
	return WithPolicy(wagonet.PolicyConfig{Rules: rules})
}

// AllowAllNames conspicuously grants every structurally valid mDNS name while
// preserving the exact 224.0.0.251:5353 multicast endpoint and finite bounds.
func AllowAllNames() Option {
	return WithPolicy(wagonet.PolicyConfig{Rules: []wagonet.PolicyRule{
		{Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportMDNS}, Directions: []wagonet.PolicyDirection{wagonet.PolicyOutbound}},
		{Action: wagonet.PolicyAllow, Transports: []wagonet.PolicyTransport{wagonet.PolicyTransportMDNS}, Directions: []wagonet.PolicyDirection{wagonet.PolicyInbound}},
	}})
}

func Register(network *wagonet.Network, options ...Option) error {
	registration := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyMDNS(&registration); err != nil {
			return err
		}
	}
	backendConfig, err := registration.config.backend()
	if err != nil || !mdnsbackend.ValidConfig(backendConfig, 65535, nil, nil, false) {
		if err != nil {
			return err
		}
		return ErrInvalidConfig
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common, ok := base.(*lnetocore.Namespace)
		if !ok {
			return nscore.Service{}, plugin.ErrInvalidBackend
		}
		adapter, err := mdnsbackend.New(common, backendConfig)
		if err != nil {
			return nscore.Service{}, err
		}
		return nscore.Service{Key: mdnsns.ServiceKey, Value: adapter}, nil
	})
	module := mdnsbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(registration.authority()))
	return network.RegisterModule(module)
}

func (c Config) backend() (mdnsbackend.Config, error) {
	services := make([]mdnsns.Service, len(c.Services))
	for i, service := range c.Services {
		ttl := service.TTLSeconds
		if ttl == 0 {
			ttl = 120
		}
		if len(service.TXT) > mdnsns.MaxTXTBytes {
			return mdnsbackend.Config{}, ErrInvalidService
		}
		converted := mdnsns.Service{Name: service.Name, Host: service.Host, Address: service.Address, TTLSeconds: ttl, Port: service.Port, TXTLength: uint16(len(service.TXT))}
		copy(converted.TXT[:], service.TXT)
		if !converted.Valid() {
			return mdnsbackend.Config{}, ErrInvalidService
		}
		services[i] = converted
	}
	return mdnsbackend.Config{
		Services: services, MaxServices: c.MaxServices, MaxQueries: c.MaxQueries, MaxAnnouncements: c.MaxAnnouncements,
		MaxRecords: c.MaxRecords, MaxPacketBytes: c.MaxPacketBytes, MaxQueuedResponses: c.MaxQueuedResponses,
		MaxQuestionsPerPacket: c.MaxQuestionsPerPacket, MaxRecordsPerPacket: c.MaxRecordsPerPacket,
		MaxAttempts: c.MaxAttempts, RetryServiceAttempts: c.RetryServiceAttempts,
	}, nil
}

func (r registration) authority() policy.Config {
	if !r.defaultAuthority {
		return policy.Merge(r.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(), r.authorityAdditions)
}

func defaultAuthority() policy.Config {
	return policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportMDNS}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{224, 0, 0, 251}), 32)}, Ports: []policy.PortRange{{First: mdnsbackend.Port, Last: mdnsbackend.Port}}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportMDNS}, Directions: []policy.Direction{policy.DirectionOutbound}, DNSSuffixes: []string{"local"}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportMDNS}, Directions: []policy.Direction{policy.DirectionInbound}, DNSSuffixes: []string{"local"}},
		},
		MulticastTransports: []policy.Transport{policy.TransportMDNS},
	}
}

func cloneConfig(config Config) Config {
	cloned := config
	cloned.Services = cloneServices(config.Services)
	return cloned
}

func cloneServices(services []Service) []Service {
	copied := make([]Service, len(services))
	for i, service := range services {
		copied[i] = service
		copied[i].TXT = append([]byte(nil), service.TXT...)
	}
	return copied
}
