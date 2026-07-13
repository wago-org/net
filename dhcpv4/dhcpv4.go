// Package dhcpv4 selectively registers bounded DHCPv4 client leases and
// explicitly authorized finite automatic server service.
package dhcpv4

import (
	"errors"
	"net/netip"

	wagonet "github.com/wago-org/net"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	dhcpbackend "github.com/wago-org/net/internal/backend/lneto/dhcpv4"
	dhcpbinding "github.com/wago-org/net/internal/binding/dhcpv4"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var (
	ErrInvalidOption = errors.New("wagonet/dhcpv4: invalid option")
	ErrInvalidConfig = errors.New("wagonet/dhcpv4: invalid finite configuration")
	ErrInvalidServer = errors.New("wagonet/dhcpv4: invalid server configuration")
)

// Server enables bounded automatic DORA service. It is disabled unless
// explicitly supplied, and its pool authority never inherits general UDP.
type Server struct {
	Address      netip.Addr
	Gateway      netip.Addr
	DNS          netip.Addr
	Subnet       netip.Prefix
	LeaseSeconds uint32
	MaxClients   uint16
}

// Config fixes every client/server, packet, DNS-option, and response wait
// dimension. ApplyLease transactionally contributes the accepted IPv4 identity
// and therefore requires the shared static IPv4 address to be 0.0.0.0.
type Config struct {
	MaxLeases               uint16
	MaxPacketBytes          int
	ResponseServiceAttempts uint16
	MaxDNSServers           uint8
	ApplyLease              bool
	Server                  *Server
}

func DefaultConfig() Config {
	return Config{MaxLeases: 1, MaxPacketBytes: 576, ResponseServiceAttempts: 32, MaxDNSServers: dhcpns.MaxDNSServers}
}

type Option interface{ applyDHCPv4(*registration) error }
type optionFunc func(*registration) error

func (f optionFunc) applyDHCPv4(r *registration) error { return f(r) }

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

// ApplyLeaseIdentity enables transactional namespace address/subnet mutation.
// Close or release rolls the exact contribution back to the configured static
// address. Existing protocol adapters read the shared current identity.
func ApplyLeaseIdentity() Option {
	return optionFunc(func(target *registration) error {
		target.config.ApplyLease = true
		return nil
	})
}

// WithServer explicitly enables one copied finite DHCPv4 server pool.
func WithServer(server Server) Option {
	copied := server
	return optionFunc(func(target *registration) error {
		target.config.Server = &copied
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

func Register(network *wagonet.Network, options ...Option) error {
	registration := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyDHCPv4(&registration); err != nil {
			return err
		}
	}
	backendConfig, err := registration.config.backend()
	if err != nil || !dhcpbackend.ValidConfig(backendConfig, 65535, nil, nil, false) {
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
		adapter, err := dhcpbackend.New(common, backendConfig)
		if err != nil {
			return nscore.Service{}, err
		}
		return nscore.Service{Key: dhcpns.ServiceKey, Value: adapter}, nil
	})
	module := dhcpbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(registration.authority()))
	return network.RegisterModule(module)
}

func (c Config) backend() (dhcpbackend.Config, error) {
	backend := dhcpbackend.Config{MaxLeases: c.MaxLeases, MaxPacketBytes: c.MaxPacketBytes, ResponseServiceAttempts: c.ResponseServiceAttempts, MaxDNSServers: c.MaxDNSServers, ApplyLease: c.ApplyLease}
	if c.Server != nil {
		server := *c.Server
		backend.Server = dhcpbackend.ServerConfig{ServerAddr: server.Address, Gateway: server.Gateway, DNS: server.DNS, Subnet: server.Subnet, LeaseSeconds: server.LeaseSeconds, MaxClients: server.MaxClients}
		if server.MaxClients == 0 || server.LeaseSeconds == 0 {
			return dhcpbackend.Config{}, ErrInvalidServer
		}
	}
	return backend, nil
}

func (r registration) authority() policy.Config {
	if !r.defaultAuthority {
		return policy.Merge(r.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(r.config), r.authorityAdditions)
}

func defaultAuthority(config Config) policy.Config {
	var result policy.Config
	if config.MaxLeases != 0 {
		result.Rules = append(result.Rules,
			policy.Rule{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 32)}, Ports: []policy.PortRange{{First: dhcpns.ClientPort, Last: dhcpns.ClientPort}}},
			policy.Rule{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), 32)}, Ports: []policy.PortRange{{First: dhcpns.ServerPort, Last: dhcpns.ServerPort}}},
		)
		result.WildcardBindTransports = append(result.WildcardBindTransports, policy.TransportDHCPv4)
		result.BroadcastTransports = append(result.BroadcastTransports, policy.TransportDHCPv4)
		result.PrivilegedBindTransports = append(result.PrivilegedBindTransports, policy.TransportDHCPv4)
	}
	if config.Server != nil {
		server := config.Server
		result.Rules = append(result.Rules,
			policy.Rule{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(server.Address, 32)}, Ports: []policy.PortRange{{First: dhcpns.ServerPort, Last: dhcpns.ServerPort}}},
			policy.Rule{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{server.Subnet.Masked()}, Ports: []policy.PortRange{{First: dhcpns.ClientPort, Last: dhcpns.ClientPort}}},
		)
		result.PrivilegedBindTransports = append(result.PrivilegedBindTransports, policy.TransportDHCPv4)
	}
	return result
}

func cloneConfig(config Config) Config {
	cloned := config
	if config.Server != nil {
		server := *config.Server
		cloned.Server = &server
	}
	return cloned
}
