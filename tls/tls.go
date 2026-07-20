// Package tls selectively registers Wago's outbound, verified, nonblocking TLS
// client capability. TLS is independent from the public raw-TCP capability.
package tls

import (
	"errors"

	wagonet "github.com/wago-org/net"
	gotls "github.com/wago-org/net/internal/backend/gotls"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	tlsbackend "github.com/wago-org/net/internal/backend/lneto/tls"
	tlsbinding "github.com/wago-org/net/internal/binding/tls"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
)

var ErrInvalidOption = errors.New("wagonet/tls: invalid option")

// Option configures TLS-local profiles, authority, and finite storage.
type Option interface{ applyTLS(*registration) error }
type optionFunc func(*registration) error

func (option optionFunc) applyTLS(target *registration) error { return option(target) }

type registration struct {
	config             Config
	profiles           []*ClientProfile
	serverProfiles     []*ServerProfile
	defaultAuthority   bool
	authorityAdditions policy.Config
}

// WithConfig supplies exact advanced TLS, worker, and private TCP bounds.
func WithConfig(config Config) Option {
	return optionFunc(func(target *registration) error { target.config = config; return nil })
}

// WithClientProfile adds one immutable host-defined profile. Duplicate IDs are
// rejected; a network must register at least one profile.
func WithClientProfile(profile *ClientProfile) Option {
	return optionFunc(func(target *registration) error {
		if profile == nil || profile.id == 0 {
			return ErrInvalidProfile
		}
		target.profiles = append(target.profiles, profile)
		return nil
	})
}

// WithServerProfile adds one immutable host-defined server identity profile.
// Duplicate IDs are rejected independently from client profile IDs.
func WithServerProfile(profile *ServerProfile) Option {
	return optionFunc(func(target *registration) error {
		if profile == nil || profile.id == 0 {
			return ErrInvalidServerProfile
		}
		target.serverProfiles = append(target.serverProfiles, profile)
		return nil
	})
}

// WithPolicy adds advanced TLS authority. Deny rules from any composition
// layer retain precedence, including applicable raw-TCP denies.
func WithPolicy(config wagonet.PolicyConfig) Option {
	return optionFunc(func(target *registration) error {
		target.authorityAdditions = policy.Merge(target.authorityAdditions, config)
		return nil
	})
}

// WithoutDefaultAuthority suppresses the ordinary outbound TLS grant.
func WithoutDefaultAuthority() Option {
	return optionFunc(func(target *registration) error { target.defaultAuthority = false; return nil })
}

// AllowLoopback permits otherwise granted TLS connections to loopback IPs. It
// does not grant raw-TCP loopback authority.
func AllowLoopback() Option {
	return WithPolicy(wagonet.PolicyConfig{LoopbackTransports: []wagonet.PolicyTransport{wagonet.PolicyTransportTLS}})
}

func defaultAuthority(client, server bool) policy.Config {
	directions := make([]policy.Direction, 0, 2)
	if client {
		directions = append(directions, policy.DirectionOutbound)
	}
	if server {
		directions = append(directions, policy.DirectionInbound)
	}
	if len(directions) == 0 {
		return policy.Config{}
	}
	return policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTLS}, Directions: directions,
	}}}
}

func (registration registration) authority() policy.Config {
	if !registration.defaultAuthority {
		return policy.Merge(registration.authorityAdditions)
	}
	return policy.Merge(defaultAuthority(len(registration.profiles) != 0, len(registration.serverProfiles) != 0), registration.authorityAdditions)
}

// Register selects only net.tls, wago_net_tls, and the private TLS transport.
// It never selects net.tcp or installs wago_net_tcp imports.
func Register(network *wagonet.Network, options ...Option) error {
	config := registration{config: DefaultConfig(), defaultAuthority: true}
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyTLS(&config); err != nil {
			return err
		}
	}
	if network == nil || !validConfig(config.config) || (len(config.profiles) == 0 && len(config.serverProfiles) == 0) || len(config.profiles) > MaximumClientProfiles || len(config.serverProfiles) > MaximumClientProfiles {
		return ErrInvalidConfig
	}
	profiles, err := compileProfiles(config.profiles, config.config)
	if err != nil {
		return err
	}
	serverProfiles, err := compileServerProfiles(config.serverProfiles, config.config)
	if err != nil {
		return err
	}
	maxListeners, acceptBacklog := uint16(0), uint16(0)
	if len(serverProfiles) != 0 {
		maxListeners, acceptBacklog = config.config.MaxListeners, config.config.AcceptBacklog
	}
	backendConfig := tlsbackend.Config{
		MaxStreams:                     config.config.MaxStreams,
		MaxListeners:                   maxListeners,
		AcceptBacklog:                  acceptBacklog,
		MaxConcurrentHandshakes:        config.config.MaxConcurrentHandshakes,
		MaxServerNameBytes:             config.config.MaxServerNameBytes,
		MaxServiceAttemptsPerHandshake: config.config.MaxServiceAttemptsPerHandshake,
		TCP: tcpbackend.Config{
			MaxListeners:       maxListeners,
			MaxOutboundStreams: config.config.MaxStreams,
			AcceptBacklog:      acceptBacklog,
			ReceiveBytes:       config.config.TransportReceiveBytes,
			TransmitBytes:      config.config.TransportTransmitBytes,
			TransmitPackets:    config.config.TransportTransmitPackets,
		},
		Engine: gotls.Limits{
			PlaintextReceiveBytes:          config.config.PlaintextReceiveBytes,
			PlaintextTransmitBytes:         config.config.PlaintextTransmitBytes,
			CiphertextReceiveBytes:         config.config.CiphertextReceiveBytes,
			CiphertextTransmitBytes:        config.config.CiphertextTransmitBytes,
			MaxHandshakeBytes:              config.config.MaxHandshakeBytes,
			MaxServiceAttemptsPerHandshake: config.config.MaxServiceAttemptsPerHandshake,
			MaxRecordsPerService:           int(config.config.MaxRecordsPerService),
		},
		Profiles: profiles, ServerProfiles: serverProfiles,
	}
	backend := plugin.NewBackend(plugin.BackendLnetoV1,
		func(target any) error {
			common, ok := target.(*lnetocore.Config)
			if !ok {
				return plugin.ErrInvalidBackend
			}
			if uint32(common.MaxActiveTCPPorts)+uint32(config.config.MaxStreams)+uint32(maxListeners) > uint32(^uint16(0)) {
				return plugin.ErrInvalidBackend
			}
			common.MaxActiveTCPPorts += config.config.MaxStreams + maxListeners
			return nil
		},
		func(base any) (nscore.Service, error) {
			common, ok := base.(*lnetocore.Namespace)
			if !ok {
				return nscore.Service{}, plugin.ErrInvalidBackend
			}
			adapter, err := tlsbackend.New(common, backendConfig)
			if err != nil {
				return nscore.Service{}, err
			}
			return nscore.Service{Key: tlsns.ServiceKey, Value: adapter}, nil
		},
	)
	module := tlsbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(config.authority()))
	return network.RegisterModule(module)
}

func compileServerProfiles(input []*ServerProfile, config Config) ([]gotls.ServerProfile, error) {
	profiles := make([]gotls.ServerProfile, 0, len(input))
	seen := make(map[uint32]struct{}, len(input))
	for _, profile := range input {
		if profile == nil || profile.id == 0 || profile.config == nil {
			return nil, ErrInvalidServerProfile
		}
		if _, exists := seen[profile.id]; exists {
			return nil, ErrInvalidServerProfile
		}
		seen[profile.id] = struct{}{}
		if len(profile.config.NextProtos) > int(config.MaxALPNProtocols) {
			return nil, ErrInvalidServerProfile
		}
		aggregate := 0
		for _, protocol := range profile.config.NextProtos {
			if len(protocol) > 32 {
				return nil, ErrInvalidServerProfile
			}
			aggregate += len(protocol)
		}
		if aggregate > int(config.MaxALPNAggregateBytes) {
			return nil, ErrInvalidServerProfile
		}
		chainBytes := 0
		for _, certificate := range profile.config.Certificates {
			for _, der := range certificate.Certificate {
				chainBytes += len(der)
				if chainBytes > config.MaxCertificateChainBytes {
					return nil, ErrInvalidServerProfile
				}
			}
		}
		profiles = append(profiles, gotls.ServerProfile{
			ID: profile.id, Config: profile.config.Clone(), RequiredALPN: profile.requiredALPN,
			MaxCertificateChainBytes: config.MaxCertificateChainBytes, MaxPeerCertificates: config.MaxPeerCertificates,
		})
	}
	return profiles, nil
}

func compileProfiles(input []*ClientProfile, config Config) ([]gotls.Profile, error) {
	profiles := make([]gotls.Profile, 0, len(input))
	seen := make(map[uint32]struct{}, len(input))
	for _, profile := range input {
		if profile == nil || profile.id == 0 {
			return nil, ErrInvalidProfile
		}
		if _, exists := seen[profile.id]; exists {
			return nil, ErrInvalidProfile
		}
		seen[profile.id] = struct{}{}
		if len(profile.config.NextProtos) > int(config.MaxALPNProtocols) {
			return nil, ErrInvalidProfile
		}
		aggregate := 0
		for _, protocol := range profile.config.NextProtos {
			if len(protocol) > 32 {
				return nil, ErrInvalidProfile
			}
			aggregate += len(protocol)
		}
		if aggregate > int(config.MaxALPNAggregateBytes) {
			return nil, ErrInvalidProfile
		}
		if len(profile.allowedNames) == 0 || len(profile.allowedNames) > MaximumServerNamesPerProfile {
			return nil, ErrInvalidProfile
		}
		allowed := make(map[string]tlsns.IdentityType, len(profile.allowedNames))
		for name, identity := range profile.allowedNames {
			if len(name) > int(config.MaxServerNameBytes) {
				return nil, ErrInvalidProfile
			}
			switch identity {
			case identityDNS:
				allowed[name] = tlsns.IdentityDNS
			case identityIP:
				allowed[name] = tlsns.IdentityIP
			default:
				return nil, ErrInvalidProfile
			}
		}
		profiles = append(profiles, gotls.Profile{
			ID: profile.id, Config: profile.config.Clone(), RequiredALPN: profile.requiredALPN,
			MaxCertificateChainBytes: config.MaxCertificateChainBytes,
			MaxPeerCertificates:      config.MaxPeerCertificates, AllowedNames: allowed,
		})
	}
	return profiles, nil
}
