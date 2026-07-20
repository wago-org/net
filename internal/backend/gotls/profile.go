package gotls

import (
	cryptotls "crypto/tls"
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/wago-org/net/internal/dnsname"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
)

var (
	ErrInvalidConfig    = errors.New("net/tls: invalid engine configuration")
	ErrHandshakeLimit   = errors.New("net/tls: handshake byte limit exceeded")
	ErrCertificateLimit = errors.New("net/tls: certificate limit exceeded")
	ErrALPN             = errors.New("net/tls: required ALPN was not negotiated")
)

// Profile is an internal immutable crypto/tls client profile. Config must
// already have passed the public fail-closed validation and cloning step.
type Profile struct {
	ID                       uint32
	Config                   *cryptotls.Config
	RequiredALPN             string
	MaxCertificateChainBytes int
	MaxPeerCertificates      uint16
	AllowedNames             map[string]tlsns.IdentityType
}

func (profile Profile) Clone() (Profile, error) {
	if profile.ID == 0 || profile.Config == nil || profile.MaxCertificateChainBytes <= 0 || profile.MaxPeerCertificates == 0 {
		return Profile{}, ErrInvalidConfig
	}
	cloned := profile
	cloned.Config = profile.Config.Clone()
	cloned.Config.NextProtos = append([]string(nil), profile.Config.NextProtos...)
	cloned.AllowedNames = make(map[string]tlsns.IdentityType, len(profile.AllowedNames))
	for name, identity := range profile.AllowedNames {
		if identity != tlsns.IdentityDNS && identity != tlsns.IdentityIP {
			return Profile{}, ErrInvalidConfig
		}
		cloned.AllowedNames[name] = identity
	}
	if len(cloned.AllowedNames) == 0 {
		return Profile{}, ErrInvalidConfig
	}
	if profile.Config.RootCAs != nil {
		cloned.Config.RootCAs = profile.Config.RootCAs.Clone()
	}
	return cloned, nil
}

// AuthorizeServerName normalizes one guest-selected verification identity and
// checks exact host authority before any transport is created.
func (profile Profile) AuthorizeServerName(name string) (string, tlsns.IdentityType, bool) {
	if name == "" || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return "", 0, false
	}
	if address, err := netip.ParseAddr(name); err == nil && !address.Is4In6() && !address.IsUnspecified() {
		normalized := address.String()
		identity := tlsns.IdentityIP
		return normalized, identity, profile.AllowedNames[normalized] == identity
	}
	normalized, ok := dnsname.Normalize(name)
	if !ok {
		return "", 0, false
	}
	identity := tlsns.IdentityDNS
	return normalized, identity, profile.AllowedNames[normalized] == identity
}

// Limits fixes all worker-owned queues and one bounded transport pump.
type Limits struct {
	PlaintextReceiveBytes          int
	PlaintextTransmitBytes         int
	CiphertextReceiveBytes         int
	CiphertextTransmitBytes        int
	MaxHandshakeBytes              int
	MaxServiceAttemptsPerHandshake uint32
	MaxRecordsPerService           int
}

func (limits Limits) valid() bool {
	return limits.PlaintextReceiveBytes > 0 && limits.PlaintextTransmitBytes > 0 &&
		limits.CiphertextReceiveBytes >= 17<<10 && limits.CiphertextTransmitBytes >= 17<<10 &&
		limits.MaxHandshakeBytes > 0 && limits.MaxServiceAttemptsPerHandshake > 0 &&
		limits.MaxRecordsPerService > 0 && limits.MaxRecordsPerService <= 256
}
