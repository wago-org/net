package tls

import (
	cryptotls "crypto/tls"
	"crypto/x509"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/wago-org/net/internal/dnsname"
)

var (
	ErrInvalidProfile     = errors.New("wagonet/tls: invalid client profile")
	ErrUnsafeTLSConfig    = errors.New("wagonet/tls: unsafe TLS configuration")
	ErrUnauthorizedName   = errors.New("wagonet/tls: server name is not authorized")
	ErrTLS12RequiresOptIn = errors.New("wagonet/tls: TLS 1.2 requires explicit opt-in")
)

// ClientProfile is an effectively immutable host-defined TLS client profile.
// It never becomes guest memory; guests select only its numeric ID.
type ClientProfile struct {
	id           uint32
	config       *cryptotls.Config
	allowedNames map[string]identityKind
	requiredALPN string
	allowTLS12   bool
}

type identityKind uint8

const (
	identityDNS identityKind = iota + 1
	identityIP
)

// ClientProfileOption constrains one host-owned client profile.
type ClientProfileOption interface{ applyClientProfile(*profileBuilder) error }

type clientProfileOptionFunc func(*profileBuilder) error

func (option clientProfileOptionFunc) applyClientProfile(builder *profileBuilder) error {
	return option(builder)
}

type profileBuilder struct {
	allowedNames map[string]identityKind
	requiredALPN string
	allowTLS12   bool
}

// AllowServerNames authorizes exact normalized DNS names or canonical IP
// literals. The guest must select one of these identities before any network
// activity begins.
func AllowServerNames(names ...string) ClientProfileOption {
	copied := append([]string(nil), names...)
	return clientProfileOptionFunc(func(builder *profileBuilder) error {
		if len(copied) == 0 {
			return ErrInvalidProfile
		}
		if builder.allowedNames == nil {
			builder.allowedNames = make(map[string]identityKind, len(copied))
		}
		for _, name := range copied {
			normalized, kind, ok := normalizeIdentity(name)
			if !ok {
				return ErrInvalidProfile
			}
			builder.allowedNames[normalized] = kind
		}
		return nil
	})
}

// RequireALPN requires the peer to negotiate exactly protocol. Offered ALPN
// bytes are host-defined and are never taken from guest memory.
func RequireALPN(protocol string) ClientProfileOption {
	return clientProfileOptionFunc(func(builder *profileBuilder) error {
		if !validALPN(protocol) || builder.requiredALPN != "" {
			return ErrInvalidProfile
		}
		builder.requiredALPN = protocol
		return nil
	})
}

// EnableTLS12 is the conspicuous opt-in required before a profile may lower
// MinVersion to TLS 1.2. Go's safe default TLS 1.2 cipher suites remain in use.
func EnableTLS12() ClientProfileOption {
	return clientProfileOptionFunc(func(builder *profileBuilder) error {
		builder.allowTLS12 = true
		return nil
	})
}

// NewClientProfile validates and deeply clones a caller-owned crypto/tls
// configuration. Later mutation of the supplied config, trust pool, certificate
// slices, or ALPN slice cannot change the profile.
func NewClientProfile(id uint32, config *cryptotls.Config, options ...ClientProfileOption) (*ClientProfile, error) {
	if id == 0 || config == nil {
		return nil, ErrInvalidProfile
	}
	builder := profileBuilder{}
	for _, option := range options {
		if option == nil {
			return nil, ErrInvalidProfile
		}
		if err := option.applyClientProfile(&builder); err != nil {
			return nil, err
		}
	}
	if len(builder.allowedNames) == 0 {
		return nil, ErrInvalidProfile
	}
	cloned, err := cloneSafeConfig(config, builder.allowTLS12)
	if err != nil {
		return nil, err
	}
	if builder.requiredALPN != "" {
		if len(cloned.NextProtos) == 0 {
			cloned.NextProtos = []string{builder.requiredALPN}
		} else if !slices.Contains(cloned.NextProtos, builder.requiredALPN) {
			return nil, ErrInvalidProfile
		}
	}
	return &ClientProfile{id: id, config: cloned, allowedNames: builder.allowedNames, requiredALPN: builder.requiredALPN, allowTLS12: builder.allowTLS12}, nil
}

// ID returns the finite guest-selectable profile identifier.
func (profile *ClientProfile) ID() uint32 {
	if profile == nil {
		return 0
	}
	return profile.id
}

func (profile *ClientProfile) authorizeServerName(name string) (string, identityKind, error) {
	if profile == nil {
		return "", 0, ErrInvalidProfile
	}
	normalized, kind, ok := normalizeIdentity(name)
	if !ok || profile.allowedNames[normalized] != kind {
		return "", 0, ErrUnauthorizedName
	}
	return normalized, kind, nil
}

func cloneSafeConfig(input *cryptotls.Config, allowTLS12 bool) (*cryptotls.Config, error) {
	if input.InsecureSkipVerify || input.KeyLogWriter != nil || input.Renegotiation != cryptotls.RenegotiateNever ||
		input.VerifyPeerCertificate != nil || input.VerifyConnection != nil || input.GetClientCertificate != nil ||
		input.GetCertificate != nil || input.GetConfigForClient != nil || input.ClientSessionCache != nil ||
		input.UnwrapSession != nil || input.WrapSession != nil || input.Rand != nil || input.NameToCertificate != nil ||
		input.ClientAuth != cryptotls.NoClientCert || input.ClientCAs != nil || input.SessionTicketKey != ([32]byte{}) ||
		len(input.CipherSuites) != 0 || len(input.CurvePreferences) != 0 ||
		len(input.EncryptedClientHelloConfigList) != 0 || input.EncryptedClientHelloRejectionVerify != nil ||
		len(input.EncryptedClientHelloKeys) != 0 {
		return nil, ErrUnsafeTLSConfig
	}
	cloned := input.Clone()
	cloned.ServerName = ""
	cloned.InsecureSkipVerify = false
	cloned.KeyLogWriter = nil
	cloned.Renegotiation = cryptotls.RenegotiateNever
	cloned.ClientSessionCache = nil
	cloned.NextProtos = append([]string(nil), input.NextProtos...)
	for _, protocol := range cloned.NextProtos {
		if !validALPN(protocol) {
			return nil, ErrInvalidProfile
		}
	}
	if input.RootCAs != nil {
		cloned.RootCAs = input.RootCAs.Clone()
	}
	cloned.Certificates = cloneCertificates(input.Certificates)
	minVersion := cloned.MinVersion
	if minVersion == 0 {
		minVersion = cryptotls.VersionTLS13
	}
	if minVersion < cryptotls.VersionTLS12 {
		return nil, ErrUnsafeTLSConfig
	}
	if minVersion == cryptotls.VersionTLS12 && !allowTLS12 {
		return nil, ErrTLS12RequiresOptIn
	}
	if minVersion > cryptotls.VersionTLS13 {
		return nil, ErrInvalidProfile
	}
	cloned.MinVersion = minVersion
	if cloned.MaxVersion == 0 {
		cloned.MaxVersion = cryptotls.VersionTLS13
	}
	if cloned.MaxVersion < cloned.MinVersion || cloned.MaxVersion > cryptotls.VersionTLS13 {
		return nil, ErrInvalidProfile
	}
	return cloned, nil
}

func cloneCertificates(input []cryptotls.Certificate) []cryptotls.Certificate {
	out := make([]cryptotls.Certificate, len(input))
	for i := range input {
		out[i] = input[i]
		out[i].Certificate = make([][]byte, len(input[i].Certificate))
		for j := range input[i].Certificate {
			out[i].Certificate[j] = append([]byte(nil), input[i].Certificate[j]...)
		}
		out[i].OCSPStaple = append([]byte(nil), input[i].OCSPStaple...)
		out[i].SignedCertificateTimestamps = make([][]byte, len(input[i].SignedCertificateTimestamps))
		for j := range input[i].SignedCertificateTimestamps {
			out[i].SignedCertificateTimestamps[j] = append([]byte(nil), input[i].SignedCertificateTimestamps[j]...)
		}
		if input[i].Leaf != nil {
			out[i].Leaf = cloneCertificate(input[i].Leaf)
		}
	}
	return out
}

func cloneCertificate(input *x509.Certificate) *x509.Certificate {
	if input == nil {
		return nil
	}
	// Parsing Raw creates an independent standard-library representation while
	// avoiding a fragile hand-maintained copy of x509.Certificate's slices.
	if len(input.Raw) != 0 {
		if parsed, err := x509.ParseCertificate(append([]byte(nil), input.Raw...)); err == nil {
			return parsed
		}
	}
	// A malformed or synthetic Leaf is not retained: crypto/tls can safely parse
	// the independently cloned certificate DER when it needs a leaf.
	return nil
}

func normalizeIdentity(name string) (string, identityKind, bool) {
	if name == "" || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return "", 0, false
	}
	if address, err := netip.ParseAddr(name); err == nil && address.Zone() == "" && !address.Is4In6() && !address.IsUnspecified() {
		return address.String(), identityIP, true
	}
	normalized, ok := dnsname.Normalize(name)
	if !ok {
		return "", 0, false
	}
	return normalized, identityDNS, true
}

func validALPN(protocol string) bool {
	return len(protocol) > 0 && len(protocol) <= 255 && utf8.ValidString(protocol)
}
