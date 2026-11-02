package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"crypto/x509"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/wago-org/net/internal/policy"
)

func TestClientProfileDefaultsTLS13AndClones(t *testing.T) {
	config := testServerConfig(t)
	config.Certificates[0].SupportedSignatureAlgorithms = []cryptotls.SignatureScheme{cryptotls.Ed25519}
	profile, err := NewClientProfile(1, config, AllowServerNames("API.Example.com."), RequireALPN("h2"))
	if err != nil {
		t.Fatal(err)
	}
	config.NextProtos[0] = "mutated"
	config.Certificates[0].SupportedSignatureAlgorithms[0] = cryptotls.ECDSAWithP256AndSHA256
	config.InsecureSkipVerify = true
	if profile.config.NextProtos[0] != "h2" || profile.config.InsecureSkipVerify ||
		profile.config.Certificates[0].SupportedSignatureAlgorithms[0] != cryptotls.Ed25519 {
		t.Fatal("profile retained caller mutation")
	}
	if profile.config.MinVersion != cryptotls.VersionTLS13 || profile.config.MaxVersion != cryptotls.VersionTLS13 {
		t.Fatalf("versions = %x..%x", profile.config.MinVersion, profile.config.MaxVersion)
	}
	if name, kind, err := profile.authorizeServerName("api.example.com"); err != nil || name != "api.example.com" || kind != identityDNS {
		t.Fatalf("authorize = %q, %v, %v", name, kind, err)
	}
}

func TestClientProfileRejectsUnsafeConfiguration(t *testing.T) {
	unsafe := []*cryptotls.Config{
		{InsecureSkipVerify: true},
		{KeyLogWriter: discardWriter{}},
		{Renegotiation: cryptotls.RenegotiateOnceAsClient},
		{VerifyConnection: func(cryptotls.ConnectionState) error { return nil }},
		{Time: func() time.Time { return time.Now() }},
		{ClientSessionCache: cryptotls.NewLRUClientSessionCache(1)},
		{WrapSession: func(cryptotls.ConnectionState, *cryptotls.SessionState) ([]byte, error) { return nil, nil }},
		{CipherSuites: []uint16{cryptotls.TLS_RSA_WITH_AES_128_CBC_SHA}},
	}
	for _, config := range unsafe {
		if _, err := NewClientProfile(1, config, AllowServerNames("example.com")); err != ErrUnsafeTLSConfig {
			t.Fatalf("config %+v: %v", config, err)
		}
	}
}

func TestProfilesUseOnlyPackageOwnedFrozenValidationTime(t *testing.T) {
	configured := time.Date(2030, 5, 6, 7, 8, 9, 10, time.FixedZone("caller", 3600))
	client, err := NewClientProfile(1, &cryptotls.Config{}, AllowServerNames("example.com"), ValidationTime(configured))
	if err != nil {
		t.Fatal(err)
	}
	if client.config.Time == nil {
		t.Fatal("client validation time callback missing")
	}
	if got := client.config.Time(); !got.Equal(configured) || got.Location() != time.UTC {
		t.Fatalf("client validation time = %v", got)
	}
	server, err := NewServerProfile(1, testServerConfig(t), ValidationTime(configured))
	if err != nil {
		t.Fatal(err)
	}
	if server.config.Time == nil {
		t.Fatal("server validation time callback missing")
	}
	if got := server.config.Time(); !got.Equal(configured) || got.Location() != time.UTC {
		t.Fatalf("server validation time = %v", got)
	}
	if _, err := NewClientProfile(1, &cryptotls.Config{}, AllowServerNames("example.com"), ValidationTime(time.Time{})); err != ErrInvalidProfile {
		t.Fatalf("zero client validation time = %v", err)
	}
	if _, err := NewServerProfile(1, testServerConfig(t), ValidationTime(time.Time{})); err != ErrInvalidServerProfile {
		t.Fatalf("zero server validation time = %v", err)
	}
	if _, err := NewClientProfile(1, &cryptotls.Config{}, AllowServerNames("example.com"), ValidationTime(configured), ValidationTime(configured)); err != ErrInvalidProfile {
		t.Fatalf("duplicate client validation time = %v", err)
	}
	if _, err := NewServerProfile(1, testServerConfig(t), ValidationTime(configured), ValidationTime(configured)); err != ErrInvalidServerProfile {
		t.Fatalf("duplicate server validation time = %v", err)
	}
}

func TestClientProfileEnablesOnlyBoundedInternalSessionResumption(t *testing.T) {
	profile, err := NewClientProfile(1, &cryptotls.Config{}, AllowServerNames("example.com"), EnableClientSessionResumption(4, 128<<10))
	if err != nil {
		t.Fatal(err)
	}
	if profile.config.ClientSessionCache != nil || profile.maxClientSessionEntries != 4 || profile.maxClientSessionBytes != 128<<10 {
		t.Fatalf("resumption profile = cache %T entries %d bytes %d", profile.config.ClientSessionCache, profile.maxClientSessionEntries, profile.maxClientSessionBytes)
	}
	for name, option := range map[string]ClientProfileOption{
		"zero entries":     EnableClientSessionResumption(0, 1),
		"zero bytes":       EnableClientSessionResumption(1, 0),
		"too many entries": EnableClientSessionResumption(MaximumClientSessionEntries+1, 1),
		"too many bytes":   EnableClientSessionResumption(1, int(MaximumClientSessionBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClientProfile(1, &cryptotls.Config{}, AllowServerNames("example.com"), option); err != ErrInvalidProfile {
				t.Fatalf("invalid resumption bounds = %v", err)
			}
		})
	}
	if _, err := NewClientProfile(1, &cryptotls.Config{}, AllowServerNames("example.com"), EnableClientSessionResumption(1, 1024), EnableClientSessionResumption(1, 1024)); err != ErrInvalidProfile {
		t.Fatalf("duplicate resumption option = %v", err)
	}
}

func TestClientProfileRequiresTLS12OptInAndExactIdentity(t *testing.T) {
	config := &cryptotls.Config{MinVersion: cryptotls.VersionTLS12}
	if _, err := NewClientProfile(1, config, AllowServerNames("192.0.2.10")); err != ErrTLS12RequiresOptIn {
		t.Fatalf("without opt-in: %v", err)
	}
	profile, err := NewClientProfile(1, config, AllowServerNames("192.0.2.10"), EnableTLS12())
	if err != nil {
		t.Fatal(err)
	}
	if _, kind, err := profile.authorizeServerName("192.0.2.10"); err != nil || kind != identityIP {
		t.Fatalf("IP authorization: %v, %v", kind, err)
	}
	if _, _, err := profile.authorizeServerName("example.com"); err != ErrUnauthorizedName {
		t.Fatalf("wrong identity: %v", err)
	}
}

func TestServerProfileDefaultsTLS13ClonesAndRequiresStaticCertificate(t *testing.T) {
	config := testServerConfig(t)
	config.Certificates[0].SupportedSignatureAlgorithms = []cryptotls.SignatureScheme{cryptotls.Ed25519}
	profile, err := NewServerProfile(7, config, RequireServerALPN("h2"))
	if err != nil {
		t.Fatal(err)
	}
	originalDER := append([]byte(nil), profile.config.Certificates[0].Certificate[0]...)
	config.NextProtos[0] = "mutated"
	config.Certificates[0].Certificate[0][0] ^= 0xff
	config.Certificates[0].SupportedSignatureAlgorithms[0] = cryptotls.ECDSAWithP256AndSHA256
	config.SessionTicketsDisabled = false
	if profile.ID() != 7 || profile.config.NextProtos[0] != "h2" || string(profile.config.Certificates[0].Certificate[0]) != string(originalDER) ||
		profile.config.Certificates[0].SupportedSignatureAlgorithms[0] != cryptotls.Ed25519 {
		t.Fatal("server profile retained caller mutation")
	}
	if profile.config.MinVersion != cryptotls.VersionTLS13 || profile.config.MaxVersion != cryptotls.VersionTLS13 || !profile.config.SessionTicketsDisabled {
		t.Fatalf("server profile defaults = %x..%x tickets-disabled=%v", profile.config.MinVersion, profile.config.MaxVersion, profile.config.SessionTicketsDisabled)
	}
	if _, err := NewServerProfile(8, &cryptotls.Config{}); err != ErrInvalidServerProfile {
		t.Fatalf("missing certificate = %v", err)
	}
}

func TestServerProfileEnablesExplicitBoundedSessionTicketKeys(t *testing.T) {
	first, second := [32]byte{1}, [32]byte{2}
	profile, err := NewServerProfile(7, testServerConfig(t), EnableServerSessionTickets(first, second))
	if err != nil {
		t.Fatal(err)
	}
	if profile.config.SessionTicketsDisabled {
		t.Fatal("explicit server session tickets remained disabled")
	}
	for name, option := range map[string]ServerProfileOption{
		"empty":     EnableServerSessionTickets(),
		"zero key":  EnableServerSessionTickets([32]byte{}),
		"duplicate": EnableServerSessionTickets(first, first),
		"too many":  EnableServerSessionTickets(first, second, [32]byte{3}, [32]byte{4}, [32]byte{5}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewServerProfile(7, testServerConfig(t), option); err != ErrInvalidServerProfile {
				t.Fatalf("invalid ticket keys = %v", err)
			}
		})
	}
	if _, err := NewServerProfile(7, testServerConfig(t), EnableServerSessionTickets(first), EnableServerSessionTickets(second)); err != ErrInvalidServerProfile {
		t.Fatalf("duplicate ticket option = %v", err)
	}
}

func TestServerProfileStorageRequiresExplicitListenerAuthority(t *testing.T) {
	profile, err := NewServerProfile(7, testServerConfig(t), RequireServerALPN("h2"))
	if err != nil {
		t.Fatal(err)
	}
	configuration := registration{config: DefaultConfig(), serverProfiles: []*ServerProfile{profile}, defaultAuthority: true}
	compiled, err := policy.Compile(configuration.authority())
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("192.0.2.20")
	if compiled.CheckEndpoint(policy.OperationTLSListen, address, 8443) {
		t.Fatal("server profile storage implicitly granted inbound TLS authority")
	}
	if err := AllowListeners().applyTLS(&configuration); err != nil {
		t.Fatal(err)
	}
	compiled, err = policy.Compile(configuration.authority())
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.CheckEndpoint(policy.OperationTLSListen, address, 8443) {
		t.Fatal("explicit listener authority did not grant inbound TLS")
	}
	if compiled.CheckEndpoint(policy.OperationTCPListen, address, 8443) {
		t.Fatal("explicit TLS listener authority widened raw TCP listen")
	}
	if compiled.CheckEndpoint(policy.OperationTLSConnect, address, 8443) {
		t.Fatal("server-only profile granted outbound TLS authority")
	}
	profiles, err := compileServerProfiles(configuration.serverProfiles, configuration.config)
	if err != nil || len(profiles) != 1 || profiles[0].ID != 7 || profiles[0].RequiredALPN != "h2" {
		t.Fatalf("compiled server profiles = %+v, %v", profiles, err)
	}
}

func TestProfilesAcceptOnlyStandardSoftwareSignerFamilies(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, signer := range map[string]crypto.Signer{
		"ed25519": ed25519Key,
		"ecdsa":   ecdsaKey,
		"rsa":     rsaKey,
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfigForSigner(t, signer)
			if _, err := NewClientProfile(1, config, AllowServerNames("example.com")); err != nil {
				t.Fatalf("client profile = %v", err)
			}
			if _, err := NewServerProfile(1, config); err != nil {
				t.Fatalf("server profile = %v", err)
			}
		})
	}
}

func TestClientProfileRejectsMalformedChainsMismatchedAndExternalSigners(t *testing.T) {
	malformed := testServerConfig(t)
	malformed.Certificates[0].Certificate[0] = []byte{1, 2, 3}
	if _, err := NewClientProfile(1, malformed, AllowServerNames("example.com")); err != ErrInvalidProfile {
		t.Fatalf("malformed client certificate = %v", err)
	}

	mismatched := testServerConfig(t)
	_, otherSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatched.Certificates[0].PrivateKey = otherSigner
	if _, err := NewClientProfile(1, mismatched, AllowServerNames("example.com")); err != ErrInvalidProfile {
		t.Fatalf("mismatched client signer = %v", err)
	}

	wrapped := testServerConfig(t)
	wrapped.Certificates[0].PrivateKey = externalSigner{Signer: wrapped.Certificates[0].PrivateKey.(crypto.Signer)}
	if _, err := NewClientProfile(1, wrapped, AllowServerNames("example.com")); err != ErrUnsafeTLSConfig {
		t.Fatalf("external client signer = %v", err)
	}
}

func TestServerProfileRejectsMalformedChainAndMismatchedSigner(t *testing.T) {
	malformed := testServerConfig(t)
	malformed.Certificates[0].Certificate[0] = []byte{1, 2, 3}
	if _, err := NewServerProfile(1, malformed); err != ErrInvalidServerProfile {
		t.Fatalf("malformed leaf = %v", err)
	}

	mismatched := testServerConfig(t)
	_, otherSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatched.Certificates[0].PrivateKey = otherSigner
	if _, err := NewServerProfile(1, mismatched); err != ErrInvalidServerProfile {
		t.Fatalf("mismatched signer = %v", err)
	}

	brokenChain := testServerConfig(t)
	other := testServerConfig(t)
	brokenChain.Certificates[0].Certificate = append(brokenChain.Certificates[0].Certificate, other.Certificates[0].Certificate[0])
	if _, err := NewServerProfile(1, brokenChain); err != ErrInvalidServerProfile {
		t.Fatalf("broken chain = %v", err)
	}

	wrapped := testServerConfig(t)
	wrapped.Certificates[0].PrivateKey = externalSigner{Signer: wrapped.Certificates[0].PrivateKey.(crypto.Signer)}
	if _, err := NewServerProfile(1, wrapped); err != ErrUnsafeTLSConfig {
		t.Fatalf("external server signer = %v", err)
	}
}

func TestServerProfileRejectsUnsafeConfigurationAndRequiresTLS12OptIn(t *testing.T) {
	unsafe := testServerConfig(t)
	unsafe.GetCertificate = func(*cryptotls.ClientHelloInfo) (*cryptotls.Certificate, error) { return nil, nil }
	if _, err := NewServerProfile(1, unsafe); err != ErrUnsafeTLSConfig {
		t.Fatalf("dynamic certificate callback = %v", err)
	}
	unsafeClock := testServerConfig(t)
	unsafeClock.Time = func() time.Time { return time.Now() }
	if _, err := NewServerProfile(1, unsafeClock); err != ErrUnsafeTLSConfig {
		t.Fatalf("dynamic clock callback = %v", err)
	}
	invalidClientAuth := testServerConfig(t)
	invalidClientAuth.ClientAuth = cryptotls.RequireAndVerifyClientCert
	if _, err := NewServerProfile(1, invalidClientAuth); err != ErrInvalidServerProfile {
		t.Fatalf("client auth without roots = %v", err)
	}
	tls12 := testServerConfig(t)
	tls12.MinVersion = cryptotls.VersionTLS12
	if _, err := NewServerProfile(1, tls12); err != ErrTLS12RequiresOptIn {
		t.Fatalf("TLS 1.2 without opt-in = %v", err)
	}
	if _, err := NewServerProfile(1, tls12, EnableServerTLS12()); err != nil {
		t.Fatalf("TLS 1.2 with opt-in = %v", err)
	}
}

type externalSigner struct {
	crypto.Signer
}

func testServerConfig(t testing.TB) *cryptotls.Config {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testConfigForSigner(t, privateKey)
}

func testConfigForSigner(t testing.TB, signer crypto.Signer) *cryptotls.Config {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"server.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return &cryptotls.Config{Certificates: []cryptotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: signer}}, NextProtos: []string{"h2"}}
}

func TestAllowLoopbackRegistrationAuthorityIsTLSScoped(t *testing.T) {
	configuration := registration{config: DefaultConfig(), profiles: []*ClientProfile{{id: 1}}, defaultAuthority: true}
	if err := AllowLoopback().applyTLS(&configuration); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.Compile(configuration.authority())
	if err != nil {
		t.Fatal(err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	if !compiled.CheckEndpoint(policy.OperationTLSConnect, loopback, 443) {
		t.Fatal("public TLS registration option did not grant TLS loopback")
	}
	if compiled.CheckEndpoint(policy.OperationTCPConnect, loopback, 443) {
		t.Fatal("public TLS registration option widened raw TCP loopback")
	}
}

func FuzzServerNameNormalizationAndAuthorization(f *testing.F) {
	f.Add("api.example.com")
	f.Add("192.0.2.10")
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 512 {
			name = name[:512]
		}
		profile, err := NewClientProfile(1, &cryptotls.Config{}, AllowServerNames("api.example.com", "192.0.2.10"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, _ = profile.authorizeServerName(name)
	})
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
