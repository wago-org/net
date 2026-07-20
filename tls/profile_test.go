package tls

import (
	"crypto/ed25519"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/wago-org/net/internal/policy"
)

func TestClientProfileDefaultsTLS13AndClones(t *testing.T) {
	config := &cryptotls.Config{NextProtos: []string{"h2"}}
	profile, err := NewClientProfile(1, config, AllowServerNames("API.Example.com."), RequireALPN("h2"))
	if err != nil {
		t.Fatal(err)
	}
	config.NextProtos[0] = "mutated"
	config.InsecureSkipVerify = true
	if profile.config.NextProtos[0] != "h2" || profile.config.InsecureSkipVerify {
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
	profile, err := NewServerProfile(7, config, RequireServerALPN("h2"))
	if err != nil {
		t.Fatal(err)
	}
	originalDER := append([]byte(nil), profile.config.Certificates[0].Certificate[0]...)
	config.NextProtos[0] = "mutated"
	config.Certificates[0].Certificate[0][0] ^= 0xff
	config.SessionTicketsDisabled = false
	if profile.ID() != 7 || profile.config.NextProtos[0] != "h2" || string(profile.config.Certificates[0].Certificate[0]) != string(originalDER) {
		t.Fatal("server profile retained caller mutation")
	}
	if profile.config.MinVersion != cryptotls.VersionTLS13 || profile.config.MaxVersion != cryptotls.VersionTLS13 || !profile.config.SessionTicketsDisabled {
		t.Fatalf("server profile defaults = %x..%x tickets-disabled=%v", profile.config.MinVersion, profile.config.MaxVersion, profile.config.SessionTicketsDisabled)
	}
	if _, err := NewServerProfile(8, &cryptotls.Config{}); err != ErrInvalidServerProfile {
		t.Fatalf("missing certificate = %v", err)
	}
}

func TestServerOnlyRegistrationAuthorityIsInboundAndProfileCompiles(t *testing.T) {
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
	if !compiled.CheckEndpoint(policy.OperationTLSListen, address, 8443) {
		t.Fatal("server profile did not grant inbound TLS authority")
	}
	if compiled.CheckEndpoint(policy.OperationTLSConnect, address, 8443) {
		t.Fatal("server-only profile granted outbound TLS authority")
	}
	profiles, err := compileServerProfiles(configuration.serverProfiles, configuration.config)
	if err != nil || len(profiles) != 1 || profiles[0].ID != 7 || profiles[0].RequiredALPN != "h2" {
		t.Fatalf("compiled server profiles = %+v, %v", profiles, err)
	}
}

func TestServerProfileRejectsUnsafeConfigurationAndRequiresTLS12OptIn(t *testing.T) {
	unsafe := testServerConfig(t)
	unsafe.GetCertificate = func(*cryptotls.ClientHelloInfo) (*cryptotls.Certificate, error) { return nil, nil }
	if _, err := NewServerProfile(1, unsafe); err != ErrUnsafeTLSConfig {
		t.Fatalf("dynamic certificate callback = %v", err)
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

func testServerConfig(t testing.TB) *cryptotls.Config {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"server.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"server.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &cryptotls.Config{Certificates: []cryptotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}, NextProtos: []string{"h2"}}
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
