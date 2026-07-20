package tls

import (
	cryptotls "crypto/tls"
	"testing"
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

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
