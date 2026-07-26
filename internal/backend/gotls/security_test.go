package gotls

import (
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"runtime"
	"testing"
	"time"

	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
)

func TestServerProfileCloneOwnsSupportedSignatureAlgorithms(t *testing.T) {
	certificate, _ := testCertificate(t, "server.example.com")
	certificate.SupportedSignatureAlgorithms = []cryptotls.SignatureScheme{cryptotls.PSSWithSHA256}
	profile := ServerProfile{
		ID:                       1,
		Config:                   &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}},
		MaxCertificateChainBytes: 64 << 10,
		MaxPeerCertificates:      4,
	}
	cloned, err := profile.Clone()
	if err != nil {
		t.Fatal(err)
	}
	profile.Config.Certificates[0].SupportedSignatureAlgorithms[0] = cryptotls.ECDSAWithP256AndSHA256
	if got := cloned.Config.Certificates[0].SupportedSignatureAlgorithms[0]; got != cryptotls.PSSWithSHA256 {
		t.Fatalf("cloned signature algorithm = %v, want %v", got, cryptotls.PSSWithSHA256)
	}
}

func TestRequiredALPNMissingFailsAuthentication(t *testing.T) {
	certificate, roots := testCertificate(t, "api.example.com")
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
	go func() { _ = server.Handshake() }()
	profile := secureTestProfile(roots, "api.example.com")
	profile.Config.NextProtos = []string{"h2"}
	profile.RequiredALPN = "h2"
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitForFailure(t, client, nscore.FailureTLSAuthentication)
}

func TestUnknownRootFailsAuthentication(t *testing.T) {
	certificate, _ := testCertificate(t, "api.example.com")
	_, unrelatedRoots := testCertificate(t, "unrelated.example.com")
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
	go func() { _ = server.Handshake() }()
	profile := secureTestProfile(unrelatedRoots, "api.example.com")
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitForFailure(t, client, nscore.FailureTLSAuthentication)
}

func TestCertificateAndHandshakeByteLimitsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name                             string
		certificateLimit, handshakeLimit int
	}{
		{name: "certificate chain", certificateLimit: 1, handshakeLimit: 256 << 10},
		{name: "handshake bytes", certificateLimit: 64 << 10, handshakeLimit: 128},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, roots := testCertificate(t, "api.example.com")
			serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
			server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
			go func() { _ = server.Handshake() }()
			profile := secureTestProfile(roots, "api.example.com")
			profile.MaxCertificateChainBytes = test.certificateLimit
			limits := testLimits()
			limits.MaxHandshakeBytes = test.handshakeLimit
			client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			waitForFailure(t, client, nscore.FailureResourceLimit)
		})
	}
}

func TestWrongIPSANFailsAuthentication(t *testing.T) {
	verificationTime := time.Unix(1_800_000_000, 0)
	certificate, roots := testCertificateFields(t, nil, []net.IP{net.ParseIP("192.0.2.3")}, verificationTime.Add(-time.Hour), verificationTime.Add(time.Hour))
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
	go func() { _ = server.Handshake() }()
	profile := Profile{
		ID: 1, Config: &cryptotls.Config{RootCAs: roots, Time: func() time.Time { return verificationTime }, MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13},
		MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
		AllowedNames: map[string]tlsns.IdentityType{"192.0.2.2": tlsns.IdentityIP},
	}
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "192.0.2.2", tlsns.IdentityIP, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitForFailure(t, client, nscore.FailureTLSAuthentication)
}

func TestMissingAndInvalidIntermediateFailAuthentication(t *testing.T) {
	for _, test := range []struct {
		name                string
		invalidIntermediate bool
	}{
		{name: "missing intermediate"},
		{name: "invalid intermediate", invalidIntermediate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, roots := testCertificateChain(t, test.invalidIntermediate)
			serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
			server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
			go func() { _ = server.Handshake() }()
			profile := secureTestProfile(roots, "api.example.com")
			client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			waitForFailure(t, client, nscore.FailureTLSAuthentication)
		})
	}
}

func TestIPSubjectAlternativeNameVerification(t *testing.T) {
	verificationTime := time.Unix(1_800_000_000, 0)
	certificate, roots := testCertificateFields(t, nil, []net.IP{net.ParseIP("192.0.2.2")}, verificationTime.Add(-time.Hour), verificationTime.Add(time.Hour))
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
	go func() { _ = server.Handshake() }()
	profile := Profile{
		ID: 1, Config: &cryptotls.Config{RootCAs: roots, Time: func() time.Time { return verificationTime }, MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13},
		MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
		AllowedNames: map[string]tlsns.IdentityType{"192.0.2.2": tlsns.IdentityIP},
	}
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "192.0.2.2", tlsns.IdentityIP, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for attempt := 0; attempt < 1000000; attempt++ {
		progress, err := client.TryFinishConnect()
		if err != nil {
			t.Fatal(err)
		}
		if progress == nscore.ProgressDone {
			info, ok := client.ConnectionInfo()
			if !ok || info.VerifiedIdentity != tlsns.IdentityIP {
				t.Fatalf("info = %+v, %v", info, ok)
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("IP SAN handshake did not complete")
}

func TestCertificateValidityWindowIsEnforced(t *testing.T) {
	verificationTime := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name          string
		before, after time.Time
	}{
		{name: "expired", before: verificationTime.Add(-2 * time.Hour), after: verificationTime.Add(-time.Hour)},
		{name: "not yet valid", before: verificationTime.Add(time.Hour), after: verificationTime.Add(2 * time.Hour)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificate, roots := testCertificateFields(t, []string{"api.example.com"}, nil, test.before, test.after)
			serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
			server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
			go func() { _ = server.Handshake() }()
			profile := secureTestProfile(roots, "api.example.com")
			client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			waitForFailure(t, client, nscore.FailureTLSAuthentication)
		})
	}
}

func TestTLSVersionBelowMinimumFailsClosed(t *testing.T) {
	certificate, roots := testCertificate(t, "api.example.com")
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS12, MaxVersion: cryptotls.VersionTLS12})
	go func() { _ = server.Handshake() }()
	profile := secureTestProfile(roots, "api.example.com")
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitForFailure(t, client, nscore.FailureTLSProtocol)
}

func TestRawEOFWithoutCloseNotifyIsTLSProtocolFailure(t *testing.T) {
	client, server, transport := establishedTestPair(t)
	defer client.Close()
	_ = server
	transport.eof.Store(true)
	for attempt := 0; attempt < 1000000; attempt++ {
		_, _, _ = client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8})
		_, err := client.TryRead(make([]byte, 1))
		if err != nil {
			failure, ok := nscore.FailureOf(err)
			if !ok || failure != nscore.FailureTLSProtocol {
				t.Fatalf("failure = %v, %v", failure, err)
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("truncated TLS stream did not fail")
}

func TestCloseNotifyProducesStableEOFWithoutRepeatedServiceWork(t *testing.T) {
	client, server, transport := establishedTestPair(t)
	defer client.Close()
	closed := make(chan error, 1)
	go func() { closed <- server.CloseWrite() }()
	for attempt := 0; attempt < 1000000; attempt++ {
		_, _, _ = client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8})
		result, err := client.TryRead(make([]byte, 1))
		if err != nil {
			t.Fatal(err)
		}
		if result.State == nscore.IOEOF {
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			default:
			}
			transport.eof.Store(true)
			budget := nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8}
			for repeat := 0; repeat < 100; repeat++ {
				report, progress, err := client.TryService(budget)
				if err != nil || report != (nscore.ServiceReport{}) || progress != nscore.ProgressWouldBlock || !report.ValidResult(budget, progress) {
					t.Fatalf("clean EOF service %d = %+v, %v, %v", repeat, report, progress, err)
				}
				if ready := client.Readiness(); ready&nscore.ReadyReadable == 0 {
					t.Fatalf("clean EOF readiness %d = %v", repeat, ready)
				}
				stable, err := client.TryRead(make([]byte, 1))
				if err != nil || stable.State != nscore.IOEOF {
					t.Fatalf("stable EOF read %d = %+v, %v", repeat, stable, err)
				}
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("clean close_notify did not produce EOF")
}

func TestCorruptedRecordFailsTLSProtocol(t *testing.T) {
	client, _, _ := establishedTestPair(t)
	defer client.Close()
	// Invalid application-data record with a deliberately bad authentication tag.
	corrupt := []byte{23, 3, 3, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := client.bridge.feedCipher(corrupt); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 1000000; attempt++ {
		_, err := client.TryRead(make([]byte, 1))
		if err != nil {
			failure, ok := nscore.FailureOf(err)
			if !ok || failure != nscore.FailureTLSProtocol {
				t.Fatalf("failure = %v, %v", failure, err)
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("corrupted record did not fail")
}

func TestCloseDuringHandshakeJoinsWorkers(t *testing.T) {
	certificate, roots := testCertificate(t, "api.example.com")
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	_ = certificate
	profile := secureTestProfile(roots, "api.example.com")
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- client.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not join TLS workers")
	}
}

func establishedTestPair(t testing.TB) (*Stream, *cryptotls.Conn, *memoryTransport) {
	t.Helper()
	certificate, roots := testCertificate(t, "api.example.com")
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"}})
	serverDone := make(chan error, 1)
	go func() { err := server.Handshake(); serverBridge.finishHandshake(); serverDone <- err }()
	profile := secureTestProfile(roots, "api.example.com")
	profile.Config.NextProtos = []string{"h2"}
	profile.RequiredALPN = "h2"
	transport := &memoryTransport{peer: serverBridge}
	client, err := NewClient(transport, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 1000000; attempt++ {
		progress, err := client.TryFinishConnect()
		if err != nil {
			t.Fatal(err)
		}
		if progress == nscore.ProgressDone {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				_, _, _ = client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8})
				select {
				case err := <-serverDone:
					if err != nil {
						client.Close()
						t.Fatal(err)
					}
					return client, server, transport
				default:
					runtime.Gosched()
				}
			}
			client.Close()
			t.Fatal("server handshake did not finish")
		}
		runtime.Gosched()
	}
	client.Close()
	t.Fatal("handshake did not complete")
	return nil, nil, nil
}

func testCertificateChain(t testing.TB, invalidIntermediate bool) (cryptotls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "ignored"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"api.example.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{leafDER}
	if invalidIntermediate {
		unrelatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		unrelatedTemplate := &x509.Certificate{SerialNumber: big.NewInt(103), Subject: pkix.Name{CommonName: "unrelated"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		unrelatedDER, err := x509.CreateCertificate(rand.Reader, unrelatedTemplate, unrelatedTemplate, &unrelatedKey.PublicKey, unrelatedKey)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, unrelatedDER)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return cryptotls.Certificate{Certificate: chain, PrivateKey: leafKey}, roots
}

func secureTestProfile(roots *x509.CertPool, name string) Profile {
	pool := roots.Clone()
	verificationTime := time.Unix(1_800_000_000, 0)
	return Profile{
		ID: 1, Config: &cryptotls.Config{RootCAs: pool, Time: func() time.Time { return verificationTime }, MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13},
		MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
		AllowedNames: map[string]tlsns.IdentityType{name: tlsns.IdentityDNS},
	}
}

func waitForFailure(t testing.TB, client *Stream, want nscore.Failure) {
	t.Helper()
	for attempt := 0; attempt < 1000000; attempt++ {
		_, err := client.TryFinishConnect()
		if err != nil {
			failure, ok := nscore.FailureOf(err)
			if !ok || failure != want {
				t.Fatalf("failure = %v, want %v: %v", failure, want, err)
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("expected TLS failure did not arrive")
}
