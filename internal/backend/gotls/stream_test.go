package gotls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
)

func TestClientHandshakeVerificationALPNAndPlaintext(t *testing.T) {
	certificate, roots := testCertificate(t, "api.example.com")
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{
		Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13,
		MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"},
	})
	serverDone := make(chan error, 1)
	go func() {
		err := server.Handshake()
		serverBridge.finishHandshake()
		serverDone <- err
	}()

	verificationTime := time.Unix(1_800_000_000, 0)
	profile := Profile{
		ID:           1,
		Config:       &cryptotls.Config{RootCAs: roots, Time: func() time.Time { return verificationTime }, MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"}},
		RequiredALPN: "h2", MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
		AllowedNames: map[string]tlsns.IdentityType{"api.example.com": tlsns.IdentityDNS},
	}
	transport := &memoryTransport{
		peer: serverBridge, readLimit: 13, writeLimit: 11,
		finishErrorAfterReady: nscore.Fail(nscore.FailureConnectionRefused, net.ErrClosed),
	}
	t.Cleanup(func() {
		if calls := transport.finishCalls.Load(); calls != 1 {
			t.Errorf("transport finish-connect calls = %d, want 1", calls)
		}
	})
	client, err := NewClient(transport, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
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
			break
		}
		runtime.Gosched()
		if attempt == 999999 {
			client.mu.Lock()
			terminal, verified := client.terminal, client.verified
			client.mu.Unlock()
			t.Fatalf("handshake did not complete: ready=%v terminal=%v verified=%v client-out=%d server-out=%d", client.Readiness(), terminal, verified, client.bridge.cipherPending(), serverBridge.cipherPending())
		}
	}
	serverDeadline := time.NewTimer(2 * time.Second)
	defer serverDeadline.Stop()
	for {
		if _, _, err := client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-serverDone:
			if err != nil {
				t.Fatal(err)
			}
			goto serverHandshakeComplete
		case <-serverDeadline.C:
			t.Fatalf("server handshake did not receive final client flight: client-out=%d server-out=%d", client.bridge.cipherPending(), serverBridge.cipherPending())
		default:
			runtime.Gosched()
		}
	}

serverHandshakeComplete:
	info, ok := client.ConnectionInfo()
	if !ok || info.NegotiatedALPN != "h2" || info.TLSVersion != cryptotls.VersionTLS13 || info.PeerLeafSPKI256 == ([32]byte{}) {
		t.Fatalf("connection info = %+v, %v", info, ok)
	}
	binding, ok := client.ChannelBinding()
	peerState := server.ConnectionState()
	peerBinding, exportErr := peerState.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, tlsns.ChannelBindingBytes)
	if !ok || exportErr != nil || !bytes.Equal(binding[:], peerBinding) {
		t.Fatalf("channel binding = %x, %v; peer=%x, %v", binding, ok, peerBinding, exportErr)
	}

	serverRead := make(chan string, 1)
	go func() {
		buffer := make([]byte, 5)
		count, _ := server.Read(buffer)
		serverRead <- string(buffer[:count])
	}()
	result, err := client.TryWrite([]byte("hello"))
	if err != nil || result.Bytes != 5 {
		t.Fatalf("write = %+v, %v", result, err)
	}
	for attempt := 0; attempt < 10000; attempt++ {
		_, _, _ = client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8})
		select {
		case got := <-serverRead:
			if got != "hello" {
				t.Fatalf("server read %q", got)
			}
			return
		default:
			runtime.Gosched()
		}
	}
	t.Fatal("plaintext did not reach peer")
}

func TestServerHandshakeALPNAndPlaintext(t *testing.T) {
	certificate, roots := testCertificate(t, "server.example.com")
	clientBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	client := cryptotls.Client(clientBridge, &cryptotls.Config{
		RootCAs: roots, ServerName: "server.example.com", Time: func() time.Time { return time.Unix(1_800_000_000, 0) }, MinVersion: cryptotls.VersionTLS13,
		MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"},
	})
	clientDone := make(chan error, 1)
	go func() {
		err := client.Handshake()
		clientBridge.finishHandshake()
		clientDone <- err
	}()

	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 49152}
	profile := ServerProfile{
		ID: 9,
		Config: &cryptotls.Config{
			Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13,
			MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"},
		},
		RequiredALPN: "h2", MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
	}
	transport := &memoryTransport{
		peer: clientBridge, local: local, remote: remote, readLimit: 13, writeLimit: 11,
		finishErrorAfterReady: nscore.Fail(nscore.FailureConnectionRefused, net.ErrClosed),
	}
	t.Cleanup(func() {
		if calls := transport.finishCalls.Load(); calls != 1 {
			t.Errorf("transport finish-connect calls = %d, want 1", calls)
		}
	})
	server, err := NewServer(transport, profile, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for attempt := 0; attempt < 1000000; attempt++ {
		progress, err := server.TryFinishConnect()
		if err != nil {
			t.Fatal(err)
		}
		if progress == nscore.ProgressDone {
			break
		}
		runtime.Gosched()
		if attempt == 999999 {
			t.Fatal("server handshake did not complete")
		}
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	info, ok := server.ConnectionInfo()
	if !ok || info.Role != tlsns.RoleServer || info.PeerAuthenticated || info.NegotiatedALPN != "h2" || info.LocalEndpoint != local || info.RemoteEndpoint != remote {
		t.Fatalf("server connection info = %+v, %v", info, ok)
	}
	binding, ok := server.ChannelBinding()
	peerState := client.ConnectionState()
	peerBinding, exportErr := peerState.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, tlsns.ChannelBindingBytes)
	if !ok || exportErr != nil || !bytes.Equal(binding[:], peerBinding) {
		t.Fatalf("server channel binding = %x, %v; peer=%x, %v", binding, ok, peerBinding, exportErr)
	}

	clientWrite := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello"))
		clientWrite <- err
	}()
	buffer := make([]byte, 5)
	for attempt := 0; attempt < 100000; attempt++ {
		_, _, _ = server.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8})
		result, err := server.TryRead(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if result.State == nscore.IOReady && result.Bytes != 0 {
			if string(buffer[:result.Bytes]) != "hello" {
				t.Fatalf("server plaintext = %q", buffer[:result.Bytes])
			}
			if err := <-clientWrite; err != nil {
				t.Fatal(err)
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("client plaintext did not reach bounded TLS server")
}

func TestServerStaticSNISelectsMatchingImmutableCertificate(t *testing.T) {
	alpha, _ := testCertificate(t, "alpha.example.com")
	beta, _ := testCertificate(t, "beta.example.com")
	roots := x509.NewCertPool()
	for _, certificate := range []cryptotls.Certificate{alpha, beta} {
		parsed, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		roots.AddCert(parsed)
	}
	clientBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	client := cryptotls.Client(clientBridge, &cryptotls.Config{
		RootCAs: roots, ServerName: "beta.example.com", Time: func() time.Time { return time.Unix(1_800_000_000, 0) },
		MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13,
	})
	clientDone := make(chan error, 1)
	go func() {
		err := client.Handshake()
		clientBridge.finishHandshake()
		clientDone <- err
	}()
	server, err := NewServer(&memoryTransport{peer: clientBridge}, ServerProfile{
		ID: 1,
		Config: &cryptotls.Config{
			Certificates: []cryptotls.Certificate{alpha, beta},
			MinVersion:   cryptotls.VersionTLS13,
			MaxVersion:   cryptotls.VersionTLS13,
		},
		MaxCertificateChainBytes: 64 << 10,
		MaxPeerCertificates:      4,
	}, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for attempt := 0; attempt < 1000000; attempt++ {
		progress, err := server.TryFinishConnect()
		if err != nil {
			t.Fatal(err)
		}
		if progress == nscore.ProgressDone {
			break
		}
		runtime.Gosched()
		if attempt == 999999 {
			t.Fatal("SNI handshake did not complete")
		}
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, beta.Certificate[0]) {
		t.Fatalf("SNI selected peer certificates = %d", len(state.PeerCertificates))
	}
}

func TestTransportEOFConsumesExactlyOneServiceOperation(t *testing.T) {
	peer := newBridgeConn(32, 32, 64)
	transport := &memoryTransport{peer: peer}
	transport.eof.Store(true)
	limits := testLimits()
	stream := &Stream{
		transport:     transport,
		bridge:        newBridgeConn(limits.CiphertextReceiveBytes, limits.CiphertextTransmitBytes, limits.MaxHandshakeBytes),
		limits:        limits,
		cipherScratch: make([]byte, CiphertextScratchBytes),
		verified:      true,
	}
	stream.cond = sync.NewCond(&stream.mu)
	budget := nscore.ServiceBudget{Packets: 2, Bytes: 1024, Operations: 2}
	report, progress, err := stream.TryService(budget)
	if err != nil || report != (nscore.ServiceReport{Operations: 1}) || progress != nscore.ProgressDone || !report.ValidResult(budget, progress) {
		t.Fatalf("first EOF service = %+v, %v, %v", report, progress, err)
	}
	report, progress, err = stream.TryService(budget)
	if err != nil || report != (nscore.ServiceReport{}) || progress != nscore.ProgressWouldBlock || !report.ValidResult(budget, progress) {
		t.Fatalf("repeated EOF service = %+v, %v, %v", report, progress, err)
	}
}

func TestClientRejectsWrongHostname(t *testing.T) {
	certificate, roots := testCertificate(t, "other.example.com")
	serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
	server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13})
	go func() { _ = server.Handshake() }()
	verificationTime := time.Unix(1_800_000_000, 0)
	profile := Profile{
		ID: 1, Config: &cryptotls.Config{RootCAs: roots, Time: func() time.Time { return verificationTime }, MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13},
		MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
		AllowedNames: map[string]tlsns.IdentityType{"api.example.com": tlsns.IdentityDNS},
	}
	client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for attempt := 0; attempt < 1000000; attempt++ {
		_, err = client.TryFinishConnect()
		if err != nil {
			failure, ok := nscore.FailureOf(err)
			if !ok || failure != nscore.FailureTLSAuthentication {
				t.Fatalf("failure = %v, %v", failure, err)
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("wrong hostname was not rejected")
}

func testLimits() Limits {
	return Limits{
		PlaintextReceiveBytes: 16 << 10, PlaintextTransmitBytes: 16 << 10,
		CiphertextReceiveBytes: 32 << 10, CiphertextTransmitBytes: 32 << 10,
		MaxHandshakeBytes: 256 << 10, MaxServiceAttemptsPerHandshake: 2_000_000, MaxRecordsPerService: 8,
	}
}

type memoryTransport struct {
	peer                  *bridgeConn
	closed                atomic.Bool
	eof                   atomic.Bool
	finishCalls           atomic.Uint32
	finishErrorAfterReady error
	readLimit             int
	writeLimit            int
	local, remote         nscore.Endpoint
}

func (transport *memoryTransport) LocalEndpoint() nscore.Endpoint {
	if transport.local.Valid() {
		return transport.local
	}
	return nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 49152}
}
func (transport *memoryTransport) RemoteEndpoint() nscore.Endpoint {
	if transport.remote.Valid() {
		return transport.remote
	}
	return nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443}
}
func (transport *memoryTransport) Readiness() nscore.Readiness {
	return nscore.ReadyConnected | nscore.ReadyReadable | nscore.ReadyWritable
}
func (transport *memoryTransport) TryFinishConnect() (nscore.Progress, error) {
	if transport.finishCalls.Add(1) > 1 && transport.finishErrorAfterReady != nil {
		return 0, transport.finishErrorAfterReady
	}
	return nscore.ProgressDone, nil
}
func (transport *memoryTransport) TryRead(dst []byte) (nscore.IOResult, error) {
	if transport.readLimit > 0 && len(dst) > transport.readLimit {
		dst = dst[:transport.readLimit]
	}
	count := transport.peer.peekCipher(dst)
	if count == 0 {
		if transport.eof.Load() {
			return nscore.IOResult{State: nscore.IOEOF}, nil
		}
		return nscore.IOResult{State: nscore.IOWouldBlock}, nil
	}
	transport.peer.discardCipher(count)
	return nscore.IOResult{Bytes: count, State: nscore.IOReady}, nil
}
func (transport *memoryTransport) TryWrite(src []byte) (nscore.IOResult, error) {
	if transport.writeLimit > 0 && len(src) > transport.writeLimit {
		src = src[:transport.writeLimit]
	}
	count, err := transport.peer.feedCipher(src)
	if err != nil {
		return nscore.IOResult{}, err
	}
	if count == 0 {
		return nscore.IOResult{State: nscore.IOWouldBlock}, nil
	}
	return nscore.IOResult{Bytes: count, State: nscore.IOReady}, nil
}
func (transport *memoryTransport) TryShutdownWrite() (nscore.Progress, error) {
	return nscore.ProgressDone, nil
}
func (transport *memoryTransport) Close() error {
	if transport.closed.CompareAndSwap(false, true) {
		transport.peer.abort(nil)
	}
	return nil
}

func testCertificate(t testing.TB, dnsName string) (cryptotls.Certificate, *x509.CertPool) {
	now := time.Unix(1_800_000_000, 0)
	return testCertificateFields(t, []string{dnsName}, nil, now.Add(-time.Hour), now.Add(time.Hour))
}

func testCertificateFields(t testing.TB, dnsNames []string, ipAddresses []net.IP, notBefore, notAfter time.Time) (cryptotls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ignored-common-name"},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: dnsNames, IPAddresses: ipAddresses,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return certificate, roots
}
