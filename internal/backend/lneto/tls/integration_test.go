package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	gotls "github.com/wago-org/net/internal/backend/gotls"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestLiveLnetoTLSClientServerHandshakeDataShutdownAndReuse(t *testing.T) {
	for _, mutual := range []bool{false, true} {
		name := "server-auth"
		if mutual {
			name = "mutual-auth"
		}
		t.Run(name, func(t *testing.T) {
			pair := newLiveTLSPair(t, mutual)
			listenerValue, progress, err := pair.server.TryListenTLS(pair.endpoint, 2)
			if err != nil || progress != nscore.ProgressDone {
				t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
			}
			listener := listenerValue.(*listener)
			pair.assertLiveCounts(t, 0, 1, 0, 1)

			client, server := pair.establish(t, listener)
			pair.assertLiveCounts(t, 1, 2, 1, 1)
			assertLiveConnectionInfo(t, client, server, mutual)
			pair.exchange(t, client, server, bytes.Repeat([]byte("client-to-server/"), 256))
			pair.exchange(t, server, client, bytes.Repeat([]byte("server-to-client/"), 256))
			pair.cleanShutdown(t, client, server)
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			pair.assertLiveCounts(t, 0, 1, 0, 1)

			// Reuse the same live TLS listener and port for a second connection,
			// then abort it without close_notify to prove truncation classification.
			secondClient, secondServer := pair.establish(t, listener)
			pair.finishRawTransportShutdown(t, secondClient)
			pair.expectTruncation(t, secondServer)
			if err := secondClient.Close(); err != nil {
				t.Fatal(err)
			}
			if err := secondServer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			pair.assertReleased(t)
		})
	}
}

func TestLiveLnetoTLSListenerCloseAcceptRaceReleasesOwnership(t *testing.T) {
	pair := newLiveTLSPair(t, false)
	for iteration := 0; iteration < 32; iteration++ {
		listenerValue, progress, err := pair.server.TryListenTLS(pair.endpoint, 2)
		if err != nil || progress != nscore.ProgressDone {
			t.Fatalf("iteration %d listen = %T, %v, %v", iteration, listenerValue, progress, err)
		}
		listener := listenerValue.(*listener)
		clientValue, progress, err := pair.client.TryConnectTLS(pair.endpoint, 1, "server.example.com")
		if err != nil || progress != nscore.ProgressInProgress {
			t.Fatalf("iteration %d connect = %T, %v, %v", iteration, clientValue, progress, err)
		}
		client := clientValue.(*stream)
		for attempt := 0; attempt < 100000 && listener.Readiness()&nscore.ReadyAccept == 0; attempt++ {
			pair.serviceStream(t, client, false)
			pair.relay(t, pair.clientCore, pair.serverCore)
			pair.relay(t, pair.serverCore, pair.clientCore)
			runtime.Gosched()
		}
		if listener.Readiness()&nscore.ReadyAccept == 0 {
			t.Fatalf("iteration %d connection did not reach accept backlog", iteration)
		}

		start := make(chan struct{})
		var accepted nscore.Resource
		var acceptProgress nscore.Progress
		var acceptErr, closeErr error
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			accepted, acceptProgress, acceptErr = listener.TryAcceptTLS()
		}()
		go func() {
			defer workers.Done()
			<-start
			closeErr = listener.Close()
		}()
		close(start)
		workers.Wait()
		if closeErr != nil {
			t.Fatalf("iteration %d listener close: %v", iteration, closeErr)
		}
		if accepted != nil {
			if acceptErr != nil || acceptProgress != nscore.ProgressInProgress {
				t.Fatalf("iteration %d accepted result = %T, %v, %v", iteration, accepted, acceptProgress, acceptErr)
			}
			if err := accepted.Close(); err != nil {
				t.Fatalf("iteration %d accepted close: %v", iteration, err)
			}
		} else if acceptErr == nil && acceptProgress != nscore.ProgressWouldBlock {
			t.Fatalf("iteration %d empty accept result = %v, %v", iteration, acceptProgress, acceptErr)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("iteration %d client close: %v", iteration, err)
		}
	}
	pair.assertReleased(t)
}

func TestLiveLnetoTLSConcurrentResourceAndNamespaceCloseIsExactlyOnce(t *testing.T) {
	pair := newLiveTLSPair(t, true)
	listenerValue, progress, err := pair.server.TryListenTLS(pair.endpoint, 2)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
	}
	listener := listenerValue.(*listener)
	client, server := pair.establish(t, listener)
	closers := []func() error{client.Close, server.Close, listener.Close, pair.clientCore.Close, pair.serverCore.Close}
	start := make(chan struct{})
	errors := make(chan error, len(closers))
	var workers sync.WaitGroup
	for _, closeResource := range closers {
		workers.Add(1)
		go func(closeResource func() error) {
			defer workers.Done()
			<-start
			errors <- closeResource()
		}(closeResource)
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	pair.assertReleased(t)
}

func TestLiveLnetoTLSNamespaceTeardownReleasesListenerStreamAndHandshake(t *testing.T) {
	pair := newLiveTLSPair(t, false)
	listenerValue, progress, err := pair.server.TryListenTLS(pair.endpoint, 2)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("listen = %T, %v, %v", listenerValue, progress, err)
	}
	listener := listenerValue.(*listener)
	client, server := pair.establish(t, listener)
	if client == nil || server == nil {
		t.Fatal("live streams missing")
	}
	if err := pair.clientCore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pair.serverCore.Close(); err != nil {
		t.Fatal(err)
	}
	pair.assertReleased(t)
}

type liveTLSPair struct {
	clientCore    *lnetocore.Namespace
	serverCore    *lnetocore.Namespace
	client        *Adapter
	server        *Adapter
	clientAccount *quota.Account
	serverAccount *quota.Account
	endpoint      nscore.Endpoint
}

func newLiveTLSPair(t testing.TB, mutual bool) *liveTLSPair {
	t.Helper()
	certificate, clientCertificate, roots, now := liveTLSCertificates(t)
	clientMAC := [6]byte{0x02, 0, 0, 0, 0, 41}
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 42}
	clientAddress := netip.MustParseAddr("192.0.2.41")
	serverAddress := netip.MustParseAddr("192.0.2.42")
	endpoint := nscore.Endpoint{Address: serverAddress, Port: 8443}

	clientPolicy, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTLS},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	serverPolicy, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTLS},
		Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	limits := quota.Limits{
		Resources: 16, TCPResources: 8, TLSResources: 8, TLSHandshakes: 4,
		QueuedBytes: 2 << 20, TLSPlaintextBytes: 512 << 10, TLSCiphertextBytes: 512 << 10,
	}
	clientAccount := quota.NewAccount(limits)
	serverAccount := quota.NewAccount(limits)
	mtu := uint16(ethernet.MaxMTU)
	newCore := func(hostname string, seed int64, address netip.Addr, hardware, gateway [6]byte, compiled *policy.Policy, account *quota.Account) *lnetocore.Namespace {
		core, err := lnetocore.New(lnetocore.Config{
			Hostname: hostname, RandSeed: seed, HardwareAddress: hardware, GatewayHardwareAddress: gateway,
			IPv4Address: address, MTU: mtu, MaxActiveTCPPorts: 4, Policy: compiled, Quotas: account,
			Link: packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 64, EgressFrames: 64},
		})
		if err != nil {
			t.Fatal(err)
		}
		return core
	}
	clientCore := newCore("tls-client", 41, clientAddress, clientMAC, serverMAC, clientPolicy, clientAccount)
	serverCore := newCore("tls-server", 42, serverAddress, serverMAC, clientMAC, serverPolicy, serverAccount)
	t.Cleanup(func() {
		_ = clientCore.Close()
		_ = serverCore.Close()
	})

	clientTLSConfig := &cryptotls.Config{
		RootCAs: roots, Time: func() time.Time { return now }, MinVersion: cryptotls.VersionTLS13,
		MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"},
	}
	if mutual {
		clientTLSConfig.Certificates = []cryptotls.Certificate{clientCertificate}
	}
	serverTLSConfig := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{certificate}, Time: func() time.Time { return now },
		MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13,
		NextProtos: []string{"h2"}, SessionTicketsDisabled: true,
	}
	if mutual {
		serverTLSConfig.ClientAuth = cryptotls.RequireAndVerifyClientCert
		serverTLSConfig.ClientCAs = roots
	}
	engine := engineLimitsForTest()
	engine.MaxServiceAttemptsPerHandshake = 100000
	client, err := New(clientCore, Config{
		MaxStreams: 2, MaxConcurrentHandshakes: 2, MaxServerNameBytes: 253, MaxServiceAttemptsPerHandshake: 100000,
		TCP:    tcpbackend.Config{MaxOutboundStreams: 2, ReceiveBytes: 8 << 10, TransmitBytes: 8 << 10, TransmitPackets: 32},
		Engine: engine,
		Profiles: []gotls.Profile{{
			ID: 1, Config: clientTLSConfig, RequiredALPN: "h2", MaxCertificateChainBytes: 64 << 10,
			MaxPeerCertificates: 4, AllowedNames: map[string]tlsns.IdentityType{"server.example.com": tlsns.IdentityDNS},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(serverCore, Config{
		MaxStreams: 2, MaxListeners: 1, AcceptBacklog: 2, MaxConcurrentHandshakes: 2,
		MaxServerNameBytes: 253, MaxServiceAttemptsPerHandshake: 100000,
		TCP:    tcpbackend.Config{MaxListeners: 1, MaxOutboundStreams: 2, AcceptBacklog: 2, ReceiveBytes: 8 << 10, TransmitBytes: 8 << 10, TransmitPackets: 32},
		Engine: engine,
		ServerProfiles: []gotls.ServerProfile{{
			ID: 2, Config: serverTLSConfig, RequiredALPN: "h2", MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &liveTLSPair{
		clientCore: clientCore, serverCore: serverCore, client: client, server: server,
		clientAccount: clientAccount, serverAccount: serverAccount, endpoint: endpoint,
	}
}

func (pair *liveTLSPair) establish(t testing.TB, listener *listener) (*stream, *stream) {
	t.Helper()
	clientValue, progress, err := pair.client.TryConnectTLS(pair.endpoint, 1, "server.example.com")
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("connect = %T, %v, %v", clientValue, progress, err)
	}
	client := clientValue.(*stream)
	var server *stream
	for attempt := 0; attempt < 100000; attempt++ {
		pair.serviceStream(t, client, false)
		if server != nil {
			pair.serviceStream(t, server, false)
		}
		pair.relay(t, pair.clientCore, pair.serverCore)
		pair.relay(t, pair.serverCore, pair.clientCore)
		if server == nil && listener.Readiness()&nscore.ReadyAccept != 0 {
			serverValue, acceptProgress, acceptErr := listener.TryAcceptTLS()
			if acceptErr != nil || acceptProgress != nscore.ProgressInProgress {
				t.Fatalf("accept = %T, %v, %v", serverValue, acceptProgress, acceptErr)
			}
			server = serverValue.(*stream)
		}
		clientProgress, clientErr := client.TryFinishConnect()
		if clientErr != nil {
			t.Fatalf("client handshake: %v", clientErr)
		}
		serverProgress := nscore.ProgressInProgress
		if server != nil {
			serverProgress, err = server.TryFinishConnect()
			if err != nil {
				t.Fatalf("server handshake: %v", err)
			}
		}
		if clientProgress == nscore.ProgressDone && serverProgress == nscore.ProgressDone {
			return client, server
		}
		runtime.Gosched()
	}
	t.Fatalf("live TLS handshake did not complete: client=%v server=%v listener=%v", client.Readiness(), readinessOf(server), listener.Readiness())
	return nil, nil
}

func (pair *liveTLSPair) exchange(t testing.TB, from, to *stream, payload []byte) {
	t.Helper()
	sent := 0
	backpressured := false
	received := make([]byte, 0, len(payload))
	buffer := make([]byte, 257)
	for attempt := 0; attempt < 200000 && len(received) < len(payload); attempt++ {
		if sent < len(payload) {
			remaining := len(payload) - sent
			result, err := from.TryWrite(payload[sent:])
			if err != nil {
				t.Fatalf("write after %d bytes: %+v, %v", sent, result, err)
			}
			if result.Bytes < remaining {
				backpressured = true
			}
			sent += result.Bytes
		}
		pair.serviceStream(t, from, false)
		pair.serviceStream(t, to, false)
		pair.relay(t, pair.clientCore, pair.serverCore)
		pair.relay(t, pair.serverCore, pair.clientCore)
		result, err := to.TryRead(buffer)
		if err != nil {
			t.Fatalf("read after %d bytes: %+v, %v", len(received), result, err)
		}
		if result.Bytes != 0 {
			received = append(received, buffer[:result.Bytes]...)
		}
		runtime.Gosched()
	}
	if sent != len(payload) || !bytes.Equal(received, payload) {
		t.Fatalf("exchange sent=%d received=%d want=%d", sent, len(received), len(payload))
	}
	if len(payload) > 1024 && !backpressured {
		t.Fatal("payload larger than the plaintext queue did not exercise backpressure")
	}
}

func (pair *liveTLSPair) cleanShutdown(t testing.TB, client, server *stream) {
	t.Helper()
	pair.finishShutdownWrite(t, client, server, "client")
	pair.awaitEOF(t, server, client, "server")
	pair.finishShutdownWrite(t, server, client, "server")
	pair.awaitEOF(t, client, server, "client")
}

func (pair *liveTLSPair) finishShutdownWrite(t testing.TB, writer, peer *stream, side string) {
	t.Helper()
	for attempt := 0; attempt < 100000; attempt++ {
		progress, err := writer.TryShutdownWrite()
		if err != nil {
			t.Fatalf("%s shutdown = %v, %v", side, progress, err)
		}
		if progress == nscore.ProgressDone {
			return
		}
		pair.serviceStream(t, writer, false)
		pair.serviceStream(t, peer, false)
		pair.relay(t, pair.clientCore, pair.serverCore)
		pair.relay(t, pair.serverCore, pair.clientCore)
		runtime.Gosched()
	}
	t.Fatalf("%s shutdown did not complete", side)
}

func (pair *liveTLSPair) awaitEOF(t testing.TB, reader, writer *stream, side string) {
	t.Helper()
	buffer := make([]byte, 1)
	for attempt := 0; attempt < 100000; attempt++ {
		pair.serviceStream(t, writer, false)
		pair.serviceStream(t, reader, false)
		pair.relay(t, pair.clientCore, pair.serverCore)
		pair.relay(t, pair.serverCore, pair.clientCore)
		result, err := reader.TryRead(buffer)
		if err != nil {
			t.Fatalf("%s EOF read = %+v, %v", side, result, err)
		}
		if result.State == nscore.IOEOF {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("%s did not observe close_notify", side)
}

func (pair *liveTLSPair) finishRawTransportShutdown(t testing.TB, client *stream) {
	t.Helper()
	if client == nil || client.transport == nil {
		t.Fatal("client private transport missing")
	}
	for attempt := 0; attempt < 100000; attempt++ {
		progress, err := client.transport.TryShutdownWrite()
		if err != nil {
			t.Fatalf("raw transport shutdown = %v, %v", progress, err)
		}
		pair.relay(t, pair.clientCore, pair.serverCore)
		pair.relay(t, pair.serverCore, pair.clientCore)
		if progress == nscore.ProgressDone {
			return
		}
	}
	t.Fatal("raw transport shutdown did not complete")
}

func (pair *liveTLSPair) expectTruncation(t testing.TB, server *stream) {
	t.Helper()
	for attempt := 0; attempt < 100000; attempt++ {
		_, _, serviceErr := server.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 32})
		pair.relay(t, pair.clientCore, pair.serverCore)
		pair.relay(t, pair.serverCore, pair.clientCore)
		_, readErr := server.TryRead(make([]byte, 1))
		for _, candidate := range []error{serviceErr, readErr} {
			if candidate == nil {
				continue
			}
			failure, ok := nscore.FailureOf(candidate)
			if !ok || failure != nscore.FailureTLSProtocol {
				t.Fatalf("truncation = %v (%v)", candidate, failure)
			}
			return
		}
		runtime.Gosched()
	}
	t.Fatal("abrupt TLS close did not become TLS_PROTOCOL")
}

func (pair *liveTLSPair) serviceStream(t testing.TB, value *stream, allowTerminal bool) {
	t.Helper()
	if value == nil {
		return
	}
	_, _, err := value.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 32})
	if err != nil && !allowTerminal {
		t.Fatal(err)
	}
}

func (pair *liveTLSPair) relay(t testing.TB, from, to *lnetocore.Namespace) bool {
	t.Helper()
	from.Lock()
	from.SetNextIngressLocked(false)
	required := from.RequiredFrameBytesLocked()
	from.Unlock()
	report, progress, err := from.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 8})
	if err != nil {
		t.Fatalf("egress service = %+v, %v, %v", report, progress, err)
	}
	if report.Packets == 0 {
		return false
	}
	frame := make([]byte, from.Link().MaxFrameBytes())
	result, err := from.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready || result.Truncated || result.FrameBytes == 0 {
		t.Fatalf("egress dequeue = %+v, %v", result, err)
	}
	if err := to.Link().TryEnqueue(packetlink.Ingress, frame[:result.FrameBytes]); err != nil {
		t.Fatal(err)
	}
	to.Lock()
	to.SetNextIngressLocked(true)
	required = to.RequiredFrameBytesLocked()
	to.Unlock()
	report, progress, err = to.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 8})
	if err != nil || report.Packets != 1 || progress != nscore.ProgressDone {
		t.Fatalf("ingress service = %+v, %v, %v", report, progress, err)
	}
	return true
}

func (pair *liveTLSPair) assertLiveCounts(t testing.TB, clientTLS, serverTLS, clientPorts, serverPorts uint64) {
	t.Helper()
	clientUsage, _ := pair.clientAccount.Snapshot()
	serverUsage, _ := pair.serverAccount.Snapshot()
	if clientUsage.TLSResources != clientTLS || clientUsage.TLSHandshakes != 0 {
		t.Fatalf("client live quota = %+v, want TLS=%d handshakes=0", clientUsage, clientTLS)
	}
	if serverUsage.TLSResources != serverTLS || serverUsage.TLSHandshakes != 0 {
		t.Fatalf("server live quota = %+v, want TLS=%d handshakes=0", serverUsage, serverTLS)
	}
	for _, item := range []struct {
		name string
		core *lnetocore.Namespace
		want uint64
	}{{"client", pair.clientCore, clientPorts}, {"server", pair.serverCore, serverPorts}} {
		item.core.Lock()
		got := uint64(item.core.TCPPortLeaseCountLocked())
		item.core.Unlock()
		if got != item.want {
			t.Fatalf("%s live TCP leases = %d, want %d", item.name, got, item.want)
		}
	}
}

func (pair *liveTLSPair) assertReleased(t testing.TB) {
	t.Helper()
	for name, core := range map[string]*lnetocore.Namespace{"client": pair.clientCore, "server": pair.serverCore} {
		core.Lock()
		leases := core.TCPPortLeaseCountLocked()
		core.Unlock()
		if leases != 0 {
			t.Fatalf("%s retained %d TCP port leases", name, leases)
		}
	}
	for name, account := range map[string]*quota.Account{"client": pair.clientAccount, "server": pair.serverAccount} {
		usage, _ := account.Snapshot()
		if usage != (quota.Usage{}) {
			t.Fatalf("%s retained quota: %+v", name, usage)
		}
	}
}

func assertLiveConnectionInfo(t testing.TB, client, server *stream, mutual bool) {
	t.Helper()
	clientInfo, ok := client.ConnectionInfo()
	if !ok || clientInfo.Role != tlsns.RoleClient || !clientInfo.PeerAuthenticated || clientInfo.VerifiedIdentity != tlsns.IdentityDNS || clientInfo.NegotiatedALPN != "h2" || clientInfo.PeerLeafSPKI256 == ([32]byte{}) {
		t.Fatalf("client info = %+v, %v", clientInfo, ok)
	}
	serverInfo, ok := server.ConnectionInfo()
	if !ok || serverInfo.Role != tlsns.RoleServer || serverInfo.PeerAuthenticated != mutual || serverInfo.VerifiedIdentity != tlsns.IdentityNone || serverInfo.NegotiatedALPN != "h2" {
		t.Fatalf("server info = %+v, %v", serverInfo, ok)
	}
	if mutual == (serverInfo.PeerLeafSPKI256 == ([32]byte{})) {
		t.Fatalf("server peer digest = %x mutual=%v", serverInfo.PeerLeafSPKI256, mutual)
	}
}

func readinessOf(value *stream) nscore.Readiness {
	if value == nil {
		return 0
	}
	return value.Readiness()
}

func liveTLSCertificates(t testing.TB) (server, client cryptotls.Certificate, roots *x509.CertPool, now time.Time) {
	t.Helper()
	now = time.Unix(1_800_000_000, 0)
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "live TLS test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, commonName string, names []string, usage x509.ExtKeyUsage) cryptotls.Certificate {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: names,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cryptotls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: privateKey, Leaf: leaf}
	}
	server = issue(2, "server.example.com", []string{"server.example.com"}, x509.ExtKeyUsageServerAuth)
	client = issue(3, "client", nil, x509.ExtKeyUsageClientAuth)
	roots = x509.NewCertPool()
	roots.AddCert(ca)
	return server, client, roots, now
}
