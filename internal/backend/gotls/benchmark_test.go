package gotls

import (
	cryptotls "crypto/tls"
	"runtime"
	"testing"
	"time"

	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
)

func BenchmarkTLS13Handshake(b *testing.B) {
	certificate, roots := testCertificate(b, "api.example.com")
	profile := secureTestProfile(roots, "api.example.com")
	profile.Config.NextProtos = []string{"h2"}
	profile.RequiredALPN = "h2"
	b.ReportAllocs()
	for b.Loop() {
		serverBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
		server := cryptotls.Server(serverBridge, &cryptotls.Config{Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"}})
		serverDone := make(chan error, 1)
		go func() { serverDone <- server.Handshake() }()
		client, err := NewClient(&memoryTransport{peer: serverBridge}, profile, "api.example.com", tlsns.IdentityDNS, testLimits())
		if err != nil {
			b.Fatal(err)
		}
		for {
			progress, err := client.TryFinishConnect()
			if err != nil {
				b.Fatal(err)
			}
			if progress == nscore.ProgressDone {
				break
			}
			runtime.Gosched()
		}
		for {
			if _, _, err := client.TryService(nscore.ServiceBudget{Packets: 8, Bytes: 64 << 10, Operations: 8}); err != nil {
				b.Fatal(err)
			}
			select {
			case err := <-serverDone:
				if err != nil {
					b.Fatal(err)
				}
				goto serverHandshakeComplete
			default:
				runtime.Gosched()
			}
		}
	serverHandshakeComplete:
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTLS13ServerHandshake(b *testing.B) {
	certificate, roots := testCertificate(b, "server.example.com")
	profile := ServerProfile{
		ID: 9,
		Config: &cryptotls.Config{
			Certificates: []cryptotls.Certificate{certificate}, MinVersion: cryptotls.VersionTLS13,
			MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"}, SessionTicketsDisabled: true,
		},
		RequiredALPN: "h2", MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
	}
	b.ReportAllocs()
	for b.Loop() {
		clientBridge := newBridgeConn(64<<10, 64<<10, 1<<20)
		client := cryptotls.Client(clientBridge, &cryptotls.Config{
			RootCAs: roots, ServerName: "server.example.com", Time: func() time.Time { return time.Unix(1_800_000_000, 0) }, MinVersion: cryptotls.VersionTLS13,
			MaxVersion: cryptotls.VersionTLS13, NextProtos: []string{"h2"},
		})
		clientDone := make(chan error, 1)
		go func() { clientDone <- client.Handshake() }()
		server, err := NewServer(&memoryTransport{peer: clientBridge}, profile, testLimits())
		if err != nil {
			b.Fatal(err)
		}
		for {
			progress, err := server.TryFinishConnect()
			if err != nil {
				b.Fatal(err)
			}
			if progress == nscore.ProgressDone {
				break
			}
			runtime.Gosched()
		}
		if err := <-clientDone; err != nil {
			b.Fatal(err)
		}
		if err := server.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkByteRingSteadyState(b *testing.B) {
	ring := newByteRing(32 << 10)
	input := make([]byte, 4096)
	output := make([]byte, 4096)
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		if ring.write(input) != len(input) || ring.read(output) != len(output) {
			b.Fatal("short ring operation")
		}
	}
}

func BenchmarkProfileAuthorization(b *testing.B) {
	profile := Profile{AllowedNames: map[string]tlsns.IdentityType{"api.example.com": tlsns.IdentityDNS}}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, ok := profile.AuthorizeServerName("api.example.com"); !ok {
			b.Fatal("authorization failed")
		}
	}
}
