package gotls

import (
	cryptotls "crypto/tls"
	"runtime"
	"testing"

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
		if err := <-serverDone; err != nil {
			b.Fatal(err)
		}
		if err := client.Close(); err != nil {
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
