package tls

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

func TestConnectionInfoValidation(t *testing.T) {
	info := ConnectionInfo{
		LocalEndpoint:  nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 49152},
		RemoteEndpoint: nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443},
		TLSVersion:     0x304, CipherSuite: 0x1301, NegotiatedALPN: "h2", Role: RoleClient,
		PeerAuthenticated: true, PeerLeafSPKI256: [32]byte{1}, VerifiedIdentity: IdentityDNS,
	}
	if !info.Valid(32) {
		t.Fatal("valid info rejected")
	}
	info.NegotiatedALPN = "too-long"
	if info.Valid(2) {
		t.Fatal("oversized ALPN accepted")
	}
	server := ConnectionInfo{
		LocalEndpoint: info.LocalEndpoint, RemoteEndpoint: info.RemoteEndpoint,
		TLSVersion: 0x304, CipherSuite: 0x1301, Role: RoleServer,
	}
	if !server.Valid(32) {
		t.Fatal("valid unauthenticated-peer server info rejected")
	}
	server.PeerAuthenticated = true
	if server.Valid(32) {
		t.Fatal("server peer authentication without a peer key accepted")
	}
}
