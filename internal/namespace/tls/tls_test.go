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
		TLSVersion:     0x304, CipherSuite: 0x1301, NegotiatedALPN: "h2", VerifiedIdentity: IdentityDNS,
	}
	if !info.Valid(32) {
		t.Fatal("valid info rejected")
	}
	info.NegotiatedALPN = "too-long"
	if info.Valid(2) {
		t.Fatal("oversized ALPN accepted")
	}
}
