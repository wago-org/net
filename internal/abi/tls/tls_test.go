package tls

import (
	"bytes"
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/resource"
)

func TestCheckCreateRejectsOverlapAndOverflow(t *testing.T) {
	memory := make([]byte, 256)
	if CheckCreateV1(memory, 0, 16, 4, 64) {
		t.Fatal("overlapping endpoint/name accepted")
	}
	if CheckCreateV1(memory, 0, ^uint32(0)-1, 8, 64) {
		t.Fatal("overflowing name accepted")
	}
	if !CheckCreateV1(memory, 0, 32, 4, 64) { // output starts after name and endpoint
		// endpoint is [0,32), name is [32,36), output is [64,136)
		t.Fatal("valid disjoint ranges rejected")
	}
}

func TestEncodeConnectionInfoAtomicAndBounded(t *testing.T) {
	memory := bytes.Repeat([]byte{0xaa}, 200)
	before := append([]byte(nil), memory...)
	info := tlsns.ConnectionInfo{
		LocalEndpoint:  nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 1234},
		RemoteEndpoint: nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443},
		TLSVersion:     0x304, CipherSuite: 0x1301, NegotiatedALPN: string(make([]byte, MaxALPNV1Bytes+1)),
		VerifiedIdentity: tlsns.IdentityDNS,
	}
	if EncodeConnectionInfoV1(memory, 0, info) || !bytes.Equal(memory, before) {
		t.Fatal("oversized ALPN mutated output")
	}
	info.NegotiatedALPN = "h2"
	if !EncodeConnectionInfoV1(memory, 0, info) {
		t.Fatal("valid connection info rejected")
	}
}

func TestEncodeStreamRejectsZeroHandle(t *testing.T) {
	memory := make([]byte, StreamV1Size)
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 443}
	if EncodeStreamV1(memory, 0, resource.Handle(0), endpoint, endpoint) {
		t.Fatal("zero handle accepted")
	}
}
