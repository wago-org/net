package tls

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
		TLSVersion:     0x304, CipherSuite: 0x1301, NegotiatedALPN: string(make([]byte, MaxALPNV1Bytes+1)), Role: tlsns.RoleClient,
		PeerAuthenticated: true, PeerLeafSPKI256: [32]byte{1}, VerifiedIdentity: tlsns.IdentityDNS,
	}
	if EncodeConnectionInfoV1(memory, 0, info) || !bytes.Equal(memory, before) {
		t.Fatal("oversized ALPN mutated output")
	}
	info.NegotiatedALPN = "h2"
	if !EncodeConnectionInfoV1(memory, 0, info) {
		t.Fatal("valid connection info rejected")
	}
}

func TestEncodeConnectionInfoV1CompatibilityFixture(t *testing.T) {
	memory := make([]byte, ConnectionInfoV1Size)
	var peerSPKI [32]byte
	for index := range peerSPKI {
		peerSPKI[index] = byte(index + 1)
	}
	info := tlsns.ConnectionInfo{
		LocalEndpoint:     nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 49152},
		RemoteEndpoint:    nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443},
		TLSVersion:        0x0304,
		CipherSuite:       0x1301,
		NegotiatedALPN:    "h2",
		PeerAuthenticated: true,
		PeerLeafSPKI256:   peerSPKI,
		VerifiedIdentity:  tlsns.IdentityDNS,
		Role:              tlsns.RoleClient,
	}
	if !EncodeConnectionInfoV1(memory, 0, info) {
		t.Fatal("fixture encode failed")
	}
	const preServerFixture = "010000c000000000c000020100000000000000000000000000000000000000000100bb0100000000c000020200000000000000000000000000000000000000000403011300000000010000000200000068320000000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	want, err := hex.DecodeString(preServerFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(memory, want) {
		t.Fatalf("v1 bytes changed:\n got %x\nwant %x", memory, want)
	}
	if resumed := binary.LittleEndian.Uint32(memory[68:72]); resumed != 0 {
		t.Fatalf("v1 resumed = %d, want 0", resumed)
	}

	info.Role = tlsns.RoleServer
	info.PeerAuthenticated = false
	info.PeerLeafSPKI256 = [32]byte{}
	info.VerifiedIdentity = tlsns.IdentityNone
	if !EncodeConnectionInfoV1(memory, 0, info) {
		t.Fatal("server v1 encode failed")
	}
	if resumed := binary.LittleEndian.Uint32(memory[68:72]); resumed != 0 {
		t.Fatalf("server role leaked into v1 resumed = %d", resumed)
	}
	info.Resumed = true
	if !EncodeConnectionInfoV1(memory, 0, info) {
		t.Fatal("resumed server v1 encode failed")
	}
	if resumed := binary.LittleEndian.Uint32(memory[68:72]); resumed != 1 {
		t.Fatalf("v1 resumed = %d, want 1", resumed)
	}
}

func TestEncodeConnectionInfoV2FlagsAndBounds(t *testing.T) {
	memory := bytes.Repeat([]byte{0xa5}, int(ConnectionInfoV2Size)+8)
	info := tlsns.ConnectionInfo{
		LocalEndpoint:     nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 443},
		RemoteEndpoint:    nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 49152},
		TLSVersion:        0x0304,
		CipherSuite:       0x1301,
		NegotiatedALPN:    "h2",
		Resumed:           true,
		PeerAuthenticated: true,
		PeerLeafSPKI256:   [32]byte{1},
		VerifiedIdentity:  tlsns.IdentityDNS,
		Role:              tlsns.RoleServer,
	}
	if !EncodeConnectionInfoV2(memory, 4, info) {
		t.Fatal("v2 encode failed")
	}
	flags := binary.LittleEndian.Uint32(memory[4+68 : 4+72])
	want := ConnectionInfoV2FlagResumed | ConnectionInfoV2FlagServerRole | ConnectionInfoV2FlagPeerAuthenticated
	if flags != want {
		t.Fatalf("v2 flags = %#x, want %#x", flags, want)
	}
	if !bytes.Equal(memory[:4], bytes.Repeat([]byte{0xa5}, 4)) || !bytes.Equal(memory[4+ConnectionInfoV2Size:], bytes.Repeat([]byte{0xa5}, 4)) {
		t.Fatal("v2 encode wrote outside output range")
	}
	if ValidConnectionInfoV2Flags(ConnectionInfoV2KnownFlags | 1<<31) {
		t.Fatal("unknown v2 flag accepted")
	}
}

func FuzzCheckListenV1(f *testing.F) {
	f.Add(uint32(0), uint32(32), uint32(128))
	f.Fuzz(func(t *testing.T, endpointPtr, listenerPtr, memoryLength uint32) {
		if memoryLength > 4096 {
			memoryLength = 4096
		}
		_ = CheckListenV1(make([]byte, memoryLength), endpointPtr, listenerPtr)
	})
}

func FuzzEncodeListenerV1(f *testing.F) {
	f.Add(uint32(0), uint64(1), uint16(443), uint32(128))
	f.Fuzz(func(t *testing.T, ptr uint32, handle uint64, port uint16, memoryLength uint32) {
		if memoryLength > 4096 {
			memoryLength = 4096
		}
		_ = EncodeListenerV1(make([]byte, memoryLength), ptr, resource.Handle(handle), nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: port})
	})
}

func FuzzCheckCreateV1(f *testing.F) {
	f.Add(uint32(0), uint32(32), uint32(4), uint32(64), uint32(256))
	f.Fuzz(func(t *testing.T, endpointPtr, namePtr, nameLength, streamPtr, memoryLength uint32) {
		if memoryLength > 4096 {
			memoryLength = 4096
		}
		_ = CheckCreateV1(make([]byte, memoryLength), endpointPtr, namePtr, nameLength, streamPtr)
	})
}

func FuzzEncodeConnectionInfoV1(f *testing.F) {
	f.Add("h2", uint16(0x304), uint16(0x1301))
	f.Fuzz(func(t *testing.T, alpn string, version, cipher uint16) {
		if len(alpn) > 128 {
			alpn = alpn[:128]
		}
		memory := make([]byte, ConnectionInfoV1Size)
		info := tlsns.ConnectionInfo{
			LocalEndpoint:  nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 1234},
			RemoteEndpoint: nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443},
			TLSVersion:     version, CipherSuite: cipher, NegotiatedALPN: alpn, Role: tlsns.RoleClient,
			PeerAuthenticated: true, PeerLeafSPKI256: [32]byte{1}, VerifiedIdentity: tlsns.IdentityDNS,
		}
		_ = EncodeConnectionInfoV1(memory, 0, info)
	})
}

func FuzzEncodeConnectionInfoV2(f *testing.F) {
	f.Add("h2", uint16(0x304), uint16(0x1301), uint8(tlsns.RoleServer), true, true)
	f.Fuzz(func(t *testing.T, alpn string, version, cipher uint16, role uint8, resumed, authenticated bool) {
		if len(alpn) > 128 {
			alpn = alpn[:128]
		}
		memory := make([]byte, ConnectionInfoV2Size)
		identity := tlsns.IdentityNone
		hash := [32]byte{}
		if authenticated {
			identity = tlsns.IdentityDNS
			hash[0] = 1
		}
		info := tlsns.ConnectionInfo{
			LocalEndpoint: nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 1234}, RemoteEndpoint: nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 443},
			TLSVersion: version, CipherSuite: cipher, NegotiatedALPN: alpn, Resumed: resumed, Role: tlsns.Role(role),
			PeerAuthenticated: authenticated, PeerLeafSPKI256: hash, VerifiedIdentity: identity,
		}
		_ = EncodeConnectionInfoV2(memory, 0, info)
	})
}

func TestEncodeStreamRejectsZeroHandle(t *testing.T) {
	memory := make([]byte, StreamV1Size)
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 443}
	if EncodeStreamV1(memory, 0, resource.Handle(0), endpoint, endpoint) {
		t.Fatal("zero handle accepted")
	}
}
