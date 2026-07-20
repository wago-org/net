// Package tls defines the backend-neutral outbound TLS namespace and secure
// stream contracts. It contains no crypto/tls or transport implementation type.
package tls

import nscore "github.com/wago-org/net/internal/namespace/core"

const ServiceKey nscore.ServiceKey = "tls"

// MaxReadBytes bounds one checked guest read and reusable ABI scratch.
const MaxReadBytes = 64 << 10

// IdentityType records which standard x509 identity rule verified the peer.
type IdentityType uint8

const (
	IdentityDNS IdentityType = iota + 1
	IdentityIP
)

// ConnectionInfo is bounded post-handshake metadata. Certificate chains and
// private key material are deliberately absent.
type ConnectionInfo struct {
	LocalEndpoint    nscore.Endpoint
	RemoteEndpoint   nscore.Endpoint
	TLSVersion       uint16
	CipherSuite      uint16
	NegotiatedALPN   string
	Resumed          bool
	PeerLeafSPKI256  [32]byte
	VerifiedIdentity IdentityType
}

// Valid reports whether metadata can be represented without truncation.
func (info ConnectionInfo) Valid(maxALPN int) bool {
	return info.LocalEndpoint.Valid() && info.RemoteEndpoint.Valid() &&
		info.TLSVersion != 0 && info.CipherSuite != 0 &&
		(info.VerifiedIdentity == IdentityDNS || info.VerifiedIdentity == IdentityIP) &&
		len(info.NegotiatedALPN) <= maxALPN
}

// Namespace creates only outbound secure streams from finite host profiles.
type Namespace interface {
	TryConnectTLS(remote nscore.Endpoint, profileID uint32, serverName string) (nscore.Resource, nscore.Progress, error)
}

// Stream exposes plaintext only after TCP completion, TLS handshake,
// certificate-chain verification, identity verification, and required ALPN.
type Stream interface {
	nscore.Resource
	LocalEndpoint() nscore.Endpoint
	RemoteEndpoint() nscore.Endpoint
	TryFinishConnect() (nscore.Progress, error)
	TryRead(dst []byte) (nscore.IOResult, error)
	TryWrite(src []byte) (nscore.IOResult, error)
	TryShutdownWrite() (nscore.Progress, error)
	ConnectionInfo() (ConnectionInfo, bool)
}
