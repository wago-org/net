// Package udp defines the narrow backend-neutral UDP namespace facet and
// datagram resource contracts.
package udp

import nscore "github.com/wago-org/net/internal/namespace/core"

// ServiceKey is the protocol-local key used to attach a UDP adapter to one
// shared composed namespace.
const ServiceKey nscore.ServiceKey = "udp"

// MaxDatagramPayloadBytes bounds one UDP payload in the narrow namespace
// contract and the instance-owned scratch used for atomic receive commits.
const MaxDatagramPayloadBytes = 1<<16 - 1

// Namespace creates UDP sockets on the shared namespace object. The returned
// shared resource must satisfy Socket before callers publish it.
type Namespace interface {
	TryBindUDP(local nscore.Endpoint) (nscore.Resource, nscore.Progress, error)
}

// Socket preserves datagram boundaries. TrySend accepts the whole datagram on
// ProgressDone and accepts none on other progress values.
type Socket interface {
	nscore.Resource
	LocalEndpoint() nscore.Endpoint
	TryReceive(dst []byte) (DatagramResult, error)
	TrySend(payload []byte, remote nscore.Endpoint) (nscore.Progress, error)
}

// DatagramResult describes exactly one received datagram. DatagramBytes is its
// original payload size, while Copied is the prefix copied into the caller's
// buffer. The unread suffix is discarded when Truncated is true.
type DatagramResult struct {
	Copied        int
	DatagramBytes int
	Source        nscore.Endpoint
	Truncated     bool
	Ready         bool
}

// Valid reports whether the receive result is internally consistent. Ready
// distinguishes an empty datagram from no datagram.
func (r DatagramResult) Valid(size int) bool {
	if size < 0 || r.Copied < 0 || r.DatagramBytes < 0 || r.DatagramBytes > MaxDatagramPayloadBytes || r.Copied > size || r.Copied > r.DatagramBytes {
		return false
	}
	if !r.Ready {
		return r.Copied == 0 && r.DatagramBytes == 0 && !r.Truncated && r.Source == (nscore.Endpoint{})
	}
	return r.Source.Valid() && r.Truncated == (r.Copied < r.DatagramBytes)
}
