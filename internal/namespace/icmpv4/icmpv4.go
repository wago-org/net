// Package icmpv4 defines the narrow backend-neutral ICMPv4 echo namespace
// facet and generation-safe asynchronous exchange contract.
package icmpv4

import (
	"net/netip"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey is the protocol-local key used to attach an ICMPv4 adapter to one
// shared composed namespace.
const ServiceKey nscore.ServiceKey = "icmpv4"

// Namespace starts bounded asynchronous ICMPv4 echo exchanges. The returned
// shared resource must satisfy Echo before publication.
type Namespace interface {
	TryEcho(Request) (nscore.Resource, nscore.Progress, error)
}

// Request selects one IPv4 destination and an immediately copied echo payload.
// Payload is call-scoped and must never be retained by an implementation.
type Request struct {
	Destination netip.Addr
	Payload     []byte
}

// Valid reports whether the request selects one unmapped IPv4 destination.
// Authority for loopback, multicast, broadcast, and ordinary destinations is
// enforced separately by policy.
func (r Request) Valid() bool {
	return r.Destination.Is4() && !r.Destination.Is4In6() && !r.Destination.IsUnspecified() && r.Destination.Zone() == ""
}

// Result describes one copied echo reply. Copied may be smaller than
// PayloadBytes when the caller supplied a short destination buffer.
type Result struct {
	Source       netip.Addr
	Identifier   uint16
	Sequence     uint16
	Copied       int
	PayloadBytes int
}

// Valid reports whether result is structurally consistent with a destination
// buffer of size bytes.
func (r Result) Valid(size int) bool {
	return size >= 0 && r.Source.Is4() && !r.Source.Is4In6() && !r.Source.IsUnspecified() && r.Source.Zone() == "" &&
		r.Copied >= 0 && r.Copied <= size && r.PayloadBytes >= r.Copied
}

// Next is the result of one nonblocking TryResult call.
type Next uint8

const (
	NextReady Next = iota + 1
	NextWouldBlock
)

// Echo owns one bounded exchange. TryResult copies reply bytes into dst and
// never returns backend-owned storage. Cancel immediately makes unfinished work
// terminal; Close discards all retained state and quota synchronously.
type Echo interface {
	nscore.Resource
	TryResult(dst []byte) (Result, Next, error)
	Cancel() error
}
