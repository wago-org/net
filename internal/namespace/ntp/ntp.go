// Package ntp defines the narrow backend-neutral NTP client namespace facet,
// explicit host clock authority, and generation-safe synchronization contract.
package ntp

import (
	"net/netip"
	"time"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey is the protocol-local key used to attach an NTP adapter to one
// shared composed namespace.
const ServiceKey nscore.ServiceKey = "ntp"

var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Clock is the explicit host time authority used to timestamp NTP exchanges.
// Implementations must return promptly and must not reenter the namespace.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts one explicit function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Namespace starts bounded asynchronous NTP synchronizations. The returned
// shared resource must satisfy Sync before publication.
type Namespace interface {
	TrySync() (nscore.Resource, nscore.Progress, error)
}

// Sample is one completed two-exchange NTP clock sample. CorrectedTime is the
// explicitly injected host clock at completion plus Offset; no system clock is
// adjusted by this contract.
type Sample struct {
	Server         netip.Addr
	CorrectedTime  time.Time
	Offset         time.Duration
	RoundTripDelay time.Duration
	Stratum        uint8
	Leap           uint8
	Version        uint8
	ReferenceID    [4]byte
}

// Valid reports whether a sample is finite, canonical, and suitable for the
// fixed guest ABI.
func (s Sample) Valid() bool {
	return s.Server.Is4() && !s.Server.Is4In6() && !s.Server.IsUnspecified() && !s.Server.IsLoopback() && !s.Server.IsMulticast() &&
		s.Server != limitedBroadcast && s.Server.Zone() == "" &&
		!s.CorrectedTime.IsZero() && s.CorrectedTime.Location() == time.UTC && s.CorrectedTime.Nanosecond() >= 0 &&
		s.RoundTripDelay >= 0 && s.Stratum > 0 && s.Stratum < 16 && s.Leap < 3 && s.Version == 4
}

// Next is the result of one nonblocking TryResult call.
type Next uint8

const (
	NextReady Next = iota + 1
	NextWouldBlock
)

// Sync owns one bounded two-exchange synchronization. Cancel immediately makes
// unfinished work terminal; Close discards retained state and quota
// synchronously.
type Sync interface {
	nscore.Resource
	TryResult() (Sample, Next, error)
	Cancel() error
}
