// Package linklocal4 defines bounded backend-neutral IPv4 link-local/APIPA
// claim-and-defend contracts.
package linklocal4

import (
	"net/netip"
	"time"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

// ServiceKey attaches the IPv4 link-local adapter to one shared namespace.
const ServiceKey nscore.ServiceKey = "linklocal4"

var Prefix = netip.MustParsePrefix("169.254.0.0/16")

// Clock is the explicit host monotonic time authority used for RFC 3927
// scheduling. Implementations must return promptly and must not reenter the
// namespace.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts one explicit function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Namespace starts at most the configured finite number of exact claims.
type Namespace interface {
	TryClaim(Request) (nscore.Resource, nscore.Progress, error)
}

// Request contains only inline values. An invalid FirstCandidate means that the
// adapter selects the first candidate from its deterministic finite sequence.
type Request struct {
	FirstCandidate netip.Addr
}

func (r Request) Valid() bool {
	return !r.FirstCandidate.IsValid() || ValidAddress(r.FirstCandidate)
}

// Result is the current successfully claimed identity. A resource may return to
// would-block after a repeated defense conflict and later publish a new result.
type Result struct {
	Address   netip.Addr
	Subnet    netip.Prefix
	Conflicts uint16
	Applied   bool
}

func (r Result) Valid() bool {
	return ValidAddress(r.Address) && r.Subnet == Prefix && r.Subnet.Contains(r.Address) && r.Applied
}

// ValidAddress reports whether address is in the RFC 3927 usable range. The
// first and last /24 are reserved and never exposed as candidates.
func ValidAddress(address netip.Addr) bool {
	if !address.Is4() || address.Is4In6() || address.Zone() != "" || !Prefix.Contains(address) {
		return false
	}
	value := address.As4()
	return value[2] >= 1 && value[2] <= 254
}

// ResultState is the result of one immediate TryResult operation.
type ResultState uint8

const (
	ResultReady ResultState = iota + 1
	ResultWouldBlock
)

// Resource owns one exact claim, its ongoing bounded conflict defense, and its
// exact transactional namespace identity contribution until Release or Close.
type Resource interface {
	nscore.Resource
	TryResult() (Result, ResultState, error)
	Cancel() error
	Release() error
}
