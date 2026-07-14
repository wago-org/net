// Package quota provides deterministic per-instance network accounting.
package quota

import (
	"errors"
	"sync"
	"sync/atomic"
)

var (
	ErrClosed       = errors.New("net: quota account closed")
	ErrLimit        = errors.New("net: quota limit exceeded")
	ErrInvalidUnits = errors.New("net: invalid quota units")
)

// Limits bounds every independently accounted class. Zero denies that class;
// there is no unbounded sentinel.
type Limits struct {
	Resources           uint64
	UDPResources        uint64
	TCPResources        uint64
	DNSResources        uint64
	ICMPv4Resources     uint64
	NTPResources        uint64
	MDNSResources       uint64
	DHCPv4Resources     uint64
	LinkLocal4Resources uint64
	IPv6Resources       uint64
	ICMPv6Resources     uint64
	DHCPv6Resources     uint64
	QueuedBytes         uint64
	DNSWork             uint64
	ICMPv4Work          uint64
	NTPWork             uint64
	MDNSWork            uint64
	DHCPv4Work          uint64
	LinkLocal4Work      uint64
	ICMPv6Work          uint64
	DHCPv6Work          uint64
	ServiceUnits        uint64
}

// DefaultLimits returns conservative finite per-instance limits. Callers get a
// value copy and may tighten individual fields before constructing an account.
func DefaultLimits() Limits {
	return Limits{
		Resources:           256,
		UDPResources:        64,
		TCPResources:        128,
		DNSResources:        32,
		ICMPv4Resources:     32,
		NTPResources:        16,
		MDNSResources:       32,
		DHCPv4Resources:     4,
		LinkLocal4Resources: 2,
		IPv6Resources:       1,
		ICMPv6Resources:     32,
		DHCPv6Resources:     4,
		QueuedBytes:         4 << 20,
		DNSWork:             32,
		ICMPv4Work:          32,
		NTPWork:             16,
		MDNSWork:            32,
		DHCPv4Work:          4,
		LinkLocal4Work:      2,
		ICMPv6Work:          32,
		DHCPv6Work:          4,
		ServiceUnits:        4096,
	}
}

// Usage is an immutable snapshot of current reservations and committed usage.
type Usage struct {
	Resources           uint64
	UDPResources        uint64
	TCPResources        uint64
	DNSResources        uint64
	ICMPv4Resources     uint64
	NTPResources        uint64
	MDNSResources       uint64
	DHCPv4Resources     uint64
	LinkLocal4Resources uint64
	IPv6Resources       uint64
	ICMPv6Resources     uint64
	DHCPv6Resources     uint64
	QueuedBytes         uint64
	DNSWork             uint64
	ICMPv4Work          uint64
	NTPWork             uint64
	MDNSWork            uint64
	DHCPv4Work          uint64
	LinkLocal4Work      uint64
	ICMPv6Work          uint64
	DHCPv6Work          uint64
	ServiceUnits        uint64
}

// ResourceClass identifies a resource protocol for total-plus-protocol
// accounting. ResourceOther consumes only the total resource counter.
type ResourceClass uint8

const (
	ResourceOther ResourceClass = iota + 1
	ResourceUDP
	ResourceTCP
	ResourceDNS
	ResourceICMPv4
	ResourceNTP
	ResourceMDNS
	ResourceDHCPv4
	ResourceLinkLocal4
	ResourceIPv6
	ResourceICMPv6
	ResourceDHCPv6
)

// Account is one instance's bounded, concurrently safe quota ledger.
type Account struct {
	mu     sync.Mutex
	limits Limits
	used   Usage
	closed bool
}

// NewAccount creates an empty account with the exact finite limits supplied.
func NewAccount(limits Limits) *Account {
	return &Account{limits: limits}
}

// ReserveResource tentatively reserves total and protocol resource counters.
func (a *Account) ReserveResource(class ResourceClass, count uint64) (*Reservation, error) {
	if count == 0 {
		return nil, ErrInvalidUnits
	}
	amount := Usage{Resources: count}
	switch class {
	case ResourceOther:
	case ResourceUDP:
		amount.UDPResources = count
	case ResourceTCP:
		amount.TCPResources = count
	case ResourceDNS:
		amount.DNSResources = count
	case ResourceICMPv4:
		amount.ICMPv4Resources = count
	case ResourceNTP:
		amount.NTPResources = count
	case ResourceMDNS:
		amount.MDNSResources = count
	case ResourceDHCPv4:
		amount.DHCPv4Resources = count
	case ResourceLinkLocal4:
		amount.LinkLocal4Resources = count
	case ResourceIPv6:
		amount.IPv6Resources = count
	case ResourceICMPv6:
		amount.ICMPv6Resources = count
	case ResourceDHCPv6:
		amount.DHCPv6Resources = count
	default:
		return nil, ErrInvalidUnits
	}
	return a.reserve(amount)
}

// AcquireResource commits resource accounting directly into owner-embedded
// storage, avoiding separate reservation and allocation objects.
func (a *Account) AcquireResource(charge *Charge, class ResourceClass, count uint64) error {
	amount, ok := resourceUsage(class, count)
	if !ok {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, amount)
}

// AcquireResourceAndQueuedBytes atomically commits one resource charge and its
// retained byte charge into owner-embedded storage. The byte component may be
// zero for bounded resources that retain metadata but no payload storage.
func (a *Account) AcquireResourceAndQueuedBytes(charge *Charge, class ResourceClass, count, bytes uint64) error {
	amount, ok := resourceUsage(class, count)
	if !ok {
		return ErrInvalidUnits
	}
	amount.QueuedBytes = bytes
	return a.acquireInto(charge, amount)
}

// AcquireQueuedBytes commits bounded retained storage directly into
// owner-embedded storage without creating a resource charge.
func (a *Account) AcquireQueuedBytes(charge *Charge, bytes uint64) error {
	if bytes == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{QueuedBytes: bytes})
}

// AcquireDNSWork commits in-flight resolver work directly into owner-embedded
// storage.
func (a *Account) AcquireDNSWork(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{DNSWork: units})
}

// AcquireICMPv4Work commits one active echo exchange into owner-embedded
// storage until it reaches a terminal state.
func (a *Account) AcquireICMPv4Work(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{ICMPv4Work: units})
}

// AcquireNTPWork commits one active synchronization into owner-embedded
// storage until it reaches a terminal state.
func (a *Account) AcquireNTPWork(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{NTPWork: units})
}

// AcquireMDNSWork commits one active multicast query or announcement.
func (a *Account) AcquireMDNSWork(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{MDNSWork: units})
}

// AcquireDHCPv4Work commits one active DORA transaction.
func (a *Account) AcquireDHCPv4Work(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{DHCPv4Work: units})
}

// AcquireLinkLocal4Work commits one active claim-and-defend operation.
func (a *Account) AcquireLinkLocal4Work(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{LinkLocal4Work: units})
}

// AcquireICMPv6Work commits one active echo or Neighbor Solicitation until it
// reaches a terminal state.
func (a *Account) AcquireICMPv6Work(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{ICMPv6Work: units})
}

// AcquireDHCPv6Work commits one active Solicit/Request acquisition until it
// reaches a terminal state.
func (a *Account) AcquireDHCPv6Work(charge *Charge, units uint64) error {
	if units == 0 {
		return ErrInvalidUnits
	}
	return a.acquireInto(charge, Usage{DHCPv6Work: units})
}

// ReserveQueuedBytes tentatively accounts bytes retained outside a host call.
func (a *Account) ReserveQueuedBytes(bytes uint64) (*Reservation, error) {
	if bytes == 0 {
		return nil, ErrInvalidUnits
	}
	return a.reserve(Usage{QueuedBytes: bytes})
}

// ReserveDNSWork tentatively accounts bounded in-flight resolver work.
func (a *Account) ReserveDNSWork(units uint64) (*Reservation, error) {
	if units == 0 {
		return nil, ErrInvalidUnits
	}
	return a.reserve(Usage{DNSWork: units})
}

// ReserveService tentatively accounts bounded service/poll work units.
func (a *Account) ReserveService(units uint64) (*Reservation, error) {
	if units == 0 {
		return nil, ErrInvalidUnits
	}
	return a.reserve(Usage{ServiceUnits: units})
}

// WithService accounts bounded service/poll work only for the duration of work.
// The charge is released before return and during panic unwinding. Unlike a
// retained Reservation, this scoped path does not allocate a quota token.
func (a *Account) WithService(units uint64, work func()) error {
	if units == 0 || work == nil {
		return ErrInvalidUnits
	}
	amount := Usage{ServiceUnits: units}
	if err := a.acquire(amount); err != nil {
		return err
	}
	defer a.release(amount)
	work()
	return nil
}

func (a *Account) reserve(amount Usage) (*Reservation, error) {
	if err := a.acquire(amount); err != nil {
		return nil, err
	}
	reservation := &Reservation{account: a, amount: amount}
	reservation.state.Store(reservationPending)
	return reservation, nil
}

func (a *Account) acquire(amount Usage) error {
	if a == nil {
		return ErrClosed
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if !fits(a.used.Resources, amount.Resources, a.limits.Resources) ||
		!fits(a.used.UDPResources, amount.UDPResources, a.limits.UDPResources) ||
		!fits(a.used.TCPResources, amount.TCPResources, a.limits.TCPResources) ||
		!fits(a.used.DNSResources, amount.DNSResources, a.limits.DNSResources) ||
		!fits(a.used.ICMPv4Resources, amount.ICMPv4Resources, a.limits.ICMPv4Resources) ||
		!fits(a.used.NTPResources, amount.NTPResources, a.limits.NTPResources) ||
		!fits(a.used.MDNSResources, amount.MDNSResources, a.limits.MDNSResources) ||
		!fits(a.used.DHCPv4Resources, amount.DHCPv4Resources, a.limits.DHCPv4Resources) ||
		!fits(a.used.LinkLocal4Resources, amount.LinkLocal4Resources, a.limits.LinkLocal4Resources) ||
		!fits(a.used.IPv6Resources, amount.IPv6Resources, a.limits.IPv6Resources) ||
		!fits(a.used.ICMPv6Resources, amount.ICMPv6Resources, a.limits.ICMPv6Resources) ||
		!fits(a.used.DHCPv6Resources, amount.DHCPv6Resources, a.limits.DHCPv6Resources) ||
		!fits(a.used.QueuedBytes, amount.QueuedBytes, a.limits.QueuedBytes) ||
		!fits(a.used.DNSWork, amount.DNSWork, a.limits.DNSWork) ||
		!fits(a.used.ICMPv4Work, amount.ICMPv4Work, a.limits.ICMPv4Work) ||
		!fits(a.used.NTPWork, amount.NTPWork, a.limits.NTPWork) ||
		!fits(a.used.MDNSWork, amount.MDNSWork, a.limits.MDNSWork) ||
		!fits(a.used.DHCPv4Work, amount.DHCPv4Work, a.limits.DHCPv4Work) ||
		!fits(a.used.LinkLocal4Work, amount.LinkLocal4Work, a.limits.LinkLocal4Work) ||
		!fits(a.used.ICMPv6Work, amount.ICMPv6Work, a.limits.ICMPv6Work) ||
		!fits(a.used.DHCPv6Work, amount.DHCPv6Work, a.limits.DHCPv6Work) ||
		!fits(a.used.ServiceUnits, amount.ServiceUnits, a.limits.ServiceUnits) {
		return ErrLimit
	}
	a.used.add(amount)
	return nil
}

func (a *Account) acquireInto(charge *Charge, amount Usage) error {
	if a == nil {
		return ErrClosed
	}
	if charge == nil || !charge.state.CompareAndSwap(0, reservationPending) {
		return ErrInvalidUnits
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		charge.state.Store(0)
		return ErrClosed
	}
	if !a.fitsLocked(amount) {
		a.mu.Unlock()
		charge.state.Store(0)
		return ErrLimit
	}
	a.used.add(amount)
	charge.account = a
	charge.amount = amount
	charge.state.Store(reservationCommitted)
	a.mu.Unlock()
	return nil
}

func (a *Account) fitsLocked(amount Usage) bool {
	return fits(a.used.Resources, amount.Resources, a.limits.Resources) &&
		fits(a.used.UDPResources, amount.UDPResources, a.limits.UDPResources) &&
		fits(a.used.TCPResources, amount.TCPResources, a.limits.TCPResources) &&
		fits(a.used.DNSResources, amount.DNSResources, a.limits.DNSResources) &&
		fits(a.used.ICMPv4Resources, amount.ICMPv4Resources, a.limits.ICMPv4Resources) &&
		fits(a.used.NTPResources, amount.NTPResources, a.limits.NTPResources) &&
		fits(a.used.MDNSResources, amount.MDNSResources, a.limits.MDNSResources) &&
		fits(a.used.DHCPv4Resources, amount.DHCPv4Resources, a.limits.DHCPv4Resources) &&
		fits(a.used.LinkLocal4Resources, amount.LinkLocal4Resources, a.limits.LinkLocal4Resources) &&
		fits(a.used.IPv6Resources, amount.IPv6Resources, a.limits.IPv6Resources) &&
		fits(a.used.ICMPv6Resources, amount.ICMPv6Resources, a.limits.ICMPv6Resources) &&
		fits(a.used.DHCPv6Resources, amount.DHCPv6Resources, a.limits.DHCPv6Resources) &&
		fits(a.used.QueuedBytes, amount.QueuedBytes, a.limits.QueuedBytes) &&
		fits(a.used.DNSWork, amount.DNSWork, a.limits.DNSWork) &&
		fits(a.used.ICMPv4Work, amount.ICMPv4Work, a.limits.ICMPv4Work) &&
		fits(a.used.NTPWork, amount.NTPWork, a.limits.NTPWork) &&
		fits(a.used.MDNSWork, amount.MDNSWork, a.limits.MDNSWork) &&
		fits(a.used.DHCPv4Work, amount.DHCPv4Work, a.limits.DHCPv4Work) &&
		fits(a.used.LinkLocal4Work, amount.LinkLocal4Work, a.limits.LinkLocal4Work) &&
		fits(a.used.ICMPv6Work, amount.ICMPv6Work, a.limits.ICMPv6Work) &&
		fits(a.used.DHCPv6Work, amount.DHCPv6Work, a.limits.DHCPv6Work) &&
		fits(a.used.ServiceUnits, amount.ServiceUnits, a.limits.ServiceUnits)
}

// Snapshot returns current usage and whether the account has been closed.
func (a *Account) Snapshot() (Usage, bool) {
	if a == nil {
		return Usage{}, true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.used, a.closed
}

// Close releases all pending and committed accounting and permanently rejects
// new reservations. Releases by outstanding allocations become harmless no-ops.
func (a *Account) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	a.used = Usage{}
	a.mu.Unlock()
}

func (a *Account) release(amount Usage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	// Amounts originate only from successful reserve calls. Saturating each
	// counter is a final defense against underflow if a future caller violates
	// the token state machine.
	a.used.Resources = subtract(a.used.Resources, amount.Resources)
	a.used.UDPResources = subtract(a.used.UDPResources, amount.UDPResources)
	a.used.TCPResources = subtract(a.used.TCPResources, amount.TCPResources)
	a.used.DNSResources = subtract(a.used.DNSResources, amount.DNSResources)
	a.used.ICMPv4Resources = subtract(a.used.ICMPv4Resources, amount.ICMPv4Resources)
	a.used.NTPResources = subtract(a.used.NTPResources, amount.NTPResources)
	a.used.MDNSResources = subtract(a.used.MDNSResources, amount.MDNSResources)
	a.used.DHCPv4Resources = subtract(a.used.DHCPv4Resources, amount.DHCPv4Resources)
	a.used.LinkLocal4Resources = subtract(a.used.LinkLocal4Resources, amount.LinkLocal4Resources)
	a.used.IPv6Resources = subtract(a.used.IPv6Resources, amount.IPv6Resources)
	a.used.ICMPv6Resources = subtract(a.used.ICMPv6Resources, amount.ICMPv6Resources)
	a.used.DHCPv6Resources = subtract(a.used.DHCPv6Resources, amount.DHCPv6Resources)
	a.used.QueuedBytes = subtract(a.used.QueuedBytes, amount.QueuedBytes)
	a.used.DNSWork = subtract(a.used.DNSWork, amount.DNSWork)
	a.used.ICMPv4Work = subtract(a.used.ICMPv4Work, amount.ICMPv4Work)
	a.used.NTPWork = subtract(a.used.NTPWork, amount.NTPWork)
	a.used.MDNSWork = subtract(a.used.MDNSWork, amount.MDNSWork)
	a.used.DHCPv4Work = subtract(a.used.DHCPv4Work, amount.DHCPv4Work)
	a.used.LinkLocal4Work = subtract(a.used.LinkLocal4Work, amount.LinkLocal4Work)
	a.used.ICMPv6Work = subtract(a.used.ICMPv6Work, amount.ICMPv6Work)
	a.used.DHCPv6Work = subtract(a.used.DHCPv6Work, amount.DHCPv6Work)
	a.used.ServiceUnits = subtract(a.used.ServiceUnits, amount.ServiceUnits)
}

// Reservation is a tentative charge. Exactly one Commit or Rollback wins.
type Reservation struct {
	account *Account
	amount  Usage
	state   atomic.Uint32
}

const (
	reservationPending uint32 = iota + 1
	reservationCommitted
	reservationReleased
)

// Commit converts a pending reservation into an allocation without changing
// counters. A failed commit returns nil and leaves accounting unchanged.
func (r *Reservation) Commit() (*Allocation, bool) {
	if r == nil || r.account == nil {
		return nil, false
	}
	r.account.mu.Lock()
	defer r.account.mu.Unlock()
	if r.account.closed {
		r.state.CompareAndSwap(reservationPending, reservationReleased)
		return nil, false
	}
	if !r.state.CompareAndSwap(reservationPending, reservationCommitted) {
		return nil, false
	}
	return &Allocation{reservation: r}, true
}

// Rollback releases a pending reservation. It is exactly-once and cannot undo a
// committed allocation.
func (r *Reservation) Rollback() bool {
	if r == nil || !r.state.CompareAndSwap(reservationPending, reservationReleased) {
		return false
	}
	r.account.release(r.amount)
	return true
}

// Allocation is committed accounting created from a retained Reservation.
type Allocation struct {
	reservation *Reservation
}

// Release returns committed accounting exactly once.
func (a *Allocation) Release() bool {
	if a == nil || a.reservation == nil || !a.reservation.state.CompareAndSwap(reservationCommitted, reservationReleased) {
		return false
	}
	a.reservation.account.release(a.reservation.amount)
	return true
}

// Charge is committed accounting stored directly in its owning resource. It
// avoids heap-backed reservation/allocation tokens on specialized creation paths.
type Charge struct {
	account *Account
	amount  Usage
	state   atomic.Uint32
}

// Release returns an embedded charge exactly once.
func (c *Charge) Release() bool {
	if c == nil || c.account == nil || !c.state.CompareAndSwap(reservationCommitted, reservationReleased) {
		return false
	}
	c.account.release(c.amount)
	return true
}

// ResetReleased prepares exclusive owner-embedded storage for another direct
// acquisition. It succeeds only after a charge was released. The owner must
// prevent concurrent Release, ResetReleased, and Acquire calls.
func (c *Charge) ResetReleased() bool {
	if c == nil || !c.state.CompareAndSwap(reservationReleased, reservationPending) {
		return false
	}
	c.account = nil
	c.amount = Usage{}
	c.state.Store(0)
	return true
}

func resourceUsage(class ResourceClass, count uint64) (Usage, bool) {
	if count == 0 {
		return Usage{}, false
	}
	amount := Usage{Resources: count}
	switch class {
	case ResourceOther:
	case ResourceUDP:
		amount.UDPResources = count
	case ResourceTCP:
		amount.TCPResources = count
	case ResourceDNS:
		amount.DNSResources = count
	case ResourceICMPv4:
		amount.ICMPv4Resources = count
	case ResourceNTP:
		amount.NTPResources = count
	case ResourceMDNS:
		amount.MDNSResources = count
	case ResourceDHCPv4:
		amount.DHCPv4Resources = count
	case ResourceLinkLocal4:
		amount.LinkLocal4Resources = count
	case ResourceIPv6:
		amount.IPv6Resources = count
	case ResourceICMPv6:
		amount.ICMPv6Resources = count
	case ResourceDHCPv6:
		amount.DHCPv6Resources = count
	default:
		return Usage{}, false
	}
	return amount, true
}

func fits(used, amount, limit uint64) bool {
	return used <= limit && amount <= limit-used
}

func subtract(value, amount uint64) uint64 {
	if amount > value {
		return 0
	}
	return value - amount
}

func (u *Usage) add(other Usage) {
	u.Resources += other.Resources
	u.UDPResources += other.UDPResources
	u.TCPResources += other.TCPResources
	u.DNSResources += other.DNSResources
	u.ICMPv4Resources += other.ICMPv4Resources
	u.NTPResources += other.NTPResources
	u.MDNSResources += other.MDNSResources
	u.DHCPv4Resources += other.DHCPv4Resources
	u.LinkLocal4Resources += other.LinkLocal4Resources
	u.IPv6Resources += other.IPv6Resources
	u.ICMPv6Resources += other.ICMPv6Resources
	u.DHCPv6Resources += other.DHCPv6Resources
	u.QueuedBytes += other.QueuedBytes
	u.DNSWork += other.DNSWork
	u.ICMPv4Work += other.ICMPv4Work
	u.NTPWork += other.NTPWork
	u.MDNSWork += other.MDNSWork
	u.DHCPv4Work += other.DHCPv4Work
	u.LinkLocal4Work += other.LinkLocal4Work
	u.ICMPv6Work += other.ICMPv6Work
	u.DHCPv6Work += other.DHCPv6Work
	u.ServiceUnits += other.ServiceUnits
}
