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
	Resources    uint64
	UDPResources uint64
	TCPResources uint64
	DNSResources uint64
	QueuedBytes  uint64
	DNSWork      uint64
	ServiceUnits uint64
}

// DefaultLimits returns conservative finite per-instance limits. Callers get a
// value copy and may tighten individual fields before constructing an account.
func DefaultLimits() Limits {
	return Limits{
		Resources:    256,
		UDPResources: 64,
		TCPResources: 128,
		DNSResources: 32,
		QueuedBytes:  4 << 20,
		DNSWork:      32,
		ServiceUnits: 4096,
	}
}

// Usage is an immutable snapshot of current reservations and committed usage.
type Usage struct {
	Resources    uint64
	UDPResources uint64
	TCPResources uint64
	DNSResources uint64
	QueuedBytes  uint64
	DNSWork      uint64
	ServiceUnits uint64
}

// ResourceClass identifies a resource protocol for total-plus-protocol
// accounting. ResourceOther consumes only the total resource counter.
type ResourceClass uint8

const (
	ResourceOther ResourceClass = iota + 1
	ResourceUDP
	ResourceTCP
	ResourceDNS
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
	default:
		return nil, ErrInvalidUnits
	}
	return a.reserve(amount)
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
		!fits(a.used.QueuedBytes, amount.QueuedBytes, a.limits.QueuedBytes) ||
		!fits(a.used.DNSWork, amount.DNSWork, a.limits.DNSWork) ||
		!fits(a.used.ServiceUnits, amount.ServiceUnits, a.limits.ServiceUnits) {
		return ErrLimit
	}
	a.used.add(amount)
	return nil
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
	a.used.QueuedBytes = subtract(a.used.QueuedBytes, amount.QueuedBytes)
	a.used.DNSWork = subtract(a.used.DNSWork, amount.DNSWork)
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

// Allocation is committed accounting owned by a live resource or operation.
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
	u.QueuedBytes += other.QueuedBytes
	u.DNSWork += other.DNSWork
	u.ServiceUnits += other.ServiceUnits
}
