// Package readiness coordinates bounded level-triggered polling for one
// instance's generation-safe resource table.
package readiness

import (
	"errors"
	"sync"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

var (
	ErrClosed               = errors.New("net: readiness coordinator closed")
	ErrInvalidConfig        = errors.New("net: invalid readiness config")
	ErrInvalidRegistration  = errors.New("net: invalid readiness registration")
	ErrDuplicate            = errors.New("net: duplicate readiness registration")
	ErrLimit                = errors.New("net: readiness registration limit")
	ErrInvalidBudget        = errors.New("net: invalid readiness budget")
	ErrInvalidServiceResult = errors.New("net: invalid readiness service result")
)

// Config fixes coordinator registration storage. Zero denies all registrations;
// it is not an unlimited sentinel.
type Config struct {
	MaxRegistrations int
}

// DefaultConfig returns a finite registration bound matching the default total
// per-instance resource limit.
func DefaultConfig() Config { return Config{MaxRegistrations: 256} }

// Budget independently bounds one nonblocking poll call. ServiceAttempts may be
// zero to disable backend servicing. A nonzero service bound requires a valid
// per-attempt namespace service budget.
type Budget struct {
	Scans           uint32
	Events          uint32
	ServiceAttempts uint32
	Service         nscore.ServiceBudget
}

// Valid reports whether every enabled dimension has a finite usable bound.
func (b Budget) Valid() bool {
	return b.Scans > 0 && b.Events > 0 && (b.ServiceAttempts == 0 || b.Service.Valid())
}

// Event is one level-triggered readiness snapshot for a live resource.
type Event struct {
	Handle    resource.Handle
	Readiness nscore.Readiness
}

// Valid reports whether the event names a live-form handle and known bits.
func (e Event) Valid() bool { return e.Handle != 0 && e.Readiness != 0 && e.Readiness.Valid() }

// Report describes bounded coordinator work. ServiceCompleted counts service
// attempts that reported completed work; would-block attempts remain visible in
// ServiceAttempts without becoming readiness events by themselves.
type Report struct {
	Scanned            uint32
	Events             uint32
	ServiceAttempts    uint32
	ServiceCompleted   uint32
	StaleRegistrations uint32
}

// ValidFor reports whether no independent bound or internal relationship was
// exceeded.
func (r Report) ValidFor(b Budget) bool {
	return b.Valid() && r.Scanned <= b.Scans && r.Events <= b.Events &&
		r.ServiceAttempts <= b.ServiceAttempts && r.ServiceCompleted <= r.ServiceAttempts &&
		r.StaleRegistrations <= r.Scanned
}

// Snapshot is immutable coordinator state.
type Snapshot struct {
	Registrations int
	Capacity      int
	Cursor        int
	Closed        bool
}

// Coordinator owns poll registrations for exactly one resource table.
type Coordinator struct {
	mu sync.Mutex

	table         *resource.Table
	regs          []registration
	index         map[resource.Handle]int
	cursor        int
	serviceCursor int
	limit         int
	closed        bool
}

type registration struct {
	handle resource.Handle
	kind   resource.Kind
}

type serviceable interface {
	TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error)
}

// New creates an empty coordinator for table.
func New(table *resource.Table, config Config) (*Coordinator, error) {
	if table == nil || config.MaxRegistrations <= 0 {
		return nil, ErrInvalidConfig
	}
	return &Coordinator{
		table: table,
		regs:  make([]registration, 0, config.MaxRegistrations),
		index: make(map[resource.Handle]int, config.MaxRegistrations),
		limit: config.MaxRegistrations,
	}, nil
}

// Register adds one live pollable handle. Handle kind remains explicit so every
// later lookup keeps the resource table's kind check.
func (c *Coordinator) Register(handle resource.Handle, kind resource.Kind) error {
	if c == nil {
		return ErrClosed
	}
	if handle == 0 || kind == resource.KindInvalid {
		return ErrInvalidRegistration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.table == nil {
		return ErrClosed
	}
	if _, exists := c.index[handle]; exists {
		return ErrDuplicate
	}
	if len(c.regs) == c.limit {
		return ErrLimit
	}
	value, err := c.table.Lookup(handle, kind)
	if err != nil {
		return err
	}
	if _, ok := value.(nscore.Pollable); !ok {
		return ErrInvalidRegistration
	}
	c.index[handle] = len(c.regs)
	c.regs = append(c.regs, registration{handle: handle, kind: kind})
	return nil
}

// Unregister removes one exact handle without closing its resource.
func (c *Coordinator) Unregister(handle resource.Handle) bool {
	if c == nil || handle == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	index, ok := c.index[handle]
	if !ok {
		return false
	}
	c.removeAt(index)
	return true
}

// TryPoll optionally services registered namespaces, removes stale handles, and
// writes level-triggered snapshots without sleeping. At most one full pass over
// the registrations present at call entry is made, and every output, scan, and
// backend service attempt is independently bounded.
func (c *Coordinator) TryPoll(events []Event, budget Budget) (Report, nscore.Progress, error) {
	if c == nil {
		return Report{}, 0, ErrClosed
	}
	if !budget.Valid() || uint64(budget.Events) > uint64(len(events)) {
		return Report{}, 0, ErrInvalidBudget
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.table == nil {
		return Report{}, 0, ErrClosed
	}
	clear(events[:budget.Events])
	if len(c.regs) == 0 {
		return Report{}, nscore.ProgressWouldBlock, nil
	}

	scanLimit := budget.Scans
	if scanLimit > uint32(len(c.regs)) {
		scanLimit = uint32(len(c.regs))
	}
	var report Report
	for report.Scanned < scanLimit && report.Events < budget.Events && len(c.regs) > 0 {
		if c.cursor >= len(c.regs) {
			c.cursor = 0
		}
		reg := c.regs[c.cursor]
		report.Scanned++
		value, err := c.table.Lookup(reg.handle, reg.kind)
		if errors.Is(err, resource.ErrBadHandle) {
			c.removeStaleAtCursor()
			report.StaleRegistrations++
			continue
		}
		if err != nil {
			return report, pollProgress(report), err
		}
		pollable, ok := value.(nscore.Pollable)
		if !ok {
			c.removeStaleAtCursor()
			report.StaleRegistrations++
			continue
		}

		if report.ServiceAttempts < budget.ServiceAttempts && c.cursor == c.serviceCursor {
			if service, ok := value.(serviceable); ok {
				report.ServiceAttempts++
				serviceReport, progress, serviceErr := service.TryService(budget.Service)
				if serviceErr != nil {
					if failure, ok := nscore.FailureOf(serviceErr); !ok || failure != nscore.FailureClosed {
						return report, pollProgress(report), serviceErr
					}
				} else if !serviceReport.ValidResult(budget.Service, progress) {
					return report, pollProgress(report), nscore.Fail(nscore.FailureIO, ErrInvalidServiceResult)
				} else if progress == nscore.ProgressDone {
					report.ServiceCompleted++
				}
			}
			c.advanceServiceCursor()
		}

		ready := pollable.Readiness()
		if !ready.Valid() {
			return report, pollProgress(report), nscore.Fail(nscore.FailureIO, ErrInvalidRegistration)
		}
		c.advanceCursor()
		if ready != 0 {
			event := Event{Handle: reg.handle, Readiness: ready}
			if !event.Valid() {
				return report, pollProgress(report), nscore.Fail(nscore.FailureIO, ErrInvalidRegistration)
			}
			events[report.Events] = event
			report.Events++
		}
	}
	return report, pollProgress(report), nil
}

// Snapshot returns current registration state.
func (c *Coordinator) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{Closed: true}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Snapshot{Registrations: len(c.regs), Capacity: c.limit, Cursor: c.cursor, Closed: c.closed}
}

// Close synchronously discards all registrations. Resources remain owned by the
// table and are closed separately by instance teardown.
func (c *Coordinator) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	clear(c.regs)
	c.regs = nil
	clear(c.index)
	c.index = nil
	c.table = nil
	c.cursor = 0
	c.serviceCursor = 0
	return nil
}

func (c *Coordinator) removeStaleAtCursor() {
	c.removeAt(c.cursor)
	if c.cursor >= len(c.regs) {
		c.cursor = 0
	}
}

func (c *Coordinator) removeAt(index int) {
	last := len(c.regs) - 1
	removed := c.regs[index]
	delete(c.index, removed.handle)
	if index != last {
		moved := c.regs[last]
		c.regs[index] = moved
		c.index[moved.handle] = index
		if c.cursor == last {
			c.cursor = index
		}
		if c.serviceCursor == last {
			c.serviceCursor = index
		}
	}
	c.regs[last] = registration{}
	c.regs = c.regs[:last]
	if len(c.regs) == 0 || c.cursor >= len(c.regs) {
		c.cursor = 0
	}
	if len(c.regs) == 0 || c.serviceCursor >= len(c.regs) {
		c.serviceCursor = 0
	}
}

func (c *Coordinator) advanceCursor() {
	c.cursor++
	if c.cursor == len(c.regs) {
		c.cursor = 0
	}
}

func (c *Coordinator) advanceServiceCursor() {
	c.serviceCursor++
	if c.serviceCursor == len(c.regs) {
		c.serviceCursor = 0
	}
}

func pollProgress(report Report) nscore.Progress {
	if report.Events != 0 || report.ServiceCompleted != 0 || report.StaleRegistrations != 0 {
		return nscore.ProgressDone
	}
	return nscore.ProgressWouldBlock
}
