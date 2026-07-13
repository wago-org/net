// Package resource owns opaque, instance-scoped networking resources.
package resource

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
)

// Handle is an opaque guest-visible resource identifier. Zero is always invalid.
type Handle uint64

// Kind identifies the concrete interface expected for a resource handle.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindNamespace
	KindUDPSocket
	KindTCPListener
	KindTCPStream
	KindDNSQuery
	KindICMPv4Echo
	KindNTPSync
	KindMDNSQuery
	KindMDNSAnnouncement
	KindDHCPv4Lease
	KindLinkLocal4Claim
	KindPollable
)

var (
	ErrBadHandle = errors.New("net: bad resource handle")
	ErrClosed    = errors.New("net: resource table closed")
	ErrExhausted = errors.New("net: resource handle space exhausted")
)

// Resource is the common lifetime contract for instance-owned networking state.
type Resource interface {
	Close() error
}

const noSlot = uint32(math.MaxUint32)

var nextTableID atomic.Uint64

// Table is one instance's generation-safe resource namespace. Handles encode a
// never-reused process-lifetime table ID, a per-slot generation, and a slot
// index. A slot is retired rather than allowing its generation to wrap.
type Table struct {
	mu       sync.Mutex
	id       uint32
	slots    []slot
	freeHead uint32
	liveHead uint32
	live     int
	closed   bool
}

type slot struct {
	resource Resource
	kind     Kind
	gen      uint16
	freeNext uint32
	livePrev uint32
	liveNext uint32
	retired  bool
}

// NewTable creates a resource table with a process-lifetime-unique identity.
// Table identities are deliberately never reused so a handle cannot become
// valid in a later instance after its original instance is gone.
func NewTable() (*Table, error) {
	id := nextTableID.Add(1)
	if id == 0 || id > math.MaxUint32 {
		return nil, ErrExhausted
	}
	return &Table{id: uint32(id), freeHead: noSlot, liveHead: noSlot}, nil
}

// Add inserts a resource and returns its nonzero handle in O(1) time.
func (t *Table) Add(kind Kind, r Resource) (Handle, error) {
	if t == nil || kind == KindInvalid || r == nil {
		return 0, ErrBadHandle
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, ErrClosed
	}

	var index uint32
	if t.freeHead != noSlot {
		index = t.freeHead
		s := &t.slots[index]
		t.freeHead = s.freeNext
		s.freeNext = noSlot
	} else {
		if len(t.slots) >= math.MaxUint16 {
			return 0, ErrExhausted
		}
		index = uint32(len(t.slots))
		t.slots = append(t.slots, slot{
			gen:      1,
			freeNext: noSlot,
			livePrev: noSlot,
			liveNext: noSlot,
		})
	}

	s := &t.slots[index]
	if s.retired || s.gen == 0 || s.resource != nil {
		return 0, ErrExhausted
	}
	s.resource = r
	s.kind = kind
	s.livePrev = noSlot
	s.liveNext = t.liveHead
	if t.liveHead != noSlot {
		t.slots[t.liveHead].livePrev = index
	}
	t.liveHead = index
	t.live++
	return makeHandle(t.id, s.gen, index), nil
}

// Lookup resolves a handle of the expected kind in O(1) time. Stale, forged,
// wrong-kind, zero, and cross-table handles all return ErrBadHandle.
func (t *Table) Lookup(handle Handle, kind Kind) (Resource, error) {
	if t == nil || kind == KindInvalid {
		return nil, ErrBadHandle
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, ErrClosed
	}
	_, s, err := t.lookupLocked(handle, kind)
	if err != nil {
		return nil, err
	}
	return s.resource, nil
}

// CloseHandle removes and closes one resource. Removal happens before invoking
// Resource.Close, so repeated or concurrent closes cannot close it twice.
func (t *Table) CloseHandle(handle Handle, kind Kind) error {
	if t == nil || kind == KindInvalid {
		return ErrBadHandle
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	index, s, err := t.lookupLocked(handle, kind)
	if err != nil {
		t.mu.Unlock()
		return err
	}
	r := s.resource
	t.removeLocked(index, s)
	t.mu.Unlock()
	return r.Close()
}

// Len returns the number of live resources.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.live
}

// Close deterministically closes all live resources in reverse creation order.
// It is idempotent. Cleanup is O(live), not O(handle-space), and does not
// allocate close scratch proportional to the live resource count.
func (t *Table) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	var errs []error
	for t.liveHead != noSlot {
		index := t.liveHead
		s := &t.slots[index]
		r := s.resource
		t.removeLocked(index, s)
		t.mu.Unlock()
		if err := r.Close(); err != nil {
			errs = append(errs, err)
		}
		t.mu.Lock()
	}
	t.mu.Unlock()
	return errors.Join(errs...)
}

func (t *Table) lookupLocked(handle Handle, kind Kind) (uint32, *slot, error) {
	tableID, generation, index, ok := splitHandle(handle)
	if !ok || tableID != t.id || index >= uint32(len(t.slots)) {
		return 0, nil, ErrBadHandle
	}
	s := &t.slots[index]
	if s.retired || s.resource == nil || s.gen != generation || s.kind != kind {
		return 0, nil, ErrBadHandle
	}
	return index, s, nil
}

func (t *Table) removeLocked(index uint32, s *slot) {
	if s.livePrev == noSlot {
		t.liveHead = s.liveNext
	} else {
		t.slots[s.livePrev].liveNext = s.liveNext
	}
	if s.liveNext != noSlot {
		t.slots[s.liveNext].livePrev = s.livePrev
	}
	s.resource = nil
	s.kind = KindInvalid
	s.livePrev = noSlot
	s.liveNext = noSlot
	t.live--
	if s.gen == math.MaxUint16 {
		s.retired = true
		s.freeNext = noSlot
		return
	}
	s.gen++
	s.freeNext = t.freeHead
	t.freeHead = index
}

func makeHandle(tableID uint32, generation uint16, index uint32) Handle {
	return Handle(uint64(tableID)<<32 | uint64(generation)<<16 | uint64(index+1))
}

func splitHandle(handle Handle) (tableID uint32, generation uint16, index uint32, ok bool) {
	if handle == 0 {
		return 0, 0, 0, false
	}
	tableID = uint32(uint64(handle) >> 32)
	generation = uint16(uint64(handle) >> 16)
	slotID := uint16(handle)
	if tableID == 0 || generation == 0 || slotID == 0 {
		return 0, 0, 0, false
	}
	return tableID, generation, uint32(slotID - 1), true
}

func (k Kind) String() string {
	switch k {
	case KindNamespace:
		return "namespace"
	case KindUDPSocket:
		return "udp_socket"
	case KindTCPListener:
		return "tcp_listener"
	case KindTCPStream:
		return "tcp_stream"
	case KindDNSQuery:
		return "dns_query"
	case KindICMPv4Echo:
		return "icmpv4_echo"
	case KindNTPSync:
		return "ntp_sync"
	case KindMDNSQuery:
		return "mdns_query"
	case KindMDNSAnnouncement:
		return "mdns_announcement"
	case KindDHCPv4Lease:
		return "dhcpv4_lease"
	case KindLinkLocal4Claim:
		return "linklocal4_claim"
	case KindPollable:
		return "pollable"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}
