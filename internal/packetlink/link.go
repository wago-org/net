// Package packetlink provides deterministic fixed-capacity frame ownership for
// one networking namespace. Caller-owned frame slices are copied before a call
// returns, and all retained bytes are discarded synchronously by Close.
package packetlink

import (
	"errors"
	"math"
	"sync"
)

var (
	ErrInvalidConfig = errors.New("net: invalid packet link config")
	ErrInvalidQueue  = errors.New("net: invalid packet link queue")
	ErrClosed        = errors.New("net: packet link closed")
	ErrQueueFull     = errors.New("net: packet link queue full")
	ErrFrameTooLarge = errors.New("net: packet link frame too large")
	ErrFrameBudget   = errors.New("net: packet link frame exceeds byte budget")
	ErrInvalidFill   = errors.New("net: invalid packet link fill result")
)

// Queue identifies one direction relative to the namespace stack.
type Queue uint8

const (
	Ingress Queue = iota + 1
	Egress
)

// Config fixes all storage allocated by a Link. MaxFrameBytes must be positive,
// and both queue capacities must be positive; zero is never an unlimited value.
type Config struct {
	MaxFrameBytes int
	IngressFrames int
	EgressFrames  int
}

// FrameResult describes one dequeued frame. FrameBytes is the original frame
// length and Copied is the prefix copied to the caller. Ready distinguishes an
// empty frame from an empty queue.
type FrameResult struct {
	Copied     int
	FrameBytes int
	Truncated  bool
	Ready      bool
}

// Valid reports whether the result is internally consistent for a destination
// buffer of size bytes.
func (r FrameResult) Valid(size int) bool {
	if size < 0 || r.Copied < 0 || r.FrameBytes < 0 || r.Copied > size || r.Copied > r.FrameBytes {
		return false
	}
	if !r.Ready {
		return r.Copied == 0 && r.FrameBytes == 0 && !r.Truncated
	}
	return r.Truncated == (r.Copied < r.FrameBytes)
}

// Snapshot is an immutable queue-depth snapshot.
type Snapshot struct {
	MaxFrameBytes   int
	IngressFrames   int
	IngressBytes    int
	IngressCapacity int
	EgressFrames    int
	EgressBytes     int
	EgressCapacity  int
	Closed          bool
}

// Link owns fixed ingress and egress frame storage. All methods are safe for
// concurrent use. A Fill callback runs while the link lock is held and must be
// immediate; this reserves one queue slot so failure cannot consume backend
// output when the queue is full.
type Link struct {
	mu            sync.Mutex
	maxFrameBytes int
	ingress       frameQueue
	egress        frameQueue
	closed        bool
}

type frameQueue struct {
	storage []byte
	lengths []int
	head    int
	count   int
	bytes   int
}

// New creates a link with exactly the configured frame slots.
func New(config Config) (*Link, error) {
	if !validConfig(config) {
		return nil, ErrInvalidConfig
	}
	return &Link{
		maxFrameBytes: config.MaxFrameBytes,
		ingress:       newFrameQueue(config.IngressFrames, config.MaxFrameBytes),
		egress:        newFrameQueue(config.EgressFrames, config.MaxFrameBytes),
	}, nil
}

// MaxFrameBytes returns the immutable maximum retained frame size.
func (l *Link) MaxFrameBytes() int {
	if l == nil {
		return 0
	}
	return l.maxFrameBytes
}

// TryEnqueue copies one complete frame into queue. Queue-full and oversized
// failures leave queue contents unchanged and retain no caller bytes.
func (l *Link) TryEnqueue(queue Queue, frame []byte) error {
	if l == nil {
		return ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	q, err := l.queue(queue)
	if err != nil {
		return err
	}
	if len(frame) > l.maxFrameBytes {
		return ErrFrameTooLarge
	}
	if q.count == len(q.lengths) {
		return ErrQueueFull
	}
	q.push(frame)
	return nil
}

// TryFill reserves one queue slot and lets fill write directly into link-owned
// storage. A zero-length successful fill means no frame was available. Errors,
// invalid lengths, and zero-length results roll back the slot and clear bytes
// written by fill. The callback must not retain dst after returning.
func (l *Link) TryFill(queue Queue, fill func(dst []byte) (int, error)) (FrameResult, error) {
	if l == nil {
		return FrameResult{}, ErrClosed
	}
	if fill == nil {
		return FrameResult{}, ErrInvalidFill
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return FrameResult{}, ErrClosed
	}
	q, err := l.queue(queue)
	if err != nil {
		return FrameResult{}, err
	}
	if q.count == len(q.lengths) {
		return FrameResult{}, ErrQueueFull
	}
	slot := q.tail()
	dst := q.slot(slot, l.maxFrameBytes)
	n, fillErr := fill(dst)
	if fillErr != nil {
		clear(dst)
		return FrameResult{}, fillErr
	}
	if n < 0 {
		clear(dst)
		return FrameResult{}, ErrInvalidFill
	}
	if n > l.maxFrameBytes {
		clear(dst)
		return FrameResult{}, ErrFrameTooLarge
	}
	if n == 0 {
		clear(dst)
		return FrameResult{}, nil
	}
	q.lengths[slot] = n
	q.count++
	q.bytes += n
	return FrameResult{Copied: n, FrameBytes: n, Ready: true}, nil
}

// TryDequeue copies and removes the oldest frame. If dst is smaller than the
// frame, the unread suffix is discarded and Truncated is true.
func (l *Link) TryDequeue(queue Queue, dst []byte) (FrameResult, error) {
	return l.tryDequeueWithin(queue, dst, math.MaxInt)
}

// TryDequeueWithin copies and removes the oldest frame only when its original
// size is at most maxFrameBytes. ErrFrameBudget leaves the frame queued, which
// lets a bounded service call stop without partially consuming work.
func (l *Link) TryDequeueWithin(queue Queue, dst []byte, maxFrameBytes int) (FrameResult, error) {
	if maxFrameBytes < 0 {
		return FrameResult{}, ErrFrameBudget
	}
	return l.tryDequeueWithin(queue, dst, maxFrameBytes)
}

func (l *Link) tryDequeueWithin(queue Queue, dst []byte, maxFrameBytes int) (FrameResult, error) {
	if l == nil {
		return FrameResult{}, ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return FrameResult{}, ErrClosed
	}
	q, err := l.queue(queue)
	if err != nil {
		return FrameResult{}, err
	}
	if q.count == 0 {
		return FrameResult{}, nil
	}
	frameBytes := q.lengths[q.head]
	if frameBytes > maxFrameBytes {
		return FrameResult{}, ErrFrameBudget
	}
	frame := q.slot(q.head, l.maxFrameBytes)[:frameBytes]
	copied := copy(dst, frame)
	clear(q.slot(q.head, l.maxFrameBytes))
	q.lengths[q.head] = 0
	q.head++
	if q.head == len(q.lengths) {
		q.head = 0
	}
	q.count--
	q.bytes -= frameBytes
	return FrameResult{
		Copied:     copied,
		FrameBytes: frameBytes,
		Truncated:  copied < frameBytes,
		Ready:      true,
	}, nil
}

// Snapshot returns exact committed queue depths. In-progress Fill callbacks are
// serialized and are never visible as committed frames.
func (l *Link) Snapshot() Snapshot {
	if l == nil {
		return Snapshot{Closed: true}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return Snapshot{
		MaxFrameBytes:   l.maxFrameBytes,
		IngressFrames:   l.ingress.count,
		IngressBytes:    l.ingress.bytes,
		IngressCapacity: len(l.ingress.lengths),
		EgressFrames:    l.egress.count,
		EgressBytes:     l.egress.bytes,
		EgressCapacity:  len(l.egress.lengths),
		Closed:          l.closed,
	}
}

// Close synchronously clears all retained frame bytes and permanently rejects
// new work. It is idempotent.
func (l *Link) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.ingress.clear()
	l.egress.clear()
	return nil
}

func (l *Link) queue(queue Queue) (*frameQueue, error) {
	switch queue {
	case Ingress:
		return &l.ingress, nil
	case Egress:
		return &l.egress, nil
	default:
		return nil, ErrInvalidQueue
	}
}

func validConfig(config Config) bool {
	if config.MaxFrameBytes <= 0 || config.IngressFrames <= 0 || config.EgressFrames <= 0 {
		return false
	}
	return config.IngressFrames <= math.MaxInt/config.MaxFrameBytes && config.EgressFrames <= math.MaxInt/config.MaxFrameBytes
}

func newFrameQueue(frames, maxFrameBytes int) frameQueue {
	return frameQueue{
		storage: make([]byte, frames*maxFrameBytes),
		lengths: make([]int, frames),
	}
}

func (q *frameQueue) tail() int {
	tail := q.head + q.count
	if tail >= len(q.lengths) {
		tail -= len(q.lengths)
	}
	return tail
}

func (q *frameQueue) slot(index, maxFrameBytes int) []byte {
	start := index * maxFrameBytes
	end := start + maxFrameBytes
	return q.storage[start:end:end]
}

func (q *frameQueue) push(frame []byte) {
	slot := q.tail()
	dst := q.slot(slot, len(q.storage)/len(q.lengths))
	copy(dst, frame)
	q.lengths[slot] = len(frame)
	q.count++
	q.bytes += len(frame)
}

func (q *frameQueue) clear() {
	clear(q.storage)
	clear(q.lengths)
	q.head = 0
	q.count = 0
	q.bytes = 0
}
