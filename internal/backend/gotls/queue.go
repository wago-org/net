package gotls

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var errBridgeClosed = errors.New("net/tls: bridge closed")

type byteRing struct {
	buffer []byte
	head   int
	length int
}

func newByteRing(size int) byteRing { return byteRing{buffer: make([]byte, size)} }
func (ring *byteRing) len() int     { return ring.length }
func (ring *byteRing) free() int    { return len(ring.buffer) - ring.length }

func (ring *byteRing) write(src []byte) int {
	count := min(len(src), ring.free())
	if count == 0 {
		return 0
	}
	tail := (ring.head + ring.length) % len(ring.buffer)
	first := min(count, len(ring.buffer)-tail)
	copy(ring.buffer[tail:tail+first], src[:first])
	copy(ring.buffer[:count-first], src[first:count])
	ring.length += count
	return count
}

func (ring *byteRing) read(dst []byte) int {
	count := ring.peek(dst)
	ring.discard(count)
	return count
}

func (ring *byteRing) peek(dst []byte) int {
	count := min(len(dst), ring.length)
	if count == 0 {
		return 0
	}
	first := min(count, len(ring.buffer)-ring.head)
	copy(dst[:first], ring.buffer[ring.head:ring.head+first])
	copy(dst[first:count], ring.buffer[:count-first])
	return count
}

func (ring *byteRing) discard(count int) {
	if count <= 0 {
		return
	}
	if count > ring.length {
		count = ring.length
	}
	ring.head = (ring.head + count) % len(ring.buffer)
	ring.length -= count
	if ring.length == 0 {
		ring.head = 0
	}
}

func (ring *byteRing) clear() {
	clear(ring.buffer)
	ring.head = 0
	ring.length = 0
}

// bridgeConn is the bounded blocking endpoint used only by crypto/tls workers.
// Host calls interact through nonblocking feed/peek methods below.
type bridgeConn struct {
	mu   sync.Mutex
	cond *sync.Cond

	inbound  byteRing
	outbound byteRing
	closed   bool
	peerEOF  bool
	err      error

	handshake         bool
	handshakeBytes    int
	maxHandshakeBytes int
}

func newBridgeConn(receiveBytes, transmitBytes, maxHandshakeBytes int) *bridgeConn {
	conn := &bridgeConn{
		inbound: newByteRing(receiveBytes), outbound: newByteRing(transmitBytes),
		handshake: true, maxHandshakeBytes: maxHandshakeBytes,
	}
	conn.cond = sync.NewCond(&conn.mu)
	return conn
}

func (conn *bridgeConn) Read(dst []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	for conn.inbound.len() == 0 && !conn.peerEOF && !conn.closed {
		conn.cond.Wait()
	}
	if conn.inbound.len() != 0 {
		count := conn.inbound.read(dst)
		conn.cond.Broadcast()
		return count, nil
	}
	if conn.err != nil {
		return 0, conn.err
	}
	if conn.peerEOF {
		return 0, io.EOF
	}
	return 0, errBridgeClosed
}

func (conn *bridgeConn) Write(src []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	written := 0
	for written < len(src) {
		for conn.outbound.free() == 0 && !conn.closed {
			conn.cond.Wait()
		}
		if conn.closed {
			if conn.err != nil {
				return written, conn.err
			}
			return written, errBridgeClosed
		}
		written += conn.outbound.write(src[written:])
		conn.cond.Broadcast()
	}
	return written, nil
}

func (conn *bridgeConn) Close() error                     { conn.abort(nil); return nil }
func (conn *bridgeConn) LocalAddr() net.Addr              { return bridgeAddress("local") }
func (conn *bridgeConn) RemoteAddr() net.Addr             { return bridgeAddress("remote") }
func (conn *bridgeConn) SetDeadline(time.Time) error      { return nil }
func (conn *bridgeConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *bridgeConn) SetWriteDeadline(time.Time) error { return nil }

type bridgeAddress string

func (address bridgeAddress) Network() string { return "wago-tls" }
func (address bridgeAddress) String() string  { return string(address) }

func (conn *bridgeConn) abort(err error) {
	if conn == nil {
		return
	}
	conn.mu.Lock()
	if !conn.closed {
		conn.closed = true
		conn.err = err
		conn.cond.Broadcast()
	}
	conn.mu.Unlock()
}

func (conn *bridgeConn) finishHandshake() {
	conn.mu.Lock()
	conn.handshake = false
	conn.cond.Broadcast()
	conn.mu.Unlock()
}

func (conn *bridgeConn) feedCipher(src []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closed {
		return 0, errBridgeClosed
	}
	count := min(len(src), conn.inbound.free())
	if conn.handshake && count > conn.maxHandshakeBytes-conn.handshakeBytes {
		conn.closed = true
		conn.err = ErrHandshakeLimit
		conn.cond.Broadcast()
		return 0, ErrHandshakeLimit
	}
	count = conn.inbound.write(src[:count])
	if conn.handshake {
		conn.handshakeBytes += count
	}
	if count != 0 {
		conn.cond.Broadcast()
	}
	return count, nil
}

func (conn *bridgeConn) inboundFree() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closed {
		return 0
	}
	return conn.inbound.free()
}

func (conn *bridgeConn) peekCipher(dst []byte) int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.outbound.peek(dst)
}

func (conn *bridgeConn) discardCipher(count int) {
	conn.mu.Lock()
	conn.outbound.discard(count)
	if count != 0 {
		conn.cond.Broadcast()
	}
	conn.mu.Unlock()
}

func (conn *bridgeConn) cipherPending() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.outbound.len()
}

func (conn *bridgeConn) setPeerEOF() {
	conn.mu.Lock()
	conn.peerEOF = true
	conn.cond.Broadcast()
	conn.mu.Unlock()
}
