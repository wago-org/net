package gotls

import (
	"bytes"
	"sync"
	"testing"
)

func TestByteRingWrapAndPartialIO(t *testing.T) {
	ring := newByteRing(5)
	if ring.write([]byte("abcd")) != 4 {
		t.Fatal("initial write")
	}
	out := make([]byte, 3)
	if ring.read(out) != 3 || string(out) != "abc" {
		t.Fatalf("read = %q", out)
	}
	if ring.write([]byte("efgh")) != 4 {
		t.Fatal("wrapped write")
	}
	out = make([]byte, 5)
	if ring.read(out) != 5 || string(out) != "defgh" {
		t.Fatalf("wrapped read = %q", out)
	}
}

func TestBridgeHandshakeLimitFailsClosed(t *testing.T) {
	bridge := newBridgeConn(32, 32, 4)
	if count, err := bridge.feedCipher([]byte("1234")); err != nil || count != 4 {
		t.Fatalf("first feed = %d, %v", count, err)
	}
	if count, err := bridge.feedCipher([]byte("5")); err != ErrHandshakeLimit || count != 0 {
		t.Fatalf("limit feed = %d, %v", count, err)
	}
}

func TestBridgePeerEOFIsExactlyOnceAndCloseRaceIsIdle(t *testing.T) {
	bridge := newBridgeConn(32, 32, 64)
	if !bridge.setPeerEOF() {
		t.Fatal("first peer EOF was not a transition")
	}
	if bridge.setPeerEOF() {
		t.Fatal("repeated peer EOF reported work")
	}
	if count, err := bridge.Read(make([]byte, 1)); count != 0 || err == nil {
		t.Fatalf("peer EOF read = %d, %v", count, err)
	}
	bridge.abort(nil)
	if bridge.setPeerEOF() {
		t.Fatal("peer EOF after close reported work")
	}
}

func TestBridgePeerEOFRacesCloseWithoutDeadlock(t *testing.T) {
	for range 1000 {
		bridge := newBridgeConn(32, 32, 64)
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			bridge.setPeerEOF()
		}()
		go func() {
			defer workers.Done()
			<-start
			bridge.abort(nil)
		}()
		close(start)
		workers.Wait()
		if bridge.setPeerEOF() {
			t.Fatal("terminal bridge accepted a later EOF transition")
		}
	}
}

func FuzzByteRing(f *testing.F) {
	f.Add([]byte("abcdef"), uint8(3))
	f.Fuzz(func(t *testing.T, input []byte, split uint8) {
		ring := newByteRing(32)
		input = input[:min(len(input), 32)]
		written := ring.write(input)
		first := min(written, int(split)%33)
		out := make([]byte, written)
		ring.read(out[:first])
		ring.read(out[first:])
		if !bytes.Equal(out, input[:written]) {
			t.Fatalf("round trip = %x, want %x", out, input[:written])
		}
	})
}
