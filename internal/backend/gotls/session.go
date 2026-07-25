package gotls

import (
	cryptotls "crypto/tls"
	"sync"

	"github.com/wago-org/net/internal/tlslimits"
)

// boundedClientSessionCache stores serialized TLS resumption state so every
// retained byte is subject to an explicit profile bound. It deliberately
// disables EarlyData before retaining a session; the TLS stream ABI has no
// replay-sensitive 0-RTT operation.
type boundedClientSessionCache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	usedBytes  int
	entries    []clientSessionEntry // least recently used first
}

type clientSessionEntry struct {
	key    string
	ticket []byte
	state  []byte
	size   int
}

func newBoundedClientSessionCache(maxEntries uint16, maxBytes int) (*boundedClientSessionCache, error) {
	if maxEntries == 0 || maxEntries > tlslimits.MaxClientSessionEntries || maxBytes <= 0 || uint64(maxBytes) > tlslimits.MaxClientSessionBytes {
		return nil, ErrInvalidConfig
	}
	return &boundedClientSessionCache{
		maxEntries: int(maxEntries),
		maxBytes:   maxBytes,
		entries:    make([]clientSessionEntry, 0, maxEntries),
	}, nil
}

func (cache *boundedClientSessionCache) Get(key string) (*cryptotls.ClientSessionState, bool) {
	if cache == nil || key == "" {
		return nil, false
	}
	cache.mu.Lock()
	index := cache.index(key)
	if index < 0 {
		cache.mu.Unlock()
		return nil, false
	}
	entry := cache.entries[index]
	if index+1 != len(cache.entries) {
		copy(cache.entries[index:], cache.entries[index+1:])
		cache.entries[len(cache.entries)-1] = entry
	}
	ticket := cloneSessionBytes(entry.ticket)
	encoded := cloneSessionBytes(entry.state)
	cache.mu.Unlock()

	state, err := cryptotls.ParseSessionState(encoded)
	if err != nil {
		cache.remove(key)
		return nil, false
	}
	state.EarlyData = false
	session, err := cryptotls.NewResumptionState(ticket, state)
	if err != nil {
		cache.remove(key)
		return nil, false
	}
	return session, true
}

func (cache *boundedClientSessionCache) Put(key string, session *cryptotls.ClientSessionState) {
	if cache == nil || key == "" {
		return
	}
	if session == nil {
		cache.remove(key)
		return
	}
	ticket, state, err := session.ResumptionState()
	if err != nil || state == nil {
		cache.remove(key)
		return
	}
	encoded, err := state.Bytes()
	if err != nil {
		cache.remove(key)
		return
	}
	clonedState, err := cryptotls.ParseSessionState(encoded)
	if err != nil {
		cache.remove(key)
		return
	}
	clonedState.EarlyData = false
	encoded, err = clonedState.Bytes()
	if err != nil {
		cache.remove(key)
		return
	}
	size := len(key) + len(ticket) + len(encoded)
	if size <= 0 || size > cache.maxBytes {
		cache.remove(key)
		return
	}
	entry := clientSessionEntry{
		key:    string(cloneSessionBytes([]byte(key))),
		ticket: cloneSessionBytes(ticket),
		state:  cloneSessionBytes(encoded),
		size:   size,
	}

	cache.mu.Lock()
	cache.removeLocked(key)
	for len(cache.entries) >= cache.maxEntries || cache.usedBytes+entry.size > cache.maxBytes {
		cache.evictOldestLocked()
	}
	cache.entries = append(cache.entries, entry)
	cache.usedBytes += entry.size
	cache.mu.Unlock()
}

func (cache *boundedClientSessionCache) clear() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	for len(cache.entries) != 0 {
		cache.evictOldestLocked()
	}
	cache.mu.Unlock()
}

func (cache *boundedClientSessionCache) index(key string) int {
	for index := range cache.entries {
		if cache.entries[index].key == key {
			return index
		}
	}
	return -1
}

func (cache *boundedClientSessionCache) remove(key string) {
	cache.mu.Lock()
	cache.removeLocked(key)
	cache.mu.Unlock()
}

func (cache *boundedClientSessionCache) removeLocked(key string) {
	index := cache.index(key)
	if index < 0 {
		return
	}
	cache.clearEntryLocked(index)
	copy(cache.entries[index:], cache.entries[index+1:])
	cache.entries[len(cache.entries)-1] = clientSessionEntry{}
	cache.entries = cache.entries[:len(cache.entries)-1]
}

func (cache *boundedClientSessionCache) evictOldestLocked() {
	if len(cache.entries) == 0 {
		return
	}
	cache.clearEntryLocked(0)
	copy(cache.entries, cache.entries[1:])
	cache.entries[len(cache.entries)-1] = clientSessionEntry{}
	cache.entries = cache.entries[:len(cache.entries)-1]
}

func (cache *boundedClientSessionCache) clearEntryLocked(index int) {
	entry := &cache.entries[index]
	cache.usedBytes -= entry.size
	clear(entry.ticket)
	clear(entry.state)
	*entry = clientSessionEntry{}
}

func cloneSessionBytes(input []byte) []byte {
	output := make([]byte, len(input))
	copy(output, input)
	return output
}
