package resource

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

type testResource struct {
	id     int
	closed atomic.Int32
	events *[]int
	err    error
}

func (r *testResource) Close() error {
	if r.closed.Add(1) != 1 {
		panic("resource closed more than once")
	}
	if r.events != nil {
		*r.events = append(*r.events, r.id)
	}
	return r.err
}

func newTable(t testing.TB) *Table {
	t.Helper()
	table, err := NewTable()
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	return table
}

func TestTableRejectsInvalidStaleWrongKindAndCrossTableHandles(t *testing.T) {
	first := newTable(t)
	second := newTable(t)
	resource := &testResource{}
	handle, err := first.Add(KindUDPSocket, resource)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if handle == 0 {
		t.Fatal("Add returned the invalid zero handle")
	}
	if got, err := first.Lookup(handle, KindUDPSocket); err != nil || got != resource {
		t.Fatalf("Lookup = %v, %v", got, err)
	}

	bad := []struct {
		name   string
		table  *Table
		handle Handle
		kind   Kind
	}{
		{"zero", first, 0, KindUDPSocket},
		{"wrong kind", first, handle, KindTCPStream},
		{"cross table", second, handle, KindUDPSocket},
		{"forged table", first, handle ^ Handle(uint64(1)<<32), KindUDPSocket},
		{"forged generation", first, handle ^ Handle(uint64(1)<<16), KindUDPSocket},
		{"forged slot", first, handle + 1, KindUDPSocket},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.table.Lookup(tc.handle, tc.kind); !errors.Is(err, ErrBadHandle) {
				t.Fatalf("Lookup error = %v, want ErrBadHandle", err)
			}
		})
	}

	if err := first.CloseHandle(handle, KindUDPSocket); err != nil {
		t.Fatalf("CloseHandle: %v", err)
	}
	if resource.closed.Load() != 1 {
		t.Fatalf("close count = %d, want 1", resource.closed.Load())
	}
	if _, err := first.Lookup(handle, KindUDPSocket); !errors.Is(err, ErrBadHandle) {
		t.Fatalf("stale Lookup error = %v, want ErrBadHandle", err)
	}
	if err := first.CloseHandle(handle, KindUDPSocket); !errors.Is(err, ErrBadHandle) {
		t.Fatalf("repeated CloseHandle error = %v, want ErrBadHandle", err)
	}
}

func TestICMPv4EchoKindIsExactAndNamed(t *testing.T) {
	table := newTable(t)
	echo := &testResource{}
	handle, err := table.Add(KindICMPv4Echo, echo)
	if err != nil {
		t.Fatal(err)
	}
	if KindICMPv4Echo.String() != "icmpv4_echo" {
		t.Fatalf("ICMPv4 kind name = %q", KindICMPv4Echo.String())
	}
	if _, err := table.Lookup(handle, KindDNSQuery); !errors.Is(err, ErrBadHandle) {
		t.Fatalf("wrong-kind lookup error = %v", err)
	}
	if err := table.CloseHandle(handle, KindICMPv4Echo); err != nil || echo.closed.Load() != 1 {
		t.Fatalf("close = %v, count=%d", err, echo.closed.Load())
	}
}

func TestNTPSyncKindIsExactAndNamed(t *testing.T) {
	table := newTable(t)
	sync := &testResource{}
	handle, err := table.Add(KindNTPSync, sync)
	if err != nil {
		t.Fatal(err)
	}
	if KindNTPSync.String() != "ntp_sync" {
		t.Fatalf("NTP kind name = %q", KindNTPSync.String())
	}
	if _, err := table.Lookup(handle, KindICMPv4Echo); !errors.Is(err, ErrBadHandle) {
		t.Fatalf("wrong-kind lookup error = %v", err)
	}
	if err := table.CloseHandle(handle, KindNTPSync); err != nil || sync.closed.Load() != 1 {
		t.Fatalf("close = %v, count=%d", err, sync.closed.Load())
	}
}

func TestLinkLocal4ClaimKindIsExactAndNamed(t *testing.T) {
	table := newTable(t)
	claim := &testResource{}
	handle, err := table.Add(KindLinkLocal4Claim, claim)
	if err != nil {
		t.Fatal(err)
	}
	if KindLinkLocal4Claim.String() != "linklocal4_claim" {
		t.Fatalf("link-local kind name = %q", KindLinkLocal4Claim.String())
	}
	if _, err := table.Lookup(handle, KindDHCPv4Lease); !errors.Is(err, ErrBadHandle) {
		t.Fatalf("wrong-kind lookup error = %v", err)
	}
	if err := table.CloseHandle(handle, KindLinkLocal4Claim); err != nil || claim.closed.Load() != 1 {
		t.Fatalf("close = %v, count=%d", err, claim.closed.Load())
	}
}

func TestTableReuseAdvancesGeneration(t *testing.T) {
	table := newTable(t)
	first := &testResource{}
	oldHandle, err := table.Add(KindTCPStream, first)
	if err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := table.CloseHandle(oldHandle, KindTCPStream); err != nil {
		t.Fatalf("first CloseHandle: %v", err)
	}
	second := &testResource{}
	newHandle, err := table.Add(KindTCPStream, second)
	if err != nil {
		t.Fatalf("second Add: %v", err)
	}
	if oldHandle == newHandle {
		t.Fatal("reused slot retained the stale handle")
	}
	oldTable, oldGeneration, oldIndex, _ := splitHandle(oldHandle)
	newTableID, newGeneration, newIndex, _ := splitHandle(newHandle)
	if oldTable != newTableID || oldIndex != newIndex || newGeneration != oldGeneration+1 {
		t.Fatalf("handle reuse = table %d/%d generation %d/%d index %d/%d", oldTable, newTableID, oldGeneration, newGeneration, oldIndex, newIndex)
	}
	if _, err := table.Lookup(oldHandle, KindTCPStream); !errors.Is(err, ErrBadHandle) {
		t.Fatalf("old handle Lookup error = %v", err)
	}
}

func TestTableRetiresSlotBeforeGenerationRollover(t *testing.T) {
	table := newTable(t)
	handle, err := table.Add(KindPollable, &testResource{})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := table.CloseHandle(handle, KindPollable); err != nil {
		t.Fatalf("CloseHandle: %v", err)
	}

	table.mu.Lock()
	table.slots[0].gen = ^uint16(0)
	table.mu.Unlock()
	lastGeneration, err := table.Add(KindPollable, &testResource{})
	if err != nil {
		t.Fatalf("Add max generation: %v", err)
	}
	if _, generation, index, ok := splitHandle(lastGeneration); !ok || generation != ^uint16(0) || index != 0 {
		t.Fatalf("max-generation handle = %#x", lastGeneration)
	}
	if err := table.CloseHandle(lastGeneration, KindPollable); err != nil {
		t.Fatalf("CloseHandle max generation: %v", err)
	}
	next, err := table.Add(KindPollable, &testResource{})
	if err != nil {
		t.Fatalf("Add after retirement: %v", err)
	}
	if _, _, index, _ := splitHandle(next); index != 1 {
		t.Fatalf("post-rollover slot = %d, want 1", index)
	}
	if _, err := table.Lookup(lastGeneration, KindPollable); !errors.Is(err, ErrBadHandle) {
		t.Fatalf("retired handle Lookup error = %v", err)
	}
}

func TestTableCloseIsDeterministicIdempotentAndJoinsErrors(t *testing.T) {
	table := newTable(t)
	var events []int
	firstErr := errors.New("first close")
	resources := []*testResource{
		{id: 1, events: &events, err: firstErr},
		{id: 2, events: &events},
		{id: 3, events: &events},
	}
	for _, resource := range resources {
		if _, err := table.Add(KindNamespace, resource); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if got := table.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3", got)
	}
	if err := table.Close(); !errors.Is(err, firstErr) {
		t.Fatalf("Close error = %v, want joined first error", err)
	}
	if !reflect.DeepEqual(events, []int{3, 2, 1}) {
		t.Fatalf("close order = %v, want [3 2 1]", events)
	}
	if got := table.Len(); got != 0 {
		t.Fatalf("Len after Close = %d", got)
	}
	if err := table.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := table.Add(KindNamespace, &testResource{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Add after Close error = %v, want ErrClosed", err)
	}
	if _, err := table.Lookup(1, KindNamespace); !errors.Is(err, ErrClosed) {
		t.Fatalf("Lookup after Close error = %v, want ErrClosed", err)
	}
	for i, resource := range resources {
		if resource.closed.Load() != 1 {
			t.Fatalf("resource %d close count = %d", i, resource.closed.Load())
		}
	}
}

func TestTableConcurrentCloseIsExactlyOnce(t *testing.T) {
	table := newTable(t)
	const count = 64
	resources := make([]*testResource, count)
	for i := range resources {
		resources[i] = &testResource{}
		if _, err := table.Add(KindDNSQuery, resources[i]); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = table.Close()
		}()
	}
	wg.Wait()
	for i, resource := range resources {
		if resource.closed.Load() != 1 {
			t.Fatalf("resource %d close count = %d", i, resource.closed.Load())
		}
	}
}

type preloadedCloseResource struct{ closed bool }

func (r *preloadedCloseResource) Close() error {
	if r.closed {
		panic("preloaded resource closed more than once")
	}
	r.closed = true
	return nil
}

func TestTableCloseAvoidsLiveCountScratchAllocation(t *testing.T) {
	const count = 128
	allocsFor := func(count int) float64 {
		backing := make([]slot, count)
		resources := make([]preloadedCloseResource, count)
		missingClose := -1
		allocs := testing.AllocsPerRun(1000, func() {
			missingClose = -1
			for i := range backing {
				resources[i].closed = false
				backing[i] = slot{
					resource: &resources[i],
					kind:     KindNamespace,
					gen:      1,
					freeNext: noSlot,
					livePrev: noSlot,
					liveNext: noSlot,
				}
				if i != 0 {
					backing[i].livePrev = uint32(i - 1)
				}
				if i+1 < count {
					backing[i].liveNext = uint32(i + 1)
				}
			}
			table := Table{id: 1, slots: backing, freeHead: noSlot, liveHead: 0, live: count}
			if err := table.Close(); err != nil {
				panic(err)
			}
			for i := range resources {
				if !resources[i].closed {
					missingClose = i
					return
				}
			}
		})
		if missingClose >= 0 {
			t.Fatalf("count=%d resource %d was not closed", count, missingClose)
		}
		return allocs
	}
	smallAllocs := allocsFor(1)
	largeAllocs := allocsFor(count)
	if largeAllocs != smallAllocs {
		t.Fatalf("Close allocations = %v for %d resources, want %v for 1 resource", largeAllocs, count, smallAllocs)
	}
}

func TestConcurrentCloseHandleRemovesBeforeClosing(t *testing.T) {
	table := newTable(t)
	resource := &testResource{}
	handle, err := table.Add(KindUDPSocket, resource)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if table.CloseHandle(handle, KindUDPSocket) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || resource.closed.Load() != 1 {
		t.Fatalf("successes=%d closes=%d, want 1/1", successes.Load(), resource.closed.Load())
	}
}

func TestKindString(t *testing.T) {
	if got := KindUDPSocket.String(); got != "udp_socket" {
		t.Fatalf("KindUDPSocket.String = %q", got)
	}
	if got := Kind(255).String(); got != "kind(255)" {
		t.Fatalf("unknown Kind.String = %q", got)
	}
}

func FuzzTableHandles(f *testing.F) {
	f.Add(uint64(0), uint8(KindUDPSocket))
	f.Add(^uint64(0), uint8(KindTCPStream))
	f.Fuzz(func(t *testing.T, raw uint64, rawKind uint8) {
		table := newTable(t)
		resource := &testResource{}
		handle, err := table.Add(KindUDPSocket, resource)
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		candidate := Handle(raw)
		if raw&1 != 0 {
			candidate ^= handle
		}
		kind := Kind(rawKind)
		got, err := table.Lookup(candidate, kind)
		if err == nil {
			if candidate != handle || kind != KindUDPSocket || got != resource {
				t.Fatalf("unexpected successful lookup: handle=%#x kind=%d resource=%v", candidate, kind, got)
			}
		} else if !errors.Is(err, ErrBadHandle) {
			t.Fatalf("Lookup error = %v", err)
		}
	})
}

func BenchmarkTableLookup(b *testing.B) {
	table := newTable(b)
	handle, err := table.Add(KindTCPStream, &testResource{})
	if err != nil {
		b.Fatalf("Add: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := table.Lookup(handle, KindTCPStream); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTableLookupParallel(b *testing.B) {
	table := newTable(b)
	handle, err := table.Add(KindTCPStream, &testResource{})
	if err != nil {
		b.Fatalf("Add: %v", err)
	}
	b.ReportAllocs()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			if _, err := table.Lookup(handle, KindTCPStream); err != nil {
				panic(err)
			}
		}
	})
}

func BenchmarkTableCloseLive(b *testing.B) {
	for _, count := range []int{1, 64, 1024} {
		b.Run(fmt.Sprintf("resources=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				table := newTable(b)
				for range count {
					if _, err := table.Add(KindUDPSocket, &testResource{}); err != nil {
						b.Fatal(err)
					}
				}
				if err := table.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTableClosePreloaded(b *testing.B) {
	for _, count := range []int{1, 64, 1024} {
		b.Run(fmt.Sprintf("resources=%d", count), func(b *testing.B) {
			backing := make([]slot, count)
			resources := make([]preloadedCloseResource, count)
			reset := func() Table {
				for i := range backing {
					resources[i].closed = false
					backing[i] = slot{
						resource: &resources[i],
						kind:     KindNamespace,
						gen:      1,
						freeNext: noSlot,
						livePrev: noSlot,
						liveNext: noSlot,
					}
					if i != 0 {
						backing[i].livePrev = uint32(i - 1)
					}
					if i+1 < count {
						backing[i].liveNext = uint32(i + 1)
					}
				}
				return Table{id: 1, slots: backing, freeHead: noSlot, liveHead: 0, live: count}
			}
			b.ReportAllocs()
			for range b.N {
				table := reset()
				if err := table.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
