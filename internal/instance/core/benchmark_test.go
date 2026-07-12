package core

import (
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/readiness"
	wago "github.com/wago-org/wago"
)

var (
	benchmarkState    *State
	benchmarkFound    bool
	benchmarkReport   readiness.Report
	benchmarkProgress nscore.Progress
	benchmarkErr      error
)

func BenchmarkManagerAttachDetach(b *testing.B) {
	manager := NewManager()
	instance := new(wago.Instance)
	b.ReportAllocs()
	for b.Loop() {
		if err := manager.Attach(instance); err != nil {
			b.Fatal(err)
		}
		if err := manager.Detach(instance); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkManagerForInstance(b *testing.B) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		b.Fatal(err)
	}
	defer manager.Detach(instance)
	b.ReportAllocs()
	for b.Loop() {
		benchmarkState, benchmarkFound = manager.ForInstance(instance)
	}
}

func BenchmarkStateWithLock(b *testing.B) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		b.Fatal(err)
	}
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	operation := func(LockedState) error { return nil }
	b.ReportAllocs()
	for b.Loop() {
		benchmarkErr = state.WithLock(operation)
	}
}

func BenchmarkStatePollIdle(b *testing.B) {
	manager := NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		b.Fatal(err)
	}
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	budget := readiness.Budget{Scans: 1, Events: 1}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkReport, benchmarkProgress, benchmarkErr = state.Poll(budget, nil)
		if benchmarkErr != nil || benchmarkProgress != nscore.ProgressWouldBlock {
			b.Fatalf("poll = %+v, %v, %v", benchmarkReport, benchmarkProgress, benchmarkErr)
		}
	}
}
