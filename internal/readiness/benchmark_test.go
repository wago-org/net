package readiness

import (
	"fmt"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/resource"
)

type benchmarkPollable struct{ ready nscore.Readiness }

func (p *benchmarkPollable) Close() error                { return nil }
func (p *benchmarkPollable) Readiness() nscore.Readiness { return p.ready }

type benchmarkService struct{ benchmarkPollable }

func (s *benchmarkService) TryService(budget nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{Packets: 1, Bytes: 64, Operations: 1}, nscore.ProgressDone, nil
}

var (
	benchmarkReport   Report
	benchmarkProgress nscore.Progress
	benchmarkErr      error
)

func BenchmarkCoordinatorRegisterUnregister(b *testing.B) {
	table := newTable(b)
	coordinator := newCoordinator(b, table, Config{MaxRegistrations: 1})
	handle, err := table.Add(resource.KindPollable, &benchmarkPollable{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := coordinator.Register(handle, resource.KindPollable); err != nil {
			b.Fatal(err)
		}
		if !coordinator.Unregister(handle) {
			b.Fatal("unregister")
		}
	}
}

func BenchmarkCoordinatorTryPoll(b *testing.B) {
	for _, count := range []int{1, 16, 256} {
		b.Run(fmt.Sprintf("registrations=%d", count), func(b *testing.B) {
			table := newTable(b)
			coordinator := newCoordinator(b, table, Config{MaxRegistrations: count})
			for range count {
				addAndRegister(b, table, coordinator, resource.KindPollable, &benchmarkPollable{ready: nscore.ReadyReadable})
			}
			events := make([]Event, count)
			budget := Budget{Scans: uint32(count), Events: uint32(count)}
			b.ReportAllocs()
			for b.Loop() {
				benchmarkReport, benchmarkProgress, benchmarkErr = coordinator.TryPoll(events, budget)
				if benchmarkErr != nil || benchmarkReport.Events != uint32(count) {
					b.Fatalf("poll = %+v, %v, %v", benchmarkReport, benchmarkProgress, benchmarkErr)
				}
			}
		})
	}
}

func BenchmarkCoordinatorTryPollParallel(b *testing.B) {
	table := newTable(b)
	coordinator := newCoordinator(b, table, Config{MaxRegistrations: 16})
	for range 16 {
		addAndRegister(b, table, coordinator, resource.KindPollable, &benchmarkPollable{ready: nscore.ReadyReadable})
	}
	budget := Budget{Scans: 16, Events: 16}
	b.ReportAllocs()
	b.RunParallel(func(parallel *testing.PB) {
		events := make([]Event, 16)
		for parallel.Next() {
			report, _, err := coordinator.TryPoll(events, budget)
			if err != nil || report.Events != 16 {
				panic("parallel readiness poll failed")
			}
		}
	})
}

func BenchmarkCoordinatorTryPollService(b *testing.B) {
	table := newTable(b)
	coordinator := newCoordinator(b, table, Config{MaxRegistrations: 1})
	addAndRegister(b, table, coordinator, resource.KindNamespace, &benchmarkService{benchmarkPollable{ready: nscore.ReadyReadable}})
	events := make([]Event, 1)
	budget := Budget{Scans: 1, Events: 1, ServiceAttempts: 1, Service: nscore.ServiceBudget{Packets: 1, Bytes: 64, Operations: 1}}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkReport, benchmarkProgress, benchmarkErr = coordinator.TryPoll(events, budget)
		if benchmarkErr != nil || benchmarkReport.ServiceCompleted != 1 {
			b.Fatalf("poll service = %+v, %v, %v", benchmarkReport, benchmarkProgress, benchmarkErr)
		}
	}
}
