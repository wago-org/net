package core

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestEndpointStructuralValidation(t *testing.T) {
	valid := []Endpoint{
		{Address: netip.MustParseAddr("192.0.2.1"), Port: 80},
		{Address: netip.MustParseAddr("2001:db8::1"), Port: 443, FlowInfo: 0xabcde},
		{Address: netip.MustParseAddr("fe80::1"), Port: 53, ScopeID: 2},
		{Address: netip.MustParseAddr("ff02::1"), Port: 9999, ScopeID: 3},
	}
	for _, endpoint := range valid {
		if !endpoint.Valid() {
			t.Fatalf("valid endpoint rejected: %+v", endpoint)
		}
	}
	invalid := []Endpoint{
		{},
		{Address: netip.MustParseAddr("::ffff:192.0.2.1"), Port: 80},
		{Address: netip.MustParseAddr("192.0.2.1"), ScopeID: 1},
		{Address: netip.MustParseAddr("192.0.2.1"), FlowInfo: 1},
		{Address: netip.MustParseAddr("2001:db8::1"), ScopeID: 1},
		{Address: netip.MustParseAddr("2001:db8::1"), FlowInfo: 0x10_0000},
		{Address: netip.MustParseAddr("fe80::1%eth0"), ScopeID: 1},
	}
	for _, endpoint := range invalid {
		if endpoint.Valid() {
			t.Fatalf("invalid endpoint accepted: %+v", endpoint)
		}
	}
}

func TestProtocolResultReadinessIsKnown(t *testing.T) {
	if !ReadyICMPv4Reply.Valid() || !(ReadyICMPv4Reply | ReadyError | ReadyClosed).Valid() {
		t.Fatal("ICMPv4 reply readiness rejected")
	}
	if !ReadyNTPResult.Valid() || !(ReadyNTPResult | ReadyError | ReadyClosed).Valid() {
		t.Fatal("NTP result readiness rejected")
	}
	if !ReadyMDNSResult.Valid() || !ReadyMDNSAnnouncement.Valid() || !(ReadyMDNSResult | ReadyMDNSAnnouncement | ReadyError | ReadyClosed).Valid() {
		t.Fatal("mDNS readiness rejected")
	}
	if !ReadyICMPv6Reply.Valid() || !ReadyICMPv6Neighbor.Valid() || !(ReadyICMPv6Reply | ReadyICMPv6Neighbor | ReadyError | ReadyClosed).Valid() {
		t.Fatal("ICMPv6 readiness rejected")
	}
	if Readiness(1 << 31).Valid() {
		t.Fatal("unknown readiness bit accepted")
	}
}

func TestSharedResultAndServiceContracts(t *testing.T) {
	for _, result := range []IOResult{{Bytes: 3, State: IOReady}, {State: IOWouldBlock}, {State: IOEOF}} {
		if !result.Valid(3) {
			t.Fatalf("valid I/O result rejected: %+v", result)
		}
	}
	for _, result := range []IOResult{{Bytes: -1, State: IOReady}, {Bytes: 4, State: IOReady}, {Bytes: 1, State: IOWouldBlock}, {Bytes: 1, State: IOEOF}, {State: 99}} {
		if result.Valid(3) {
			t.Fatalf("invalid I/O result accepted: %+v", result)
		}
	}

	budget := ServiceBudget{Packets: 2, Bytes: 128, Operations: 4}
	if !(ServiceReport{Packets: 2, Bytes: 128, Operations: 4}).ValidResult(budget, ProgressDone) {
		t.Fatal("exact service budget rejected")
	}
	if !(ServiceReport{}).ValidResult(budget, ProgressWouldBlock) || (ServiceReport{}).ValidResult(budget, ProgressDone) {
		t.Fatal("service progress semantics accepted an ambiguous result")
	}
	if (ServiceReport{Packets: 3}).ValidFor(budget) || (ServiceReport{Bytes: 129}).ValidFor(budget) || (ServiceReport{Operations: 5}).ValidFor(budget) {
		t.Fatal("over-budget service report accepted")
	}
}

type compositionBase struct {
	closed atomic.Int32
}

func (*compositionBase) Readiness() Readiness { return ReadyWritable }
func (*compositionBase) TryService(ServiceBudget) (ServiceReport, Progress, error) {
	return ServiceReport{}, ProgressWouldBlock, nil
}
func (b *compositionBase) Close() error {
	b.closed.CompareAndSwap(0, 1)
	return nil
}

func TestNamespaceCompositionAvoidsPerServiceHeapGrowthForPlannedSuite(t *testing.T) {
	if runtime.Compiler == "tinygo" {
		return
	}
	base := new(compositionBase)
	one := compositionServices(1)
	planned := compositionServices(11)
	overflow := compositionServices(InlineServiceCapacity + 1)
	for _, test := range []struct {
		name     string
		services []Service
		want     float64
	}{
		{name: "empty", want: 1},
		{name: "single", services: one, want: 1},
		{name: "planned", services: planned, want: 1},
		{name: "overflow", services: overflow, want: 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1000, func() {
				composed, err := ComposeNamespace(base, test.services...)
				if err != nil {
					t.Fatal(err)
				}
				carrier, ok := composed.(ServiceCarrier)
				if !ok {
					t.Fatalf("composed namespace type = %T", composed)
				}
				for _, service := range test.services {
					if got, exists := carrier.NamespaceService(service.Key); !exists || got != service.Value {
						t.Fatalf("resolved %q = %T %v", service.Key, got, exists)
					}
				}
			})
			if allocs != test.want {
				t.Fatalf("ComposeNamespace allocs = %v, want %v", allocs, test.want)
			}
		})
	}
}

func compositionServices(count int) []Service {
	services := make([]Service, count)
	for i := range services {
		value := new(int)
		*value = i
		services[i] = Service{Key: ServiceKey(fmt.Sprintf("service-%d", i)), Value: value}
	}
	return services
}

func TestNamespaceCompositionExactServicesAndLifecycle(t *testing.T) {
	empty, err := ComposeNamespace(new(compositionBase))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := empty.(ServiceCarrier).NamespaceService("tcp"); exists {
		t.Fatal("empty composition exposed TCP")
	}

	singleService := new(int)
	single, err := ComposeNamespace(new(compositionBase), Service{Key: "tcp", Value: singleService})
	if err != nil {
		t.Fatal(err)
	}
	if got, exists := single.(ServiceCarrier).NamespaceService("tcp"); !exists || got != singleService {
		t.Fatalf("single TCP service = %T %v", got, exists)
	}
	if _, exists := single.(ServiceCarrier).NamespaceService("udp"); exists {
		t.Fatal("single composition exposed UDP")
	}

	base := new(compositionBase)
	tcpService := new(int)
	udpService := new(string)
	composed, err := ComposeNamespace(base,
		Service{Key: "tcp", Value: tcpService},
		Service{Key: "udp", Value: udpService},
	)
	if err != nil {
		t.Fatal(err)
	}
	carrier, ok := composed.(ServiceCarrier)
	if !ok {
		t.Fatalf("composed namespace type = %T", composed)
	}
	if got, exists := carrier.NamespaceService("tcp"); !exists || got != tcpService {
		t.Fatalf("TCP service = %T %v", got, exists)
	}
	if got, exists := carrier.NamespaceService("udp"); !exists || got != udpService {
		t.Fatalf("UDP service = %T %v", got, exists)
	}
	if got, exists := carrier.NamespaceService("dns"); exists || got != nil {
		t.Fatalf("omitted DNS service = %T %v", got, exists)
	}
	if composed.Readiness() != ReadyWritable {
		t.Fatalf("readiness = %v", composed.Readiness())
	}
	if report, progress, err := composed.TryService(ServiceBudget{Packets: 1, Bytes: 1, Operations: 1}); err != nil || report != (ServiceReport{}) || progress != ProgressWouldBlock {
		t.Fatalf("service = %+v %v %v", report, progress, err)
	}
	if err := composed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := composed.Close(); err != nil {
		t.Fatal(err)
	}
	if base.closed.Load() != 1 {
		t.Fatalf("base close state = %d, want one closed owner", base.closed.Load())
	}
}

func TestNamespaceCompositionRejectsInvalidAndDuplicateServices(t *testing.T) {
	base := new(compositionBase)
	for _, test := range []struct {
		name     string
		base     Namespace
		services []Service
		want     error
	}{
		{name: "nil base", want: ErrInvalidNamespaceComposition},
		{name: "empty key", base: base, services: []Service{{Value: new(int)}}, want: ErrInvalidNamespaceComposition},
		{name: "nil value", base: base, services: []Service{{Key: "tcp"}}, want: ErrInvalidNamespaceComposition},
		{name: "duplicate", base: base, services: []Service{{Key: "tcp", Value: new(int)}, {Key: "tcp", Value: new(int)}}, want: ErrDuplicateNamespaceService},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ComposeNamespace(test.base, test.services...); !errors.Is(err, test.want) {
				t.Fatalf("ComposeNamespace error = %v, want %v", err, test.want)
			}
		})
	}

	direct := new(compositionBase)
	if got := ResolveNamespaceService(direct, "tcp"); got != direct {
		t.Fatalf("direct service = %T", got)
	}
	composed, err := ComposeNamespace(base, Service{Key: "tcp", Value: direct})
	if err != nil {
		t.Fatal(err)
	}
	if got := ResolveNamespaceService(composed, "tcp"); got != direct {
		t.Fatalf("resolved service = %T", got)
	}
	if got := ResolveNamespaceService(composed, "dns"); got != nil {
		t.Fatalf("omitted service = %T", got)
	}
}

func TestBackendFailureCategoriesSurviveWrapping(t *testing.T) {
	cause := errors.New("backend detail")
	err := fmt.Errorf("adapter: %w", Fail(FailureRemoteUnreachable, cause))
	failure, ok := FailureOf(err)
	if !ok || failure != FailureRemoteUnreachable || !errors.Is(err, cause) {
		t.Fatalf("FailureOf = %v, %v; error=%v", failure, ok, err)
	}
	failure, ok = FailureOf(Fail(Failure(255), cause))
	if !ok || failure != FailureIO {
		t.Fatalf("invalid failure fallback = %v, %v", failure, ok)
	}
	if _, ok := FailureOf(cause); ok {
		t.Fatal("uncategorized backend error acquired a failure category")
	}
}
