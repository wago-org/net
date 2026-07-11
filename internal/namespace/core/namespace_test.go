package core

import (
	"errors"
	"fmt"
	"net/netip"
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
