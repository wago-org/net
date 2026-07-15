package plugin

import (
	"testing"

	wago "github.com/wago-org/wago"
)

func TestRegisterBindingsAcceptsCompleteBackendNeutralTable(t *testing.T) {
	called := false
	bindings := []Binding{{
		Name: "poll", Func: func(wago.HostModule, []uint64, []uint64) { called = true },
		Params: []wago.ValType{wago.ValI32}, Results: []wago.ValType{wago.ValI32},
		Capability: "net.test", Docs: "bounded test binding",
	}}
	RegisterBindings(new(wago.Registry).ImportModule("wago_net_test"), bindings)
	if called {
		t.Fatal("registration invoked host function")
	}
	bindings[0].Func(nil, nil, nil)
	if !called {
		t.Fatal("registered host function was not preserved")
	}
}
