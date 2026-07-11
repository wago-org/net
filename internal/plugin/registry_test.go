package plugin

import (
	"errors"
	"testing"

	wago "github.com/wago-org/wago"
)

func TestSetRejectsInvalidDuplicateAndFrozenModules(t *testing.T) {
	install := func(*wago.Registry, Host) {}
	var set Set
	if err := set.Add(NewModule("", install)); !errors.Is(err, ErrInvalidModule) {
		t.Fatalf("empty key = %v", err)
	}
	if err := set.Add(NewModule(ModuleTCP, nil)); !errors.Is(err, ErrInvalidModule) {
		t.Fatalf("nil installer = %v", err)
	}
	if err := set.Add(NewModule(ModuleTCP, install)); err != nil {
		t.Fatalf("Add TCP: %v", err)
	}
	if err := set.Add(NewModule(ModuleTCP, install)); !errors.Is(err, ErrDuplicateModule) {
		t.Fatalf("duplicate TCP = %v", err)
	}
	set.Freeze()
	if err := set.Add(NewModule(ModuleUDP, install)); !errors.Is(err, ErrFrozen) {
		t.Fatalf("Add after Freeze = %v", err)
	}
}

func TestFreezeReturnsIndependentStableSnapshots(t *testing.T) {
	install := func(*wago.Registry, Host) {}
	var set Set
	if err := set.Add(NewModule(ModuleTCP, install)); err != nil {
		t.Fatalf("Add TCP: %v", err)
	}
	first := set.Freeze()
	if len(first) != 1 || first[0].key != ModuleTCP {
		t.Fatalf("first snapshot = %+v", first)
	}
	first[0] = Module{}
	second := set.Freeze()
	if len(second) != 1 || second[0].key != ModuleTCP || second[0].install == nil {
		t.Fatalf("second snapshot changed through caller mutation: %+v", second)
	}
}
