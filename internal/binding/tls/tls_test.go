package tls

import (
	"bytes"
	"testing"

	"github.com/wago-org/net/internal/guest"
	"github.com/wago-org/net/internal/plugin"
	wago "github.com/wago-org/wago"
)

type memoryModule struct{ memory []byte }

func (module memoryModule) Memory() []byte { return module.memory }

func TestBindingsRejectMalformedAndOverlappingRangesWithoutMutation(t *testing.T) {
	bindings := Bindings(plugin.Host{})
	byName := make(map[string]plugin.Binding, len(bindings))
	for _, binding := range bindings {
		byName[binding.Name] = binding
	}

	memory := bytes.Repeat([]byte{0xa5}, 256)
	before := append([]byte(nil), memory...)
	results := []uint64{0}
	// Endpoint [0,32) overlaps server name [16,20).
	byName["connect"].Func(memoryModule{memory}, []uint64{1, 0, 1, 16, 4, 64}, results)
	if got := guest.Status(wago.AsI32(results[0])); got != guest.StatusInvalidArgument {
		t.Fatalf("connect status = %v", got)
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("malformed connect mutated memory")
	}

	results[0] = 0
	// Payload [0,8) overlaps result [4,12).
	byName["read"].Func(memoryModule{memory}, []uint64{1, 0, 8, 4}, results)
	if got := guest.Status(wago.AsI32(results[0])); got != guest.StatusInvalidArgument {
		t.Fatalf("read status = %v", got)
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("malformed read mutated memory")
	}

	results[0] = 0
	byName["connection_info"].Func(memoryModule{memory}, []uint64{1, ^uint64(0)}, results)
	if got := guest.Status(wago.AsI32(results[0])); got != guest.StatusInvalidArgument {
		t.Fatalf("info status = %v", got)
	}
	if !bytes.Equal(memory, before) {
		t.Fatal("malformed info mutated memory")
	}
}

func TestConnectRejectsInvalidUTF8BeforeInstanceLookup(t *testing.T) {
	var connect plugin.Binding
	for _, binding := range Bindings(plugin.Host{}) {
		if binding.Name == "connect" {
			connect = binding
		}
	}
	memory := make([]byte, 256)
	memory[32] = 0xff
	results := []uint64{0}
	connect.Func(memoryModule{memory}, []uint64{1, 0, 1, 32, 1, 64}, results)
	if got := guest.Status(wago.AsI32(results[0])); got != guest.StatusInvalidArgument {
		t.Fatalf("status = %v", got)
	}
}
