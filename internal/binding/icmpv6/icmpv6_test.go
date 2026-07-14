package icmpv6

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	icmpabi "github.com/wago-org/net/internal/abi/icmpv6"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type testHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h testHost) Memory() []byte           { return h.memory }
func (h testHost) Instance() *wago.Instance { return h.instance }

type fakeEcho struct {
	payload []byte
	failure error
}

func (*fakeEcho) Close() error                { return nil }
func (*fakeEcho) Cancel() error               { return nil }
func (*fakeEcho) Readiness() nscore.Readiness { return nscore.ReadyICMPv6Reply }
func (e *fakeEcho) TryResult(dst []byte) (icmpns.EchoResult, icmpns.Next, error) {
	copied := copy(dst, e.payload)
	return icmpns.EchoResult{
		Source:       netip.MustParseAddr("2001:db8::2"),
		Identifier:   1,
		Sequence:     2,
		Copied:       copied,
		PayloadBytes: len(e.payload),
	}, icmpns.NextReady, e.failure
}

func TestEchoResultBindingLeavesOutputsUnchangedOnBackendError(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindICMPv6Echo, &fakeEcho{payload: []byte("mutated"), failure: errors.New("backend failed")})
	if err != nil {
		t.Fatal(err)
	}

	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 256)}
	payloadPtr, payloadLen, resultPtr := uint64(16), uint64(16), uint64(64)
	beforePayload := append([]byte(nil), host.memory[payloadPtr:payloadPtr+payloadLen]...)
	beforeResult := append([]byte(nil), host.memory[resultPtr:resultPtr+uint64(icmpabi.EchoResultV1Size)]...)
	var results [1]uint64
	EchoResult(plugin.NewHost(manager), host, []uint64{uint64(handle), payloadPtr, payloadLen, resultPtr}, results[:])
	if status := guest.Status(int32(results[0])); status != guest.StatusOther {
		t.Fatalf("status = %v", status)
	}
	if !bytes.Equal(host.memory[payloadPtr:payloadPtr+payloadLen], beforePayload) {
		t.Fatalf("payload mutated on error: %x", host.memory[payloadPtr:payloadPtr+payloadLen])
	}
	if !bytes.Equal(host.memory[resultPtr:resultPtr+uint64(icmpabi.EchoResultV1Size)], beforeResult) {
		t.Fatalf("result mutated on error")
	}
}

func BenchmarkEchoResultBindingReady(b *testing.B) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		b.Fatal(err)
	}
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindICMPv6Echo, &fakeEcho{payload: bytes.Repeat([]byte{0x5a}, 256)})
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, 1024)}
	function := Bindings(plugin.NewHost(manager))[3].Func
	params := []uint64{uint64(handle), 0, 256, 512}
	var results [1]uint64
	function(host, params, results[:])
	if status := guest.Status(int32(results[0])); status != guest.StatusOK {
		b.Fatalf("warmup status = %v", status)
	}
	b.ReportAllocs()
	b.SetBytes(256)
	b.ResetTimer()
	for b.Loop() {
		function(host, params, results[:])
	}
}
