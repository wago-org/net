package tls

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type memoryModule struct{ memory []byte }

func (module memoryModule) Memory() []byte { return module.memory }

type attachedMemoryModule struct {
	memoryModule
	instance *wago.Instance
}

func (module attachedMemoryModule) Instance() *wago.Instance { return module.instance }

type pendingInfoStream struct{ endpoint nscore.Endpoint }

func (*pendingInfoStream) Close() error                           { return nil }
func (*pendingInfoStream) Readiness() nscore.Readiness            { return nscore.ReadyConnected }
func (stream *pendingInfoStream) LocalEndpoint() nscore.Endpoint  { return stream.endpoint }
func (stream *pendingInfoStream) RemoteEndpoint() nscore.Endpoint { return stream.endpoint }
func (*pendingInfoStream) TryFinishConnect() (nscore.Progress, error) {
	return nscore.ProgressInProgress, nil
}
func (*pendingInfoStream) TryRead([]byte) (nscore.IOResult, error) {
	return nscore.IOResult{State: nscore.IOWouldBlock}, nil
}
func (*pendingInfoStream) TryWrite([]byte) (nscore.IOResult, error) {
	return nscore.IOResult{State: nscore.IOWouldBlock}, nil
}
func (*pendingInfoStream) TryShutdownWrite() (nscore.Progress, error) {
	return nscore.ProgressInProgress, nil
}
func (*pendingInfoStream) ConnectionInfo() (tlsns.ConnectionInfo, bool) {
	return tlsns.ConnectionInfo{}, false
}

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

	for _, name := range []string{"connection_info", "connection_info_v2"} {
		results[0] = 0
		byName[name].Func(memoryModule{memory}, []uint64{1, ^uint64(0)}, results)
		if got := guest.Status(wago.AsI32(results[0])); got != guest.StatusInvalidArgument {
			t.Fatalf("%s malformed status = %v", name, got)
		}
		if !bytes.Equal(memory, before) {
			t.Fatalf("malformed %s mutated memory", name)
		}

		results[0] = 0
		byName[name].Func(memoryModule{memory}, []uint64{1, 64}, results)
		if got := guest.Status(wago.AsI32(results[0])); got == guest.StatusOK {
			t.Fatalf("%s unexpectedly succeeded without an instance", name)
		}
		if !bytes.Equal(memory, before) {
			t.Fatalf("failed %s mutated output", name)
		}
	}
}

func TestConnectionInfoVersionsLeaveOutputUnchangedOnWouldBlock(t *testing.T) {
	manager, err := instancecore.NewManagerConfigured(instancecore.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("instance state missing")
	}
	stream := &pendingInfoStream{endpoint: nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 443}}
	handle, err := state.Resources().Add(resource.KindTLSStream, stream)
	if err != nil {
		t.Fatal(err)
	}
	bindings := Bindings(plugin.NewHost(manager))
	byName := make(map[string]plugin.Binding, len(bindings))
	for _, binding := range bindings {
		byName[binding.Name] = binding
	}
	memory := bytes.Repeat([]byte{0xa5}, 256)
	before := append([]byte(nil), memory...)
	module := attachedMemoryModule{memoryModule: memoryModule{memory: memory}, instance: instance}
	for _, name := range []string{"connection_info", "connection_info_v2"} {
		results := []uint64{0}
		byName[name].Func(module, []uint64{uint64(handle), 32}, results)
		if got := guest.Status(wago.AsI32(results[0])); got != guest.StatusAgain {
			t.Fatalf("%s status = %v, want AGAIN", name, got)
		}
		if !bytes.Equal(memory, before) {
			t.Fatalf("%s mutated would-block output", name)
		}
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
