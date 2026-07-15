package net

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
	"time"

	abicore "github.com/wago-org/net/internal/abi/core"
	linklocalabi "github.com/wago-org/net/internal/abi/linklocal4"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	linklocalbackend "github.com/wago-org/net/internal/backend/lneto/linklocal4"
	linklocalbinding "github.com/wago-org/net/internal/binding/linklocal4"
	nscore "github.com/wago-org/net/internal/namespace/core"
	linklocalns "github.com/wago-org/net/internal/namespace/linklocal4"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type runtimeLinkLocalClock struct{ now time.Time }

func (c *runtimeLinkLocalClock) Now() time.Time          { return c.now }
func (c *runtimeLinkLocalClock) advance(d time.Duration) { c.now = c.now.Add(d) }

type runtimeLinkLocalHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h runtimeLinkLocalHost) Memory() []byte           { return h.memory }
func (h runtimeLinkLocalHost) Instance() *wago.Instance { return h.instance }

func TestActualBackendGuestLinkLocal4SuccessfulFixedABILifecycle(t *testing.T) {
	clock := &runtimeLinkLocalClock{now: time.Unix(1000, 0)}
	limits := QuotaLimits{Resources: 3, LinkLocal4Resources: 1, LinkLocal4Work: 1, ServiceUnits: 8}
	ready := ReadinessConfig{MaxRegistrations: 3}
	extension := New(WithConfig(Config{
		Limits: &limits, Readiness: &ready,
		StaticIPv4: &StaticIPv4Config{
			Hostname: "linklocal-runtime", RandSeed: 71,
			HardwareAddress: [6]byte{2, 0, 0, 0, 0, 71}, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1},
			IPv4Address: netip.IPv4Unspecified(), MTU: 1500,
			Link: PacketLinkConfig{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2},
		},
	}))
	backend := plugin.NewBackend(plugin.BackendLnetoV1, nil, func(base any) (nscore.Service, error) {
		common := base.(*lnetocore.Namespace)
		adapter, err := linklocalbackend.New(common, linklocalbackend.Config{
			MaxClaims: 1, MaxConflicts: 4, MaxServiceAttempts: 64, Seed: 0xc0ffee, Clock: clock,
		})
		if err != nil {
			return nscore.Service{}, err
		}
		return nscore.Service{Key: linklocalns.ServiceKey, Value: adapter}, nil
	})
	module := linklocalbinding.Descriptor(backend).WithAuthority(plugin.NewAuthority(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportLinkLocal4},
		Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{linklocalns.Prefix},
	}}}))
	if err := extension.RegisterModule(module); err != nil {
		t.Fatal(err)
	}

	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatal(err)
	}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, []wago.Capability{CapInfo, CapLinkLocal4}) {
		t.Fatalf("capabilities = %v", got)
	}
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module != Module && spec.Module != LinkLocal4Module {
			t.Fatalf("unselected protocol import leaked: %s.%s", spec.Module, spec.Name)
		}
	}
	compiled, err := runtime.Compile([]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := runtime.Instantiate(context.Background(), compiled)
	if err != nil {
		t.Fatal(err)
	}
	host := runtimeLinkLocalHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 512)}
	state, ok := extension.instanceManager().ForInstance(instance)
	if !ok {
		t.Fatal("missing actual link-local state")
	}
	backendNamespace := concreteNamespace(t, state)
	link := backendNamespace.Link()
	account := state.Quotas()

	if got := callRuntimeLinkLocal(t, runtime, host, "namespace_default", 400); got != StatusOK {
		t.Fatalf("namespace_default = %v", got)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[400:408]))
	request := linklocalns.Request{FirstCandidate: netip.MustParseAddr("169.254.42.7")}
	if !linklocalabi.EncodeRequestV1(host.memory, 0, request) {
		t.Fatal("encode request")
	}
	if got := callRuntimeLinkLocal(t, runtime, host, "claim", uint64(namespaceHandle), 0, 64); got != StatusInProgress {
		t.Fatalf("claim = %v", got)
	}
	claim := resource.Handle(binary.LittleEndian.Uint64(host.memory[64:72]))
	if claim == 0 {
		t.Fatal("zero claim handle")
	}

	beforeInvalid := append([]byte(nil), host.memory...)
	if got := callRuntimeLinkLocal(t, runtime, host, "result", uint64(claim), 480); got != StatusInvalidArgument || !bytes.Equal(host.memory, beforeInvalid) {
		t.Fatalf("short result = %v mutated=%v", got, !bytes.Equal(host.memory, beforeInvalid))
	}

	writePollBudget(host.memory, 176, 3, 3, 1, 1, 1514, 1)
	bound := false
	for attempt := 0; attempt < 24 && !bound; attempt++ {
		clock.advance(3 * time.Second)
		status := callRuntimeLinkLocal(t, runtime, host, "poll", 224, 3, 176, 272)
		if status != StatusOK && status != StatusAgain {
			t.Fatalf("poll %d = %v", attempt, status)
		}
		frame := make([]byte, link.MaxFrameBytes())
		for {
			result, dequeueErr := link.TryDequeue(packetlink.Egress, frame)
			if dequeueErr != nil {
				t.Fatal(dequeueErr)
			}
			if !result.Ready {
				break
			}
			if result.Truncated || result.FrameBytes != 42 {
				t.Fatalf("claim frame = %+v", result)
			}
		}
		resultBefore := append([]byte(nil), host.memory[96:144]...)
		switch got := callRuntimeLinkLocal(t, runtime, host, "result", uint64(claim), 96); got {
		case StatusAgain:
			if !bytes.Equal(host.memory[96:144], resultBefore) {
				t.Fatal("would-block result mutated output")
			}
		case StatusOK:
			bound = true
		default:
			t.Fatalf("result %d = %v", attempt, got)
		}
	}
	if !bound {
		t.Fatal("claim did not become bound")
	}
	endpoint, ok := abicore.DecodeEndpointV1(host.memory, 96)
	if !ok || endpoint.Address != request.FirstCandidate || endpoint.Port != 0 || endpoint.ScopeID != 0 || endpoint.FlowInfo != 0 {
		t.Fatalf("encoded address = %+v, %v", endpoint, ok)
	}
	if subnet := binary.LittleEndian.Uint32(host.memory[128:132]); subnet != 16 {
		t.Fatalf("subnet bits = %d", subnet)
	}
	if conflicts := binary.LittleEndian.Uint32(host.memory[132:136]); conflicts != 0 {
		t.Fatalf("conflicts = %d", conflicts)
	}
	if flags := binary.LittleEndian.Uint32(host.memory[136:140]); flags != linklocalabi.ResultFlagApplied {
		t.Fatalf("result flags = %#x", flags)
	}
	if reserved := binary.LittleEndian.Uint32(host.memory[140:144]); reserved != 0 {
		t.Fatalf("reserved = %#x", reserved)
	}
	if address := runtimeLinkLocalIPv4Address(backendNamespace.(*lnetocore.Namespace)); address != request.FirstCandidate {
		t.Fatalf("applied address = %v", address)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 2, LinkLocal4Resources: 1, LinkLocal4Work: 1}) {
		t.Fatalf("bound quota = %+v, closed=%v", usage, closed)
	}

	if got := callRuntimeLinkLocal(t, runtime, host, "release", uint64(claim)); got != StatusOK {
		t.Fatalf("release = %v", got)
	}
	if address := runtimeLinkLocalIPv4Address(backendNamespace.(*lnetocore.Namespace)); !address.IsUnspecified() {
		t.Fatalf("released address = %v", address)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 2, LinkLocal4Resources: 1}) {
		t.Fatalf("released quota = %+v, closed=%v", usage, closed)
	}
	resultBefore := append([]byte(nil), host.memory[96:144]...)
	if got := callRuntimeLinkLocal(t, runtime, host, "result", uint64(claim), 96); got != StatusInvalidState || !bytes.Equal(host.memory[96:144], resultBefore) {
		t.Fatalf("released result = %v", got)
	}
	if got := callRuntimeLinkLocal(t, runtime, host, "close", uint64(claim)); got != StatusOK {
		t.Fatalf("close = %v", got)
	}
	if got := callRuntimeLinkLocal(t, runtime, host, "release", uint64(claim)); got != StatusBadHandle {
		t.Fatalf("stale release = %v", got)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1}) {
		t.Fatalf("closed claim quota = %+v, closed=%v", usage, closed)
	}

	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	if _, exists := extension.instanceManager().ForInstance(instance); exists {
		t.Fatal("link-local state survived instance close")
	}
	if usage, closed := account.Snapshot(); !closed || usage != (quota.Usage{}) {
		t.Fatalf("instance cleanup quota = %+v, closed=%v", usage, closed)
	}
	if snapshot := link.Snapshot(); !snapshot.Closed || snapshot.IngressFrames != 0 || snapshot.EgressFrames != 0 {
		t.Fatalf("instance cleanup link = %+v", snapshot)
	}
}

func runtimeLinkLocalIPv4Address(namespace *lnetocore.Namespace) netip.Addr {
	namespace.Lock()
	defer namespace.Unlock()
	return namespace.IPv4AddressLocked()
}

func callRuntimeLinkLocal(t testing.TB, runtime *wago.Runtime, host runtimeLinkLocalHost, name string, params ...uint64) Status {
	t.Helper()
	function, ok := runtime.HostImports()[linklocalbinding.Module+"."+name].(wago.HostFunc)
	if !ok {
		t.Fatalf("link-local import %q missing", name)
	}
	var results [1]uint64
	function(host, params, results[:])
	return Status(int32(results[0]))
}
