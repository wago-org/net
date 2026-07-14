package ipv6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	ipv6abi "github.com/wago-org/net/internal/abi/ipv6"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	ipv6ns "github.com/wago-org/net/internal/namespace/ipv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type testHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h testHost) Memory() []byte           { return h.memory }
func (h testHost) Instance() *wago.Instance { return h.instance }

type fakeBase struct{}

func (*fakeBase) Close() error                { return nil }
func (*fakeBase) Readiness() nscore.Readiness { return 0 }
func (*fakeBase) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	return nscore.ServiceReport{}, nscore.ProgressWouldBlock, nil
}

type fakeNamespace struct {
	configuration ipv6ns.Configuration
	calls         int
}

func (n *fakeNamespace) Configuration() ipv6ns.Configuration {
	n.calls++
	return n.configuration
}

func TestBindingsConfigurationAtomicStatusesAndLifecycle(t *testing.T) {
	backend := &fakeNamespace{configuration: validConfiguration()}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 256)}
	bindings := Bindings(plugin.NewHost(manager))

	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 240); status != guest.StatusOK {
		t.Fatalf("namespace_default = %v", status)
	}
	namespaceHandle := resource.Handle(binary.LittleEndian.Uint64(host.memory[240:248]))
	if namespaceHandle == 0 {
		t.Fatal("zero namespace handle")
	}

	before := append([]byte(nil), host.memory...)
	for _, ptr := range []uint64{193, uint64(^uint32(0)), uint64(^uint32(0) - ipv6abi.ConfigurationV1Size + 1)} {
		if status := callBinding(t, bindingByName(t, bindings, "configuration"), host, uint64(namespaceHandle), ptr); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
			t.Fatalf("out-of-range configuration pointer %d = %v, calls=%d", ptr, status, backend.calls)
		}
	}

	if status := callBinding(t, bindingByName(t, bindings, "configuration"), host, uint64(namespaceHandle), 64); status != guest.StatusOK || backend.calls != 1 {
		t.Fatalf("configuration = %v, calls=%d", status, backend.calls)
	}
	endpoint, ok := abicore.DecodeEndpointV1(host.memory, 64)
	if !ok || endpoint.Address != backend.configuration.Address || endpoint.ScopeID != 0 || endpoint.Port != 0 || endpoint.FlowInfo != 0 {
		t.Fatalf("endpoint = %+v, ok=%v", endpoint, ok)
	}
	encoded := host.memory[64 : 64+ipv6abi.ConfigurationV1Size]
	if prefix := binary.LittleEndian.Uint32(encoded[32:36]); prefix != 64 {
		t.Fatalf("prefix = %d", prefix)
	}
	if flags := binary.LittleEndian.Uint32(encoded[36:40]); flags != ipv6abi.ConfigurationFlagEnabled {
		t.Fatalf("flags = %#x", flags)
	}
	if transports := binary.LittleEndian.Uint32(encoded[40:44]); transports != uint32(backend.configuration.Transports) {
		t.Fatalf("transports = %#x", transports)
	}
	if mtu := binary.LittleEndian.Uint32(encoded[44:48]); mtu != uint32(backend.configuration.MTU) {
		t.Fatalf("MTU = %d", mtu)
	}
	if maximum := binary.LittleEndian.Uint32(encoded[48:52]); maximum != uint32(backend.configuration.MaxExtensionHeaders) {
		t.Fatalf("max extension headers = %d", maximum)
	}
	for offset, value := range encoded[52:] {
		if value != 0 {
			t.Fatalf("reserved byte %d = %d", offset, value)
		}
	}

	outputBefore := append([]byte(nil), host.memory[128:128+ipv6abi.ConfigurationV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "configuration"), host, 1, 128); status != guest.StatusBadHandle || !bytes.Equal(host.memory[128:128+ipv6abi.ConfigurationV1Size], outputBefore) {
		t.Fatalf("bad handle = %v", status)
	}
	state, _ := manager.ForInstance(instance)
	if err := state.CloseHandle(namespaceHandle, resource.KindNamespace); err != nil {
		t.Fatal(err)
	}
	if status := callBinding(t, bindingByName(t, bindings, "configuration"), host, uint64(namespaceHandle), 128); status != guest.StatusBadHandle || !bytes.Equal(host.memory[128:128+ipv6abi.ConfigurationV1Size], outputBefore) {
		t.Fatalf("stale handle = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 224); status != guest.StatusNotSupported {
		t.Fatalf("namespace_default after close = %v", status)
	}
}

func TestConfigurationPreservesOutputForMissingAndMalformedServices(t *testing.T) {
	for name, tc := range map[string]struct {
		backend ipv6ns.Namespace
		want    guest.Status
	}{
		"missing": {want: guest.StatusNotSupported},
		"invalid": {
			backend: &fakeNamespace{configuration: ipv6ns.Configuration{Address: netip.MustParseAddr("2001:db8::9"), PrefixBits: 64, MTU: 1500}},
			want:    guest.StatusIO,
		},
	} {
		t.Run(name, func(t *testing.T) {
			manager, instance := attachManager(t, tc.backend)
			defer manager.Detach(instance)
			state, _ := manager.ForInstance(instance)
			host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 128)}
			before := append([]byte(nil), host.memory[32:32+ipv6abi.ConfigurationV1Size]...)
			status := callBinding(t, bindingByName(t, Bindings(plugin.NewHost(manager)), "configuration"), host, uint64(state.NamespaceHandle()), 32)
			if status != tc.want || !bytes.Equal(host.memory[32:32+ipv6abi.ConfigurationV1Size], before) {
				t.Fatalf("configuration = %v, output mutated=%v", status, !bytes.Equal(host.memory[32:32+ipv6abi.ConfigurationV1Size], before))
			}
		})
	}
}

func TestBindingsRejectHighBitI32AliasesBeforeStateAndBackendWork(t *testing.T) {
	backend := &fakeNamespace{configuration: validConfiguration()}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0x6d}, 256)}
	bindings := Bindings(plugin.NewHost(manager))
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}

	high := uint64(1) << 32
	tests := []struct {
		name    string
		binding string
		params  []uint64
	}{
		{name: "namespace output", binding: "namespace_default", params: []uint64{high | 240}},
		{name: "configuration output", binding: "configuration", params: []uint64{uint64(state.NamespaceHandle()), high | 64}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := append([]byte(nil), host.memory...)
			calls := backend.calls
			if status := callBinding(t, bindingByName(t, bindings, test.binding), host, test.params...); status != guest.StatusInvalidArgument {
				t.Fatalf("status = %v", status)
			}
			if backend.calls != calls {
				t.Fatalf("backend calls = %d, want %d", backend.calls, calls)
			}
			if !bytes.Equal(host.memory, before) {
				t.Fatal("invalid alias mutated guest memory")
			}
		})
	}
}

func TestBindingsPrevalidateBeforeInstanceLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 32)}
	bindings := Bindings(plugin.NewHost(manager))
	before := append([]byte(nil), host.memory...)
	for _, ptr := range []uint64{25, uint64(^uint32(0)), uint64(^uint32(0) - abicore.HandleV1Size + 1)} {
		if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, ptr); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
			t.Fatalf("namespace range %d = %v", ptr, status)
		}
	}
	for _, ptr := range []uint64{1, uint64(^uint32(0)), uint64(^uint32(0) - ipv6abi.ConfigurationV1Size + 1)} {
		if status := callBinding(t, bindingByName(t, bindings, "configuration"), host, 1, ptr); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
			t.Fatalf("configuration range %d = %v", ptr, status)
		}
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func attachManager(t testing.TB, backend ipv6ns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		if backend == nil {
			return nscore.ComposeNamespace(&fakeBase{})
		}
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: ipv6ns.ServiceKey, Value: backend})
	}
	manager, err := instancecore.NewManagerConfigured(config)
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	return manager, instance
}

func validConfiguration() ipv6ns.Configuration {
	return ipv6ns.Configuration{
		Address: netip.MustParseAddr("2001:db8:42::7"), PrefixBits: 64, MTU: 1500,
		Transports: ipv6ns.TransportTCPConnect | ipv6ns.TransportTCPListen,
	}
}

func bindingByName(t testing.TB, bindings []plugin.Binding, name string) wago.HostFunc {
	t.Helper()
	for _, binding := range bindings {
		if binding.Name == name {
			return binding.Func
		}
	}
	t.Fatalf("binding %q missing", name)
	return nil
}

func callBinding(t testing.TB, function wago.HostFunc, host testHost, params ...uint64) guest.Status {
	t.Helper()
	var results [1]uint64
	function(host, params, results[:])
	return guest.Status(int32(results[0]))
}

func BenchmarkConfigurationBinding(b *testing.B) {
	backend := &fakeNamespace{configuration: validConfiguration()}
	manager, instance := attachManager(b, backend)
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	host := testHost{instance: instance, memory: make([]byte, 128)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "configuration")
	params := []uint64{uint64(state.NamespaceHandle()), 0}
	var results [1]uint64
	function(host, params, results[:])
	if status := guest.Status(int32(results[0])); status != guest.StatusOK {
		b.Fatalf("warmup status = %v", status)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		function(host, params, results[:])
	}
}
