package dhcpv4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	dhcpabi "github.com/wago-org/net/internal/abi/dhcpv4"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
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
	lease *fakeLease
	calls int
}

func (n *fakeNamespace) TryAcquire(dhcpns.Request) (nscore.Resource, nscore.Progress, error) {
	n.calls++
	return n.lease, nscore.ProgressInProgress, nil
}

type fakeLease struct {
	lease    dhcpns.Lease
	result   dhcpns.ResultState
	failure  error
	closed   bool
	canceled bool
	released bool
}

func (l *fakeLease) Close() error { l.closed = true; return nil }
func (l *fakeLease) Cancel() error {
	l.canceled = true
	return nil
}
func (l *fakeLease) Release() error { l.released = true; return nil }
func (*fakeLease) Readiness() nscore.Readiness {
	return nscore.ReadyDHCPv4Lease
}
func (l *fakeLease) TryResult() (dhcpns.Lease, dhcpns.ResultState, error) {
	return l.lease, l.result, l.failure
}

func TestBindingsPrevalidateAcquireAndPreserveResultOutputs(t *testing.T) {
	lease := &fakeLease{result: dhcpns.ResultWouldBlock}
	backend := &fakeNamespace{lease: lease}
	manager, instance := attachManager(t, backend)
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 1024)}
	bindings := Bindings(plugin.NewHost(manager))

	namespace := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 900)
	if namespace != guest.StatusOK {
		t.Fatalf("namespace_default = %v", namespace)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[900:908])

	request := dhcpns.Request{RequestedAddr: netip.MustParseAddr("192.0.2.20"), HostnameLength: 4}
	copy(request.Hostname[:], "host")
	if !dhcpabi.EncodeRequestV1(host.memory, 0, request) {
		t.Fatal("encode request")
	}
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "acquire"), host, namespaceHandle, 0, 8); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlap acquire = %v, calls=%d", status, backend.calls)
	}

	host.memory[104] = 1
	outBefore := append([]byte(nil), host.memory[256:264]...)
	if status := callBinding(t, bindingByName(t, bindings, "acquire"), host, namespaceHandle, 0, 256); status != guest.StatusInvalidArgument || backend.calls != 0 || !bytes.Equal(host.memory[256:264], outBefore) {
		t.Fatalf("reserved acquire = %v, calls=%d", status, backend.calls)
	}
	host.memory[104] = 0
	backend.lease = nil
	if status := callBinding(t, bindingByName(t, bindings, "acquire"), host, namespaceHandle, 0, 256); status != guest.StatusIO || backend.calls != 1 || !bytes.Equal(host.memory[256:264], outBefore) {
		t.Fatalf("typed-nil acquire = %v, calls=%d", status, backend.calls)
	}
	backend.lease = lease
	if status := callBinding(t, bindingByName(t, bindings, "acquire"), host, namespaceHandle, 0, 256); status != guest.StatusInProgress || backend.calls != 2 {
		t.Fatalf("valid acquire = %v, calls=%d", status, backend.calls)
	}
	leaseHandle := binary.LittleEndian.Uint64(host.memory[256:264])

	resultBefore := append([]byte(nil), host.memory[400:400+dhcpabi.LeaseV1Size]...)
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, 400); status != guest.StatusAgain || !bytes.Equal(host.memory[400:400+dhcpabi.LeaseV1Size], resultBefore) {
		t.Fatalf("would-block result = %v", status)
	}
	lease.failure = nscore.Fail(nscore.FailureCanceled, errors.New("canceled"))
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, 400); status != guest.StatusCanceled || !bytes.Equal(host.memory[400:400+dhcpabi.LeaseV1Size], resultBefore) {
		t.Fatalf("failed result = %v", status)
	}
	lease.failure = nil
	lease.lease = validLease(t)
	lease.result = dhcpns.ResultReady
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, 400); status != guest.StatusOK || binary.LittleEndian.Uint32(host.memory[532:536]) != lease.lease.LeaseSeconds || host.memory[400+dhcpabi.LeaseV1Size-1] != 0 {
		t.Fatalf("ready result = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, leaseHandle); status != guest.StatusOK || !lease.canceled {
		t.Fatalf("cancel = %v, canceled=%v", status, lease.canceled)
	}
	if status := callBinding(t, bindingByName(t, bindings, "release"), host, leaseHandle); status != guest.StatusOK || !lease.released {
		t.Fatalf("release = %v, released=%v", status, lease.released)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, leaseHandle); status != guest.StatusOK || !lease.closed {
		t.Fatalf("close = %v, closed=%v", status, lease.closed)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, 400); status != guest.StatusBadHandle {
		t.Fatalf("stale result = %v", status)
	}

	fresh := &fakeLease{result: dhcpns.ResultWouldBlock}
	backend.lease = fresh
	if status := callBinding(t, bindingByName(t, bindings, "acquire"), host, namespaceHandle, 0, 264); status != guest.StatusInProgress {
		t.Fatalf("fresh acquire = %v", status)
	}
	freshHandle := binary.LittleEndian.Uint64(host.memory[264:272])
	if freshHandle == leaseHandle || uint16(freshHandle) != uint16(leaseHandle) {
		t.Fatalf("generation-safe slot reuse = old %v, fresh %v", leaseHandle, freshHandle)
	}
	if status := callBinding(t, bindingByName(t, bindings, "cancel"), host, leaseHandle); status != guest.StatusBadHandle || fresh.canceled {
		t.Fatalf("stale cancel = %v, fresh canceled=%v", status, fresh.canceled)
	}
	if status := callBinding(t, bindingByName(t, bindings, "release"), host, leaseHandle); status != guest.StatusBadHandle || fresh.released {
		t.Fatalf("stale release = %v, fresh released=%v", status, fresh.released)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, freshHandle, 400); status != guest.StatusAgain {
		t.Fatalf("fresh result = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "close"), host, freshHandle); status != guest.StatusOK || !fresh.closed {
		t.Fatalf("fresh close = %v, closed=%v", status, fresh.closed)
	}
}

func TestBindingsPrevalidateOutputsBeforeInstanceAndHandleLookup(t *testing.T) {
	manager := instancecore.NewManager()
	instance := new(wago.Instance)
	host := testHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 64)}
	bindings := Bindings(plugin.NewHost(manager))
	before := append([]byte(nil), host.memory...)
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 57); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("out-of-bounds namespace = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "acquire"), host, 1, 0, 60); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("out-of-bounds acquire = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "result"), host, 1, 1); status != guest.StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("out-of-bounds result = %v", status)
	}
	if status := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 0); status != guest.StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached namespace = %v", status)
	}
}

func attachManager(t testing.TB, backend dhcpns.Namespace) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = quota.DefaultLimits()
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
		return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: backend})
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

func validLease(t testing.TB) dhcpns.Lease {
	t.Helper()
	lease := dhcpns.Lease{
		AssignedAddr: netip.MustParseAddr("192.0.2.20"), ServerAddr: netip.MustParseAddr("192.0.2.1"),
		RouterAddr: netip.MustParseAddr("192.0.2.1"), BroadcastAddr: netip.MustParseAddr("192.0.2.255"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, RenewalSeconds: 1800, RebindSeconds: 3150,
		DNSCount: 1, DNSServers: [dhcpns.MaxDNSServers]netip.Addr{netip.MustParseAddr("192.0.2.53")}, Applied: true,
	}
	if !lease.Valid() {
		t.Fatal("invalid lease fixture")
	}
	return lease
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

func BenchmarkResultBindingReady(b *testing.B) {
	lease := &fakeLease{lease: validLease(b), result: dhcpns.ResultReady}
	manager, instance := attachManager(b, &fakeNamespace{lease: lease})
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	handle, err := state.Resources().Add(resource.KindDHCPv4Lease, lease)
	if err != nil {
		b.Fatal(err)
	}
	host := testHost{instance: instance, memory: make([]byte, 512)}
	function := bindingByName(b, Bindings(plugin.NewHost(manager)), "result")
	params := []uint64{uint64(handle), 0}
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
