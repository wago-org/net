package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	dhcpabi "github.com/wago-org/net/internal/abi/dhcpv6"
	"github.com/wago-org/net/internal/guest"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
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

type fakeNamespace struct{ lease *fakeLease }

func (*fakeNamespace) Operations() dhcpns.Operations { return dhcpns.SupportedOperations }
func (n *fakeNamespace) TryAcquire() (nscore.Resource, nscore.Progress, error) {
	return n.lease, nscore.ProgressInProgress, nil
}

type fakeLease struct{ configuration dhcpns.Configuration }

func (*fakeLease) Close() error                { return nil }
func (*fakeLease) Cancel() error               { return nil }
func (*fakeLease) Readiness() nscore.Readiness { return nscore.ReadyDHCPv6Result }
func (l *fakeLease) TryResult() (dhcpns.Configuration, dhcpns.ResultState, error) {
	return l.configuration, dhcpns.ResultReady, nil
}

func TestResultBindingChecksMemoryAndEncodesReadyConfiguration(t *testing.T) {
	configuration := dhcpns.Configuration{
		TransactionID:            0x123456,
		IAID:                     [4]byte{2, 0, 0, 1},
		AssignedAddr:             netip.MustParseAddr("2001:db8::10"),
		ServerAddr:               netip.MustParseAddr("fe80::2"),
		ServerScopeID:            7,
		ServerDUIDLength:         10,
		PreferredLifetimeSeconds: 1800,
		ValidLifetimeSeconds:     3600,
	}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2})
	lease := &fakeLease{configuration: configuration}
	manager, err := instancecore.NewManagerConfigured(instancecore.Config{
		Limits: quota.DefaultLimits(), Readiness: instancecore.DefaultConfig().Readiness,
		NamespaceFactory: func(*policy.Policy, *quota.Account) (nscore.Namespace, error) {
			return nscore.ComposeNamespace(&fakeBase{}, nscore.Service{Key: dhcpns.ServiceKey, Value: &fakeNamespace{lease: lease}})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	instance := new(wago.Instance)
	if err := manager.Attach(instance); err != nil {
		t.Fatal(err)
	}
	defer manager.Detach(instance)
	host := testHost{instance: instance, memory: make([]byte, 4096)}
	bindings := Bindings(plugin.NewHost(manager))

	namespace := callBinding(t, bindingByName(t, bindings, "namespace_default"), host, 400)
	if namespace.status != guest.StatusOK {
		t.Fatalf("namespace = %v", namespace.status)
	}
	namespaceHandle := binary.LittleEndian.Uint64(host.memory[400:408])
	started := callBinding(t, bindingByName(t, bindings, "start"), host, namespaceHandle, uint64(dhcpns.OperationAcquire), 320)
	if started.status != guest.StatusInProgress {
		t.Fatalf("start = %v", started.status)
	}
	leaseHandle := binary.LittleEndian.Uint64(host.memory[320:328])

	before := bytes.Repeat([]byte{0xa5}, 16)
	copy(host.memory[:16], before)
	failed := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, uint64(len(host.memory)-1))
	if failed.status != guest.StatusInvalidArgument || !bytes.Equal(host.memory[:16], before) {
		t.Fatalf("out-of-bounds result = %v", failed.status)
	}
	for i := range host.memory[:dhcpabi.ConfigurationV1Size] {
		host.memory[i] = 0xa5
	}
	ready := callBinding(t, bindingByName(t, bindings, "result"), host, leaseHandle, 0)
	if ready.status != guest.StatusOK || binary.LittleEndian.Uint32(host.memory[:4]) != configuration.TransactionID ||
		host.memory[dhcpabi.ConfigurationV1Size-1] != 0 {
		t.Fatalf("ready result = %v xid=%x", ready.status, binary.LittleEndian.Uint32(host.memory[:4]))
	}
}

type bindingResult struct{ status guest.Status }

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

func callBinding(t testing.TB, function wago.HostFunc, host testHost, params ...uint64) bindingResult {
	t.Helper()
	var results [1]uint64
	function(host, params, results[:])
	return bindingResult{status: guest.Status(int32(results[0]))}
}
