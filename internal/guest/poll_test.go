package guest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	abicore "github.com/wago-org/net/internal/abi/core"
	instancecore "github.com/wago-org/net/internal/instance/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/plugin"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/resource"
	wago "github.com/wago-org/wago"
)

type pollTestHost struct {
	instance *wago.Instance
	memory   []byte
}

func (h pollTestHost) Memory() []byte           { return h.memory }
func (h pollTestHost) Instance() *wago.Instance { return h.instance }

type pollNamespace struct {
	ready         nscore.Readiness
	report        nscore.ServiceReport
	progress      nscore.Progress
	failure       error
	serviceCalls  int
	closeCalls    int
	quota         *quota.Account
	serviceUsage  quota.Usage
	serviceClosed bool
}

func (n *pollNamespace) Readiness() nscore.Readiness { return n.ready }
func (n *pollNamespace) Close() error {
	n.closeCalls++
	return nil
}
func (n *pollNamespace) TryService(nscore.ServiceBudget) (nscore.ServiceReport, nscore.Progress, error) {
	n.serviceCalls++
	if n.quota != nil {
		n.serviceUsage, n.serviceClosed = n.quota.Snapshot()
	}
	return n.report, n.progress, n.failure
}

func TestPollPrevalidatesBudgetAndCompleteOutputs(t *testing.T) {
	manager := instancecore.NewManager()
	host := pollTestHost{instance: new(wago.Instance), memory: bytes.Repeat([]byte{0xa5}, 128)}
	pluginHost := plugin.NewHost(manager)

	writePollBudget(host.memory, 0, 1, 1, 0, 0, 0, 0)
	before := append([]byte(nil), host.memory...)
	if status := callPoll(pluginHost, host, 32, 1, 120, 64); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("short budget range = %v", status)
	}
	if status := callPoll(pluginHost, host, 32, ^uint32(0), 0, 64); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("capacity overflow = %v", status)
	}

	writePollBudget(host.memory, 0, 0, 1, 0, 0, 0, 0)
	before = append(before[:0], host.memory...)
	if status := callPoll(pluginHost, host, 32, 1, 0, 64); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("zero scans = %v", status)
	}
	writePollBudget(host.memory, 0, 1, 2, 0, 0, 0, 0)
	before = append(before[:0], host.memory...)
	if status := callPoll(pluginHost, host, 32, 1, 0, 64); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("events over capacity = %v", status)
	}
	writePollBudget(host.memory, 0, 1, 1, 1, 1, 0, 1)
	before = append(before[:0], host.memory...)
	if status := callPoll(pluginHost, host, 32, 1, 0, 64); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("invalid service budget = %v", status)
	}
	writePollBudget(host.memory, 0, 1, 1, 0, 0, 0, 0)
	before = append(before[:0], host.memory...)
	if status := callPoll(pluginHost, host, 32, 1, 0, 40); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("overlapping outputs = %v", status)
	}
	if status := callPoll(pluginHost, host, 120, 1, 0, 64); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("short event output = %v", status)
	}
	if status := callPoll(pluginHost, host, 32, 1, 0, 112); status != StatusInvalidArgument || !bytes.Equal(host.memory, before) {
		t.Fatalf("short result output = %v", status)
	}
	if status := callPoll(pluginHost, host, 32, 1, 0, 64); status != StatusInvalidState || !bytes.Equal(host.memory, before) {
		t.Fatalf("unattached poll = %v", status)
	}
}

func TestPollPublishesAgainReadyAndStaleResultsAtomically(t *testing.T) {
	backend := &pollNamespace{}
	manager, instance := attachPollManager(t, backend, quota.DefaultLimits())
	defer manager.Detach(instance)
	host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0xa5}, 128)}
	pluginHost := plugin.NewHost(manager)
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	handle := state.NamespaceHandle()
	writePollBudget(host.memory, 0, 1, 1, 0, 0, 0, 0)

	eventBefore := append([]byte(nil), host.memory[32:48]...)
	if status := callPoll(pluginHost, host, 32, 1, 0, 64); status != StatusAgain {
		t.Fatalf("empty poll = %v", status)
	}
	if !bytes.Equal(host.memory[32:48], eventBefore) {
		t.Fatal("AGAIN mutated unused event")
	}
	assertPollResult(t, host.memory[64:88], 0, 1, 0, 0, 0)

	backend.ready = nscore.ReadyReadable | nscore.ReadyWritable
	copy(host.memory[32:48], eventBefore)
	if status := callPoll(pluginHost, host, 32, 1, 0, 64); status != StatusOK {
		t.Fatalf("ready poll = %v", status)
	}
	if got := resource.Handle(binary.LittleEndian.Uint64(host.memory[32:40])); got != handle {
		t.Fatalf("event handle = %v, want %v", got, handle)
	}
	if got := nscore.Readiness(binary.LittleEndian.Uint32(host.memory[40:44])); got != backend.ready {
		t.Fatalf("event readiness = %v", got)
	}
	if reserved := binary.LittleEndian.Uint32(host.memory[44:48]); reserved != 0 {
		t.Fatalf("event reserved = %#x", reserved)
	}
	assertPollResult(t, host.memory[64:88], 1, 1, 0, 0, 0)

	if err := state.Resources().CloseHandle(handle, resource.KindNamespace); err != nil {
		t.Fatal(err)
	}
	backend.ready = nscore.ReadyReadable
	copy(host.memory[32:48], eventBefore)
	if status := callPoll(pluginHost, host, 32, 1, 0, 64); status != StatusOK {
		t.Fatalf("stale poll = %v", status)
	}
	if !bytes.Equal(host.memory[32:48], eventBefore) {
		t.Fatal("stale poll mutated unused event")
	}
	assertPollResult(t, host.memory[64:88], 0, 1, 0, 0, 1)
	if snapshot := state.Readiness().Snapshot(); snapshot.Registrations != 0 {
		t.Fatalf("stale registration retained: %+v", snapshot)
	}
}

func TestPollQuotaAndBackendFailuresPreserveOutputs(t *testing.T) {
	t.Run("quota", func(t *testing.T) {
		limits := quota.DefaultLimits()
		limits.ServiceUnits = 2
		backend := &pollNamespace{ready: nscore.ReadyReadable}
		manager, instance := attachPollManager(t, backend, limits)
		defer manager.Detach(instance)
		host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x5a}, 128)}
		writePollBudget(host.memory, 0, 2, 1, 0, 0, 0, 0)
		before := append([]byte(nil), host.memory...)
		if status := callPoll(plugin.NewHost(manager), host, 32, 1, 0, 64); status != StatusResourceLimit || backend.serviceCalls != 0 || !bytes.Equal(host.memory, before) {
			t.Fatalf("quota poll = %v, calls=%d", status, backend.serviceCalls)
		}
	})

	t.Run("malformed service", func(t *testing.T) {
		backend := &pollNamespace{progress: nscore.ProgressDone}
		manager, instance := attachPollManager(t, backend, quota.DefaultLimits())
		defer manager.Detach(instance)
		host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x3c}, 128)}
		writePollBudget(host.memory, 0, 1, 1, 1, 1, 64, 1)
		before := append([]byte(nil), host.memory...)
		if status := callPoll(plugin.NewHost(manager), host, 32, 1, 0, 64); status != StatusIO || backend.serviceCalls != 1 || !bytes.Equal(host.memory, before) {
			t.Fatalf("malformed service poll = %v, calls=%d", status, backend.serviceCalls)
		}
	})

	t.Run("backend error", func(t *testing.T) {
		backend := &pollNamespace{failure: nscore.Fail(nscore.FailureTemporary, errors.New("temporary"))}
		manager, instance := attachPollManager(t, backend, quota.DefaultLimits())
		defer manager.Detach(instance)
		host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x7e}, 128)}
		writePollBudget(host.memory, 0, 1, 1, 1, 1, 64, 1)
		before := append([]byte(nil), host.memory...)
		if status := callPoll(plugin.NewHost(manager), host, 32, 1, 0, 64); status != StatusTemporaryFailure || backend.serviceCalls != 1 || !bytes.Equal(host.memory, before) {
			t.Fatalf("failed service poll = %v, calls=%d", status, backend.serviceCalls)
		}
	})
}

func TestPollChargesExactInstanceScopedServiceUnits(t *testing.T) {
	backend := &pollNamespace{report: nscore.ServiceReport{Operations: 1}, progress: nscore.ProgressDone, ready: nscore.ReadyReadable}
	manager, instance := attachPollManager(t, backend, quota.DefaultLimits())
	defer manager.Detach(instance)
	state, _ := manager.ForInstance(instance)
	backend.quota = state.Quotas()
	host := pollTestHost{instance: instance, memory: make([]byte, 128)}
	writePollBudget(host.memory, 0, 3, 2, 1, 1, 64, 1)
	if status := callPoll(plugin.NewHost(manager), host, 32, 2, 0, 64); status != StatusOK {
		t.Fatalf("serviced poll = %v", status)
	}
	if backend.serviceUsage.ServiceUnits != 6 || backend.serviceClosed {
		t.Fatalf("in-call service usage = %+v, closed=%v", backend.serviceUsage, backend.serviceClosed)
	}
	usage, closed := state.Quotas().Snapshot()
	if usage.ServiceUnits != 0 || closed {
		t.Fatalf("released service usage = %+v, closed=%v", usage, closed)
	}
	assertPollResult(t, host.memory[64:88], 1, 1, 1, 1, 0)

	foreign := pollTestHost{instance: new(wago.Instance), memory: bytes.Repeat([]byte{0xcc}, 128)}
	writePollBudget(foreign.memory, 0, 1, 1, 0, 0, 0, 0)
	before := append([]byte(nil), foreign.memory...)
	if status := callPoll(plugin.NewHost(manager), foreign, 32, 1, 0, 64); status != StatusInvalidState || !bytes.Equal(foreign.memory, before) {
		t.Fatalf("foreign instance poll = %v", status)
	}
}

func BenchmarkPollReady(b *testing.B) {
	backend := &pollNamespace{ready: nscore.ReadyReadable}
	manager, instance := attachPollManager(b, backend, quota.DefaultLimits())
	defer manager.Detach(instance)
	host := pollTestHost{instance: instance, memory: make([]byte, 128)}
	writePollBudget(host.memory, 0, 1, 1, 0, 0, 0, 0)
	pluginHost := plugin.NewHost(manager)
	params := []uint64{32, 1, 0, 64}
	var results [1]uint64
	Poll(pluginHost, host, params, results[:])
	if status := Status(int32(results[0])); status != StatusOK {
		b.Fatalf("warmup status = %v", status)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		Poll(pluginHost, host, params, results[:])
	}
}

func attachPollManager(t testing.TB, backend *pollNamespace, limits quota.Limits) (*instancecore.Manager, *wago.Instance) {
	t.Helper()
	config := instancecore.DefaultConfig()
	config.Limits = limits
	config.NamespaceFactory = func(*policy.Policy, *quota.Account) (nscore.Namespace, error) { return backend, nil }
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

func callPoll(host plugin.Host, module pollTestHost, eventsPtr, capacity, budgetPtr, resultPtr uint32) Status {
	var results [1]uint64
	Poll(host, module, []uint64{uint64(eventsPtr), uint64(capacity), uint64(budgetPtr), uint64(resultPtr)}, results[:])
	return Status(int32(results[0]))
}

func writePollBudget(memory []byte, ptr, scans, events, attempts, packets, bytes, operations uint32) {
	budget, ok := abicore.Slice(memory, ptr, abicore.PollBudgetV1Size)
	if !ok {
		return
	}
	binary.LittleEndian.PutUint32(budget[0:4], scans)
	binary.LittleEndian.PutUint32(budget[4:8], events)
	binary.LittleEndian.PutUint32(budget[8:12], attempts)
	binary.LittleEndian.PutUint32(budget[12:16], packets)
	binary.LittleEndian.PutUint32(budget[16:20], bytes)
	binary.LittleEndian.PutUint32(budget[20:24], operations)
}

func assertPollResult(t testing.TB, result []byte, events, scanned, attempts, completed, stale uint32) {
	t.Helper()
	if len(result) != int(abicore.PollResultV1Size) {
		t.Fatalf("result length = %d", len(result))
	}
	got := [6]uint32{
		binary.LittleEndian.Uint32(result[0:4]),
		binary.LittleEndian.Uint32(result[4:8]),
		binary.LittleEndian.Uint32(result[8:12]),
		binary.LittleEndian.Uint32(result[12:16]),
		binary.LittleEndian.Uint32(result[16:20]),
		binary.LittleEndian.Uint32(result[20:24]),
	}
	want := [6]uint32{events, scanned, attempts, completed, stale, 0}
	if got != want {
		t.Fatalf("poll result = %v, want %v", got, want)
	}
}
