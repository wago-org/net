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
	ready          nscore.Readiness
	report         nscore.ServiceReport
	progress       nscore.Progress
	failure        error
	readinessCalls int
	serviceCalls   int
	closeCalls     int
	quota          *quota.Account
	serviceUsage   quota.Usage
	serviceClosed  bool
}

func (n *pollNamespace) Readiness() nscore.Readiness {
	n.readinessCalls++
	return n.ready
}
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

func TestPollRejectsOutputAliasingBudgetBeforeBackendWork(t *testing.T) {
	backend := &pollNamespace{ready: nscore.ReadyReadable}
	manager, instance := attachPollManager(t, backend, quota.DefaultLimits())
	defer manager.Detach(instance)
	host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x6d}, 128)}
	pluginHost := plugin.NewHost(manager)
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}

	for _, test := range []struct {
		name      string
		eventsPtr uint32
		resultPtr uint32
	}{
		{name: "event output", eventsPtr: 8, resultPtr: 64},
		{name: "result output", eventsPtr: 32, resultPtr: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			for i := range host.memory {
				host.memory[i] = 0x6d
			}
			writePollBudget(host.memory, 0, 1, 1, 0, 0, 0, 0)
			beforeMemory := append([]byte(nil), host.memory...)
			beforeReadiness := state.Readiness().Snapshot()
			beforeQuota, beforeClosed := state.Quotas().Snapshot()
			readinessCalls, serviceCalls := backend.readinessCalls, backend.serviceCalls
			if status := callPoll(pluginHost, host, test.eventsPtr, 1, 0, test.resultPtr); status != StatusInvalidArgument {
				t.Fatalf("status = %v", status)
			}
			if backend.readinessCalls != readinessCalls || backend.serviceCalls != serviceCalls {
				t.Fatalf("poll work changed: readiness=%d service=%d", backend.readinessCalls, backend.serviceCalls)
			}
			if after := state.Readiness().Snapshot(); after != beforeReadiness {
				t.Fatalf("readiness state changed: before=%+v after=%+v", beforeReadiness, after)
			}
			if after, closed := state.Quotas().Snapshot(); after != beforeQuota || closed != beforeClosed {
				t.Fatalf("quota state changed: before=%+v/%v after=%+v/%v", beforeQuota, beforeClosed, after, closed)
			}
			if !bytes.Equal(host.memory, beforeMemory) {
				t.Fatal("invalid output alias mutated guest memory")
			}
		})
	}
}

func TestPollRejectsHighBitI32AliasesBeforeStateQuotaAndPollWork(t *testing.T) {
	backend := &pollNamespace{ready: nscore.ReadyReadable}
	manager, instance := attachPollManager(t, backend, quota.DefaultLimits())
	defer manager.Detach(instance)
	host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x6d}, 128)}
	writePollBudget(host.memory, 0, 1, 1, 0, 0, 0, 0)
	pluginHost := plugin.NewHost(manager)
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	high := uint64(1) << 32
	tests := []struct {
		name   string
		params [4]uint64
	}{
		{name: "events pointer", params: [4]uint64{high | 32, 1, 0, 64}},
		{name: "event capacity", params: [4]uint64{32, high | 1, 0, 64}},
		{name: "budget pointer", params: [4]uint64{32, 1, high, 64}},
		{name: "result pointer", params: [4]uint64{32, 1, 0, high | 64}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			beforeMemory := append([]byte(nil), host.memory...)
			beforeReadiness := state.Readiness().Snapshot()
			beforeQuota, beforeClosed := state.Quotas().Snapshot()
			readinessCalls, serviceCalls := backend.readinessCalls, backend.serviceCalls
			if status := callPollRaw(pluginHost, host, test.params); status != StatusInvalidArgument {
				t.Fatalf("status = %v", status)
			}
			if backend.readinessCalls != readinessCalls || backend.serviceCalls != serviceCalls {
				t.Fatalf("poll work changed: readiness=%d service=%d", backend.readinessCalls, backend.serviceCalls)
			}
			if after := state.Readiness().Snapshot(); after != beforeReadiness {
				t.Fatalf("readiness state changed: before=%+v after=%+v", beforeReadiness, after)
			}
			if after, closed := state.Quotas().Snapshot(); after != beforeQuota || closed != beforeClosed {
				t.Fatalf("quota state changed: before=%+v/%v after=%+v/%v", beforeQuota, beforeClosed, after, closed)
			}
			if !bytes.Equal(host.memory, beforeMemory) {
				t.Fatal("invalid alias mutated guest memory")
			}
		})
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

	t.Run("invalid readiness after service", func(t *testing.T) {
		backend := &pollNamespace{
			ready:    nscore.Readiness(1 << 31),
			report:   nscore.ServiceReport{Operations: 1},
			progress: nscore.ProgressDone,
		}
		manager, instance := attachPollManager(t, backend, quota.DefaultLimits())
		defer manager.Detach(instance)
		host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x91}, 128)}
		writePollBudget(host.memory, 0, 1, 1, 1, 1, 64, 1)
		before := append([]byte(nil), host.memory...)
		if status := callPoll(plugin.NewHost(manager), host, 32, 1, 0, 64); status != StatusIO || backend.serviceCalls != 1 || backend.readinessCalls != 1 || !bytes.Equal(host.memory, before) {
			t.Fatalf("invalid readiness poll = %v, service=%d readiness=%d", status, backend.serviceCalls, backend.readinessCalls)
		}
	})
}

func TestPollInvalidServiceResultRetriesAtomicallyThenRotates(t *testing.T) {
	first := &pollNamespace{progress: nscore.ProgressDone}
	manager, instance := attachPollManager(t, first, quota.DefaultLimits())
	defer manager.Detach(instance)
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	second := &pollNamespace{report: nscore.ServiceReport{Operations: 1}, progress: nscore.ProgressDone}
	secondHandle, err := state.Resources().Add(resource.KindNamespace, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Readiness().Register(secondHandle, resource.KindNamespace); err != nil {
		t.Fatal(err)
	}

	host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x4d}, 160)}
	writePollBudget(host.memory, 0, 2, 2, 1, 1, 64, 1)
	pluginHost := plugin.NewHost(manager)
	before := append([]byte(nil), host.memory...)
	for attempt := 1; attempt <= 2; attempt++ {
		if status := callPoll(pluginHost, host, 32, 2, 0, 80); status != StatusIO {
			t.Fatalf("invalid service attempt %d = %v", attempt, status)
		}
		if first.serviceCalls != attempt || first.readinessCalls != 0 || second.serviceCalls != 0 || second.readinessCalls != 0 {
			t.Fatalf("invalid service calls %d = first service/readiness %d/%d second %d/%d", attempt, first.serviceCalls, first.readinessCalls, second.serviceCalls, second.readinessCalls)
		}
		if !bytes.Equal(host.memory, before) {
			t.Fatalf("invalid service attempt %d mutated guest memory", attempt)
		}
	}

	first.report = nscore.ServiceReport{Operations: 1}
	first.ready = nscore.ReadyReadable
	firstHandle := state.NamespaceHandle()
	if status := callPoll(pluginHost, host, 32, 2, 0, 80); status != StatusOK {
		t.Fatalf("recovered first poll = %v", status)
	}
	if got := resource.Handle(binary.LittleEndian.Uint64(host.memory[32:40])); got != firstHandle {
		t.Fatalf("recovered first event handle = %v, want %v", got, firstHandle)
	}
	assertPollResult(t, host.memory[80:104], 1, 2, 1, 1, 0)
	if first.serviceCalls != 3 || first.readinessCalls != 1 || second.serviceCalls != 0 || second.readinessCalls != 1 {
		t.Fatalf("recovered first calls = first %d/%d second %d/%d", first.serviceCalls, first.readinessCalls, second.serviceCalls, second.readinessCalls)
	}

	second.ready = nscore.ReadyReadable
	if status := callPoll(pluginHost, host, 32, 2, 0, 80); status != StatusOK {
		t.Fatalf("rotated second poll = %v", status)
	}
	if got := resource.Handle(binary.LittleEndian.Uint64(host.memory[32:40])); got != firstHandle {
		t.Fatalf("rotated first event handle = %v, want %v", got, firstHandle)
	}
	if got := resource.Handle(binary.LittleEndian.Uint64(host.memory[48:56])); got != secondHandle {
		t.Fatalf("rotated second event handle = %v, want %v", got, secondHandle)
	}
	assertPollResult(t, host.memory[80:104], 2, 2, 1, 1, 0)
	if first.serviceCalls != 3 || second.serviceCalls != 1 {
		t.Fatalf("service rotation calls = %d/%d", first.serviceCalls, second.serviceCalls)
	}
}

func TestPollFailureAfterEarlierEventPreservesOutputsAndRetryCursors(t *testing.T) {
	first := &pollNamespace{ready: nscore.ReadyReadable, progress: nscore.ProgressWouldBlock}
	manager, instance := attachPollManager(t, first, quota.DefaultLimits())
	defer manager.Detach(instance)
	state, ok := manager.ForInstance(instance)
	if !ok {
		t.Fatal("attached state missing")
	}
	failure := nscore.Fail(nscore.FailureTemporary, errors.New("second service failed"))
	second := &pollNamespace{failure: failure}
	secondHandle, err := state.Resources().Add(resource.KindNamespace, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Readiness().Register(secondHandle, resource.KindNamespace); err != nil {
		t.Fatal(err)
	}

	host := pollTestHost{instance: instance, memory: bytes.Repeat([]byte{0x73}, 160)}
	writePollBudget(host.memory, 0, 2, 2, 2, 1, 64, 1)
	pluginHost := plugin.NewHost(manager)
	before := append([]byte(nil), host.memory...)
	for attempt := 1; attempt <= 2; attempt++ {
		if status := callPoll(pluginHost, host, 32, 2, 0, 96); status != StatusTemporaryFailure {
			t.Fatalf("failed poll %d = %v", attempt, status)
		}
		if first.serviceCalls != 1 || first.readinessCalls != 1 || second.serviceCalls != attempt || second.readinessCalls != 0 {
			t.Fatalf("failed calls %d = first %d/%d second %d/%d", attempt, first.serviceCalls, first.readinessCalls, second.serviceCalls, second.readinessCalls)
		}
		if snapshot := state.Readiness().Snapshot(); snapshot.Cursor != 1 || snapshot.Registrations != 2 {
			t.Fatalf("failed cursor %d = %+v", attempt, snapshot)
		}
		if !bytes.Equal(host.memory, before) {
			t.Fatalf("failed poll %d published partial event or result", attempt)
		}
	}

	second.failure = nil
	second.report = nscore.ServiceReport{Operations: 1}
	second.progress = nscore.ProgressDone
	second.ready = nscore.ReadyWritable
	if status := callPoll(pluginHost, host, 32, 2, 0, 96); status != StatusOK {
		t.Fatalf("recovered poll = %v", status)
	}
	firstHandle := state.NamespaceHandle()
	if got := resource.Handle(binary.LittleEndian.Uint64(host.memory[32:40])); got != secondHandle {
		t.Fatalf("recovered first event = %v, want %v", got, secondHandle)
	}
	if got := resource.Handle(binary.LittleEndian.Uint64(host.memory[48:56])); got != firstHandle {
		t.Fatalf("recovered second event = %v, want %v", got, firstHandle)
	}
	assertPollResult(t, host.memory[96:120], 2, 2, 2, 1, 0)
	if first.serviceCalls != 2 || first.readinessCalls != 2 || second.serviceCalls != 3 || second.readinessCalls != 1 {
		t.Fatalf("recovered calls = first %d/%d second %d/%d", first.serviceCalls, first.readinessCalls, second.serviceCalls, second.readinessCalls)
	}
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
	return callPollRaw(host, module, [4]uint64{uint64(eventsPtr), uint64(capacity), uint64(budgetPtr), uint64(resultPtr)})
}

func callPollRaw(host plugin.Host, module pollTestHost, params [4]uint64) Status {
	var results [1]uint64
	Poll(host, module, params[:], results[:])
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
