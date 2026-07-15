package dhcpv4

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	lneto "github.com/soypat/lneto"
	lnetodhcp "github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv4"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestImmediateClientServerDORAAppliesAndRollsBackIdentity(t *testing.T) {
	clientCore, client := newClient(t, true)
	serverCore, _ := newServer(t, 2)
	resource, progress, err := client.TryAcquire(dhcpns.Request{})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("acquire = %v, %v", progress, err)
	}
	lease := resource.(*leaseResource)
	for range 2 {
		transferOne(t, clientCore, serverCore)
		transferOne(t, serverCore, clientCore)
	}
	result, state, err := lease.TryResult()
	if err != nil || state != dhcpns.ResultReady || !result.Valid() || !result.Applied || result.AssignedAddr != netip.MustParseAddr("192.0.2.2") {
		t.Fatalf("lease = %+v, %v, %v", result, state, err)
	}
	clientCore.Lock()
	got := clientCore.IPv4AddressLocked()
	clientCore.Unlock()
	if got != result.AssignedAddr {
		t.Fatalf("core address = %v, want %v", got, result.AssignedAddr)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	clientCore.Lock()
	got = clientCore.IPv4AddressLocked()
	clientCore.Unlock()
	if got != netip.IPv4Unspecified() {
		t.Fatalf("rollback address = %v", got)
	}
}

func TestBoundLeaseCloseRollsBackIdentityAndAllowsFreshAcquisition(t *testing.T) {
	clientCore, client := newClient(t, true)
	serverCore, _ := newServer(t, 1)
	resource, _, err := client.TryAcquire(dhcpns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	bound := resource.(*leaseResource)
	for range 2 {
		transferOne(t, clientCore, serverCore)
		transferOne(t, serverCore, clientCore)
	}
	result, state, err := bound.TryResult()
	if err != nil || state != dhcpns.ResultReady || !result.Applied || !bound.identity.Active() {
		t.Fatalf("bound result = %+v, %v, %v identity=%v", result, state, err, bound.identity.Active())
	}
	if err := bound.Close(); err != nil {
		t.Fatal(err)
	}
	clientCore.Lock()
	address := clientCore.IPv4AddressLocked()
	ports := clientCore.UDPPortLeaseCountLocked()
	clientCore.Unlock()
	if address != netip.IPv4Unspecified() || ports != 1 || client.lease != nil || bound.identity.Active() || bound.result != (dhcpns.Lease{}) || bound.request != (dhcpns.Request{}) {
		t.Fatalf("bound close state: address=%v ports=%d mapped=%p identity=%v result=%+v request=%+v", address, ports, client.lease, bound.identity.Active(), bound.result, bound.request)
	}
	if usage, _ := client.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("bound close quota = %+v", usage)
	}
	fresh, progress, err := client.TryAcquire(dhcpns.Request{})
	if err != nil || progress != nscore.ProgressInProgress || fresh == bound {
		t.Fatalf("fresh acquisition = %T, %v, %v stale=%p", fresh, progress, err, bound)
	}
	if err := bound.Close(); err != nil {
		t.Fatal(err)
	}
	if client.lease != fresh {
		t.Fatalf("stale bound close affected fresh lease: mapped=%p fresh=%p", client.lease, fresh)
	}
}

func TestClientRejectsInvalidUnicastRequestBeforeQuotaOwnership(t *testing.T) {
	for name, address := range map[string]netip.Addr{
		"loopback":          netip.MustParseAddr("127.0.0.1"),
		"limited broadcast": limitedBroadcast,
	} {
		t.Run(name, func(t *testing.T) {
			core, adapter := newClient(t, false)
			resource, progress, err := adapter.TryAcquire(dhcpns.Request{RequestedAddr: address})
			if resource != nil || progress != 0 || failureOf(err) != nscore.FailureInvalidArgument {
				t.Fatalf("acquire = %T, %v, %v", resource, progress, err)
			}
			if adapter.lease != nil {
				t.Fatalf("rejected request installed lease %p", adapter.lease)
			}
			if usage, _ := adapter.quotas.Snapshot(); usage != (quota.Usage{}) {
				t.Fatalf("rejected request quota = %+v", usage)
			}
			core.Lock()
			ports := core.UDPPortLeaseCountLocked()
			core.Unlock()
			if ports != 1 {
				t.Fatalf("rejected request changed namespace client port ownership: %d", ports)
			}
		})
	}
}

func TestClientTimeoutCancellationQuotaAndPortOwnership(t *testing.T) {
	core, adapter := newClient(t, false)
	resource, _, err := adapter.TryAcquire(dhcpns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	_ = serviceEgress(t, core)
	for range adapter.config.ResponseServiceAttempts {
		serviceNoFrame(t, core)
	}
	if _, _, err := lease.TryResult(); failureOf(err) != nscore.FailureTimedOut {
		t.Fatalf("timeout = %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	usage, _ := adapter.quotas.Snapshot()
	if usage.DHCPv4Resources != 0 || usage.DHCPv4Work != 0 || usage.QueuedBytes != 0 {
		t.Fatalf("quota after close = %+v", usage)
	}
	core.Lock()
	if core.UDPPortLeaseCountLocked() != 1 {
		core.Unlock()
		t.Fatal("namespace client port lease was not retained")
	}
	core.Unlock()
}

func TestClientDropsLimitedBroadcastLeaseOptionsBeforePinnedMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(testing.TB, []byte) []byte
	}{
		{name: "server", mutate: func(t testing.TB, frame []byte) []byte {
			frame = rewriteDHCPOptionData(t, frame, lnetodhcp.OptServerIdentification, limitedBroadcast.AsSlice())
			return rewriteIPv4Source(t, frame, limitedBroadcast)
		}},
		{name: "router", mutate: func(t testing.TB, frame []byte) []byte {
			return rewriteDHCPOptionData(t, frame, lnetodhcp.OptRouter, limitedBroadcast.AsSlice())
		}},
		{name: "broadcast", mutate: func(t testing.TB, frame []byte) []byte {
			return appendDHCPOption(t, frame, lnetodhcp.OptBroadcastAddress, limitedBroadcast.AsSlice())
		}},
		{name: "DNS", mutate: func(t testing.TB, frame []byte) []byte {
			return rewriteDHCPOptionData(t, frame, lnetodhcp.OptDNSServers, limitedBroadcast.AsSlice())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientCore, client := newClient(t, false)
			serverCore, _ := newServer(t, 1)
			resource, progress, err := client.TryAcquire(dhcpns.Request{})
			if err != nil || progress != nscore.ProgressInProgress {
				t.Fatalf("acquire = %T, %v, %v", resource, progress, err)
			}
			lease := resource.(*leaseResource)
			transferOne(t, clientCore, serverCore)
			offer := serviceEgress(t, serverCore)

			serviceIngress(t, clientCore, test.mutate(t, offer))
			if lease.state != leaseWaitOffer || lease.wait != client.config.ResponseServiceAttempts {
				t.Fatalf("limited-broadcast offer mutated lease: state=%v wait=%d", lease.state, lease.wait)
			}
			serviceIngress(t, clientCore, offer)
			if lease.state != leaseRequest || lease.wait != 0 {
				t.Fatalf("valid offer after malformed option = state:%v wait:%d", lease.state, lease.wait)
			}
			transferOne(t, clientCore, serverCore)
			serviceIngress(t, clientCore, serviceEgress(t, serverCore))
			if result, state, err := lease.TryResult(); err != nil || state != dhcpns.ResultReady || !result.Valid() {
				t.Fatalf("valid lease after malformed option = %+v, %v, %v", result, state, err)
			}
		})
	}
}

func TestClientDropsLoopbackLeaseOptionsBeforePinnedMutation(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	for _, test := range []struct {
		name   string
		mutate func(testing.TB, []byte) []byte
	}{
		{name: "server", mutate: func(t testing.TB, frame []byte) []byte {
			frame = rewriteDHCPOptionData(t, frame, lnetodhcp.OptServerIdentification, loopback.AsSlice())
			return rewriteIPv4Source(t, frame, loopback)
		}},
		{name: "router", mutate: func(t testing.TB, frame []byte) []byte {
			return appendDHCPOption(t, frame, lnetodhcp.OptRouter, loopback.AsSlice())
		}},
		{name: "broadcast", mutate: func(t testing.TB, frame []byte) []byte {
			return appendDHCPOption(t, frame, lnetodhcp.OptBroadcastAddress, loopback.AsSlice())
		}},
		{name: "DNS", mutate: func(t testing.TB, frame []byte) []byte {
			return appendDHCPOption(t, frame, lnetodhcp.OptDNSServers, loopback.AsSlice())
		}},
	} {
		for _, stage := range []string{"OFFER", "ACK"} {
			t.Run(stage+"/"+test.name, func(t *testing.T) {
				clientCore, client := newClient(t, false)
				serverCore, _ := newServer(t, 1)
				resource, progress, err := client.TryAcquire(dhcpns.Request{})
				if err != nil || progress != nscore.ProgressInProgress {
					t.Fatalf("acquire = %T, %v, %v", resource, progress, err)
				}
				lease := resource.(*leaseResource)
				transferOne(t, clientCore, serverCore)
				offer := serviceEgress(t, serverCore)
				if stage == "OFFER" {
					serviceIngress(t, clientCore, test.mutate(t, offer))
					if lease.state != leaseWaitOffer || lease.wait != client.config.ResponseServiceAttempts {
						t.Fatalf("loopback offer mutated lease: state=%v wait=%d", lease.state, lease.wait)
					}
					serviceIngress(t, clientCore, offer)
				} else {
					serviceIngress(t, clientCore, offer)
				}
				if lease.state != leaseRequest || lease.wait != 0 {
					t.Fatalf("valid offer after malformed option = state:%v wait:%d", lease.state, lease.wait)
				}
				transferOne(t, clientCore, serverCore)
				ack := serviceEgress(t, serverCore)
				if stage == "ACK" {
					serviceIngress(t, clientCore, test.mutate(t, ack))
					if lease.state != leaseWaitACK || lease.wait != client.config.ResponseServiceAttempts {
						t.Fatalf("loopback ACK mutated lease: state=%v wait=%d", lease.state, lease.wait)
					}
				}
				serviceIngress(t, clientCore, ack)
				if result, state, err := lease.TryResult(); err != nil || state != dhcpns.ResultReady || !result.Valid() {
					t.Fatalf("valid lease after loopback option = %+v, %v, %v", result, state, err)
				}
			})
		}
	}
}

func TestClientDropsMalformedLeaseOptionShapesBeforePinnedMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		option lnetodhcp.OptNum
		data   []byte
	}{
		{name: "router not IPv4 aligned", option: lnetodhcp.OptRouter, data: []byte{192, 0, 2}},
		{name: "broadcast short", option: lnetodhcp.OptBroadcastAddress, data: []byte{192, 0, 2}},
		{name: "broadcast multiple", option: lnetodhcp.OptBroadcastAddress, data: []byte{192, 0, 2, 255, 192, 0, 2, 254}},
		{name: "DNS not IPv4 aligned", option: lnetodhcp.OptDNSServers, data: []byte{192, 0, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientCore, client := newClient(t, false)
			serverCore, _ := newServer(t, 1)
			resource, _, err := client.TryAcquire(dhcpns.Request{})
			if err != nil {
				t.Fatal(err)
			}
			lease := resource.(*leaseResource)
			transferOne(t, clientCore, serverCore)
			offer := serviceEgress(t, serverCore)
			serviceIngress(t, clientCore, appendDHCPOption(t, offer, test.option, test.data))
			if lease.state != leaseWaitOffer || lease.wait != client.config.ResponseServiceAttempts {
				t.Fatalf("malformed offer mutated lease: state=%v wait=%d", lease.state, lease.wait)
			}
			serviceIngress(t, clientCore, offer)
			if lease.state != leaseRequest || lease.wait != 0 {
				t.Fatalf("valid offer after malformed option = state:%v wait:%d", lease.state, lease.wait)
			}
		})
	}
}

func TestClientDropsTruncatedFinalOptionBeforePinnedMutation(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, _ := newServer(t, 1)
	resource, progress, err := client.TryAcquire(dhcpns.Request{})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("acquire = %T, %v, %v", resource, progress, err)
	}
	lease := resource.(*leaseResource)
	transferOne(t, clientCore, serverCore)
	offer := serviceEgress(t, serverCore)

	serviceIngress(t, clientCore, truncateDHCPEndToOption(t, offer))
	if lease.state != leaseWaitOffer || lease.wait != client.config.ResponseServiceAttempts || lease.Readiness() != 0 {
		t.Fatalf("truncated final option mutated lease: state=%v wait=%d readiness=%v", lease.state, lease.wait, lease.Readiness())
	}
	serviceIngress(t, clientCore, offer)
	if lease.state != leaseRequest || lease.wait != 0 {
		t.Fatalf("valid offer after truncated option = state:%v wait:%d", lease.state, lease.wait)
	}
}

func TestPacketInspectionPreservesValidMultiAddressOptionsAndDirectedBroadcast(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, _ := newServer(t, 1)
	if _, _, err := client.TryAcquire(dhcpns.Request{}); err != nil {
		t.Fatal(err)
	}
	transferOne(t, clientCore, serverCore)
	offer := serviceEgress(t, serverCore)
	offer = appendDHCPOption(t, offer, lnetodhcp.OptRouter, []byte{192, 0, 2, 1, 192, 0, 2, 2})
	offer = appendDHCPOption(t, offer, lnetodhcp.OptDNSServers, []byte{192, 0, 2, 53, 192, 0, 2, 54})
	offer = appendDHCPOption(t, offer, lnetodhcp.OptBroadcastAddress, []byte{192, 0, 2, 255})
	eth, err := ethernet.NewFrame(offer)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	frame, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	message, server, dnsCount, ok := inspectPacket(frame)
	if !ok || message != lnetodhcp.MsgOffer || server != netip.MustParseAddr("192.0.2.1") || dnsCount != 3 {
		t.Fatalf("inspect = message:%v server:%v DNS:%d ok:%v", message, server, dnsCount, ok)
	}
}

func TestClientRejectsAmbiguousDuplicateMessageType(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, _ := newServer(t, 1)
	resource, progress, err := client.TryAcquire(dhcpns.Request{})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("acquire = %T, %v, %v", resource, progress, err)
	}
	lease := resource.(*leaseResource)
	transferOne(t, clientCore, serverCore)
	transferOne(t, serverCore, clientCore)
	transferOne(t, clientCore, serverCore)
	ack := serviceEgress(t, serverCore)
	ambiguous := appendDHCPOption(t, ack, lnetodhcp.OptMessageType, []byte{byte(lnetodhcp.MsgNack)})

	serviceIngress(t, clientCore, ambiguous)
	if lease.state != leaseWaitACK || lease.Readiness() != 0 {
		t.Fatalf("ambiguous ACK/NACK response mutated lease: state=%v readiness=%v", lease.state, lease.Readiness())
	}
	serviceIngress(t, clientCore, ack)
	if result, state, err := lease.TryResult(); err != nil || state != dhcpns.ResultReady || !result.Valid() {
		t.Fatalf("valid ACK after ambiguous response = %+v, %v, %v", result, state, err)
	}
}

func TestClientNACKRetiresWorkClearsOnCloseAndIsolatesFreshLease(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, _ := newServer(t, 1)
	resource, progress, err := client.TryAcquire(dhcpns.Request{})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("acquire = %T, %v, %v", resource, progress, err)
	}
	failed := resource.(*leaseResource)
	if usage, closed := client.quotas.Snapshot(); closed || usage != (quota.Usage{Resources: 1, DHCPv4Resources: 1, QueuedBytes: 576, DHCPv4Work: 1}) {
		t.Fatalf("active quota = %+v, closed=%v", usage, closed)
	}

	transferOne(t, clientCore, serverCore)
	transferOne(t, serverCore, clientCore)
	transferOne(t, clientCore, serverCore)
	ack := serviceEgress(t, serverCore)
	nack := rewriteDHCPMessageType(t, ack, lnetodhcp.MsgNack)
	serviceIngress(t, clientCore, nack)

	if failed.Readiness() != nscore.ReadyError {
		t.Fatalf("NACK readiness = %v", failed.Readiness())
	}
	if _, _, err := failed.TryResult(); failureOf(err) != nscore.FailureTemporary {
		t.Fatalf("NACK result = %v", err)
	}
	clientCore.Lock()
	leases := clientCore.UDPPortLeaseCountLocked()
	clientCore.Unlock()
	if failed.state != leaseFailed || failed.wait != 0 || client.lease != failed || leases != 1 {
		t.Fatalf("terminal state = state:%v wait:%d mapped:%p leases:%d", failed.state, failed.wait, client.lease, leases)
	}
	if usage, _ := client.quotas.Snapshot(); usage != (quota.Usage{Resources: 1, DHCPv4Resources: 1, QueuedBytes: 576}) {
		t.Fatalf("terminal quota = %+v", usage)
	}

	serviceIngress(t, clientCore, ack)
	if failed.Readiness() != nscore.ReadyError || failed.state != leaseFailed {
		t.Fatalf("late ACK changed terminal lease: readiness=%v state=%v", failed.Readiness(), failed.state)
	}
	if _, _, err := client.TryAcquire(dhcpns.Request{}); failureOf(err) != nscore.FailureResourceLimit {
		t.Fatalf("terminal resource concurrency = %v", err)
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	if failed.Readiness() != nscore.ReadyClosed || failed.request != (dhcpns.Request{}) || failed.result != (dhcpns.Lease{}) || failed.failure != nil || failed.wait != 0 || failed.identity.Active() || client.lease != nil || failed.retained.ResetReleased() || failed.work.ResetReleased() {
		t.Fatalf("closed terminal resource retained state: %+v", failed)
	}
	if usage, _ := client.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed terminal quota = %+v", usage)
	}

	resource, progress, err = client.TryAcquire(dhcpns.Request{})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("fresh acquire = %T, %v, %v", resource, progress, err)
	}
	fresh := resource.(*leaseResource)
	if fresh == failed || client.lease != fresh {
		t.Fatalf("fresh lease reused stale wrapper: stale=%p fresh=%p mapped=%p", failed, fresh, client.lease)
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := client.quotas.Snapshot(); usage != (quota.Usage{Resources: 1, DHCPv4Resources: 1, QueuedBytes: 576, DHCPv4Work: 1}) || client.lease != fresh {
		t.Fatalf("stale close affected fresh lease: usage=%+v mapped=%p", usage, client.lease)
	}
	if err := clientCore.Close(); err != nil {
		t.Fatal(err)
	}
	if fresh.Readiness() != nscore.ReadyClosed || fresh.request != (dhcpns.Request{}) || fresh.result != (dhcpns.Lease{}) || fresh.failure != nil || fresh.identity.Active() {
		t.Fatalf("namespace close retained fresh lease: %+v", fresh)
	}
	if usage, _ := client.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close quota = %+v", usage)
	}
	clientCore.Lock()
	leases = clientCore.UDPPortLeaseCountLocked()
	clientCore.Unlock()
	if leases != 0 {
		t.Fatalf("namespace close retained client port lease: %d", leases)
	}
}

func TestCombinedInitializationRollbackReleasesOnlyNewPortOwnership(t *testing.T) {
	combined := defaultConfig()
	combined.Server = ServerConfig{
		ServerAddr: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 1,
	}

	t.Run("server policy denial releases client port", func(t *testing.T) {
		core, _, _ := newDHCPv4Core(t, combined.Server.ServerAddr, [6]byte{2, 0, 0, 0, 0, 1}, clientPolicy())
		if adapter, err := New(core, combined); adapter != nil || failureOf(err) != nscore.FailureAccessDenied {
			t.Fatalf("New = %p, %v", adapter, err)
		}
		core.Lock()
		ports := core.UDPPortLeaseCountLocked()
		var clientPort lnetocore.UDPPortLease
		clientAvailable := core.TryLeaseUDPPortIntoLocked(&clientPort, dhcpns.ClientPort)
		clientPort.ReleaseLocked()
		core.Unlock()
		if ports != 0 || !clientAvailable {
			t.Fatalf("policy rollback = ports:%d clientAvailable:%v", ports, clientAvailable)
		}
	})

	t.Run("server port conflict preserves prior owner and releases client port", func(t *testing.T) {
		core, _, _ := newDHCPv4Core(t, combined.Server.ServerAddr, [6]byte{2, 0, 0, 0, 0, 1}, policy.Merge(clientPolicy(), serverPolicy()))
		core.Lock()
		var held lnetocore.UDPPortLease
		if !core.TryLeaseUDPPortIntoLocked(&held, dhcpns.ServerPort) {
			core.Unlock()
			t.Fatal("failed to reserve server port")
		}
		core.Unlock()

		if adapter, err := New(core, combined); adapter != nil || failureOf(err) != nscore.FailureAddressInUse {
			t.Fatalf("New = %p, %v", adapter, err)
		}
		core.Lock()
		ports := core.UDPPortLeaseCountLocked()
		var clientPort lnetocore.UDPPortLease
		clientAvailable := core.TryLeaseUDPPortIntoLocked(&clientPort, dhcpns.ClientPort)
		clientPort.ReleaseLocked()
		held.ReleaseLocked()
		remaining := core.UDPPortLeaseCountLocked()
		core.Unlock()
		if ports != 1 || !clientAvailable || remaining != 0 {
			t.Fatalf("port-conflict rollback = ports:%d clientAvailable:%v remaining:%d", ports, clientAvailable, remaining)
		}
	})
}

func TestServerRejectedDiscoverDoesNotConsumeFiniteClientCapacity(t *testing.T) {
	firstCore, first := newClient(t, false)
	secondCore, second := newAdapter(t, netip.IPv4Unspecified(), [6]byte{2, 0, 0, 0, 0, 3}, defaultConfig(), clientPolicy())
	serverCore, server := newServer(t, 1)
	if _, _, err := first.TryAcquire(dhcpns.Request{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := second.TryAcquire(dhcpns.Request{}); err != nil {
		t.Fatal(err)
	}

	malformed := appendDHCPOption(t, serviceEgress(t, firstCore), lnetodhcp.OptParameterRequestList, make([]byte, 37))
	serviceIngress(t, serverCore, malformed)
	if len(server.serverClients) != 0 || server.serverPending != 0 {
		t.Fatalf("rejected discover consumed capacity: clients=%d pending=%d", len(server.serverClients), server.serverPending)
	}

	serviceIngress(t, serverCore, serviceEgress(t, secondCore))
	if len(server.serverClients) != 1 || server.serverPending != 1 {
		t.Fatalf("valid discover after rejected peer = clients=%d pending=%d", len(server.serverClients), server.serverPending)
	}
}

func TestDirectServerResponsesKeepRelayAddressClear(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, _ := newServer(t, 1)
	if _, _, err := client.TryAcquire(dhcpns.Request{}); err != nil {
		t.Fatal(err)
	}
	assertDirect := func(name string, response []byte) {
		t.Helper()
		eth, err := ethernet.NewFrame(response)
		if err != nil {
			t.Fatal(err)
		}
		if destination := *eth.DestinationHardwareAddr(); destination != ([6]byte{2, 0, 0, 0, 0, 2}) {
			t.Fatalf("direct %s Ethernet destination = %v", name, destination)
		}
		ip, err := ipv4.NewFrame(eth.Payload())
		if err != nil {
			t.Fatal(err)
		}
		if destination := netip.AddrFrom4(*ip.DestinationAddr()); destination != netip.MustParseAddr("192.0.2.2") {
			t.Fatalf("direct %s IPv4 destination = %v", name, destination)
		}
		udp, err := lnetoudp.NewFrame(ip.Payload())
		if err != nil {
			t.Fatal(err)
		}
		frame, err := lnetodhcp.NewFrame(udp.Payload())
		if err != nil {
			t.Fatal(err)
		}
		if got := *frame.GIAddr(); got != ([4]byte{}) {
			t.Fatalf("direct %s relay address = %v", name, got)
		}
		var router netip.Addr
		if err := frame.ForEachOption(func(_ int, option lnetodhcp.OptNum, data []byte) error {
			if option == lnetodhcp.OptRouter && len(data) == 4 {
				router = netip.AddrFrom4([4]byte(data))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if router != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("%s advertised router = %v", name, router)
		}
	}

	serviceIngress(t, serverCore, serviceEgress(t, clientCore))
	offer := serviceEgress(t, serverCore)
	assertDirect("OFFER", offer)
	serviceIngress(t, clientCore, offer)
	serviceIngress(t, serverCore, serviceEgress(t, clientCore))
	assertDirect("ACK", serviceEgress(t, serverCore))
}

func TestServerPendingResponseLifecyclePreservesRetryReleasePolicyAndClose(t *testing.T) {
	t.Run("short egress retries and release reuses capacity", func(t *testing.T) {
		firstCore, first := newClient(t, false)
		secondCore, second := newAdapter(t, netip.IPv4Unspecified(), [6]byte{2, 0, 0, 0, 0, 3}, defaultConfig(), clientPolicy())
		serverCore, server := newServer(t, 1)
		if _, _, err := first.TryAcquire(dhcpns.Request{}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := second.TryAcquire(dhcpns.Request{}); err != nil {
			t.Fatal(err)
		}
		discover := serviceEgress(t, firstCore)
		serviceIngress(t, serverCore, discover)
		if len(server.serverClients) != 1 || server.serverPending != 1 || !server.hasWorkLocked() {
			t.Fatalf("accepted discover state: clients=%d pending=%d work=%v", len(server.serverClients), server.serverPending, server.hasWorkLocked())
		}

		required := 14 + 20 + 8 + server.config.MaxPacketBytes
		short := bytes.Repeat([]byte{0xa5}, required-1)
		if n, worked, err := server.egressLocked(short); !errors.Is(err, lneto.ErrShortBuffer) || !worked || n != 0 {
			t.Fatalf("short server egress = %d, %v, %v", n, worked, err)
		}
		if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) || len(server.serverClients) != 1 || server.serverPending != 1 || !server.hasWorkLocked() {
			t.Fatalf("short egress mutated state: clients=%d pending=%d work=%v", len(server.serverClients), server.serverPending, server.hasWorkLocked())
		}
		var storage [1514]byte
		if n, worked, err := server.egressLocked(storage[:]); err != nil || !worked || n == 0 {
			t.Fatalf("server response retry = %d, %v, %v", n, worked, err)
		}
		if len(server.serverClients) != 1 || server.serverPending != 0 || server.hasWorkLocked() {
			t.Fatalf("drained response state: clients=%d pending=%d work=%v", len(server.serverClients), server.serverPending, server.hasWorkLocked())
		}

		release := rewriteDHCPMessageType(t, discover, lnetodhcp.MsgRelease)
		serviceIngress(t, serverCore, release)
		if len(server.serverClients) != 0 || server.serverPending != 0 {
			t.Fatalf("release retained server state: clients=%d pending=%d", len(server.serverClients), server.serverPending)
		}
		serviceIngress(t, serverCore, serviceEgress(t, secondCore))
		if len(server.serverClients) != 1 || server.serverPending != 1 {
			t.Fatalf("fresh client after release: clients=%d pending=%d", len(server.serverClients), server.serverPending)
		}
		if err := serverCore.Close(); err != nil {
			t.Fatal(err)
		}
		serverCore.Lock()
		ports := serverCore.UDPPortLeaseCountLocked()
		serverCore.Unlock()
		if server.serverClients != nil || server.serverPending != 0 || ports != 0 || server.hasWorkLocked() {
			t.Fatalf("server close state: clients=%#v pending=%d ports=%d work=%v", server.serverClients, server.serverPending, ports, server.hasWorkLocked())
		}
	})

	t.Run("policy denied response is consumed atomically", func(t *testing.T) {
		clientCore, client := newClient(t, false)
		config := defaultConfig()
		config.MaxLeases = 0
		config.Server = ServerConfig{ServerAddr: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 1}
		serverCore, server := newAdapter(t, config.Server.ServerAddr, [6]byte{2, 0, 0, 0, 0, 1}, config, policy.Config{Rules: []policy.Rule{{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, Ports: []policy.PortRange{{First: 67, Last: 67}}}}, PrivilegedBindTransports: []policy.Transport{policy.TransportDHCPv4}})
		if _, _, err := client.TryAcquire(dhcpns.Request{}); err != nil {
			t.Fatal(err)
		}
		serviceIngress(t, serverCore, serviceEgress(t, clientCore))
		if server.serverPending != 1 {
			t.Fatalf("pending denied response = %d", server.serverPending)
		}
		dst := bytes.Repeat([]byte{0xa5}, 1514)
		n, worked, err := server.egressLocked(dst)
		if err != nil || !worked || n != 0 {
			t.Fatalf("policy denied egress = %d, %v, %v", n, worked, err)
		}
		required := 14 + 20 + 8 + server.config.MaxPacketBytes
		if !bytes.Equal(dst[:required], make([]byte, required)) || !bytes.Equal(dst[required:], bytes.Repeat([]byte{0xa5}, len(dst)-required)) {
			t.Fatal("policy denied response did not preserve atomic no-frame output")
		}
		if len(server.serverClients) != 1 || server.serverPending != 0 || server.hasWorkLocked() {
			t.Fatalf("policy denied response retained work: clients=%d pending=%d work=%v", len(server.serverClients), server.serverPending, server.hasWorkLocked())
		}
	})
}

func TestCombinedClientServerEgressBoundsClientSchedulingDelay(t *testing.T) {
	config := defaultConfig()
	config.Server = ServerConfig{ServerAddr: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 1}
	_, combined := newAdapter(t, config.Server.ServerAddr, [6]byte{2, 0, 0, 0, 0, 1}, config, policy.Merge(clientPolicy(), serverPolicy()))
	externalCore, external := newAdapter(t, netip.IPv4Unspecified(), [6]byte{2, 0, 0, 0, 0, 3}, defaultConfig(), clientPolicy())
	if _, _, err := external.TryAcquire(dhcpns.Request{}); err != nil {
		t.Fatal(err)
	}
	discover := serviceEgress(t, externalCore)
	resource, _, err := combined.TryAcquire(dhcpns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	if handled, err := combined.ingressLocked(discover); err != nil || !handled || combined.serverPending != 1 {
		t.Fatalf("initial external discover = handled:%v err:%v pending:%d", handled, err, combined.serverPending)
	}

	var storage [1514]byte
	n, worked, err := combined.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("initial server response = %d, %v, %v", n, worked, err)
	}
	assertUDPPorts(t, storage[:n], dhcpns.ServerPort, dhcpns.ClientPort)
	if handled, err := combined.ingressLocked(discover); err != nil || !handled || combined.serverPending != 1 {
		t.Fatalf("replacement external discover = handled:%v err:%v pending:%d", handled, err, combined.serverPending)
	}

	n, worked, err = combined.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("bounded client egress = %d, %v, %v", n, worked, err)
	}
	assertUDPPorts(t, storage[:n], dhcpns.ClientPort, dhcpns.ServerPort)
	if lease.state != leaseWaitOffer || combined.serverPending != 1 {
		t.Fatalf("client egress lifecycle = state:%v pending:%d", lease.state, combined.serverPending)
	}

	n, worked, err = combined.egressLocked(storage[:])
	if err != nil || !worked || n == 0 || combined.serverPending != 0 {
		t.Fatalf("server retry after client = %d, %v, %v pending:%d", n, worked, err, combined.serverPending)
	}
	assertUDPPorts(t, storage[:n], dhcpns.ServerPort, dhcpns.ClientPort)
	if handled, err := combined.ingressLocked(discover); err != nil || !handled || combined.serverPending != 1 {
		t.Fatalf("maintenance replacement discover = handled:%v err:%v pending:%d", handled, err, combined.serverPending)
	}

	waitBefore := lease.wait
	if n, worked, err := combined.egressLocked(storage[:]); err != nil || !worked || n != 0 || lease.wait != waitBefore-1 || combined.serverPending != 1 {
		t.Fatalf("bounded client maintenance = %d, %v, %v wait:%d pending:%d", n, worked, err, lease.wait, combined.serverPending)
	}
	if n, worked, err := combined.egressLocked(storage[:]); err != nil || !worked || n == 0 || combined.serverPending != 0 {
		t.Fatalf("server response after maintenance = %d, %v, %v pending:%d", n, worked, err, combined.serverPending)
	}
}

func assertUDPPorts(t testing.TB, frame []byte, source, destination uint16) {
	t.Helper()
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if udp.SourcePort() != source || udp.DestinationPort() != destination {
		t.Fatalf("UDP ports = %d -> %d, want %d -> %d", udp.SourcePort(), udp.DestinationPort(), source, destination)
	}
}

func TestServerClientBoundAndPoolAreFinite(t *testing.T) {
	_, _ = newServer(t, 1)
	config := defaultConfig()
	config.Server = ServerConfig{ServerAddr: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600}
	if ValidConfig(config, 1500, new(policy.Policy), quota.NewAccount(quota.DefaultLimits()), true) {
		t.Fatal("zero server pool accepted")
	}
}

func TestServerRejectsSubnetNetworkAndBroadcastIdentities(t *testing.T) {
	base := defaultConfig()
	base.Server = ServerConfig{
		ServerAddr: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"),
		Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 1,
	}
	for _, test := range []struct {
		name   string
		mutate func(*ServerConfig)
	}{
		{name: "server network", mutate: func(server *ServerConfig) { server.ServerAddr = netip.MustParseAddr("192.0.2.0") }},
		{name: "server broadcast", mutate: func(server *ServerConfig) { server.ServerAddr = netip.MustParseAddr("192.0.2.255") }},
		{name: "gateway network", mutate: func(server *ServerConfig) { server.Gateway = netip.MustParseAddr("192.0.2.0") }},
		{name: "gateway broadcast", mutate: func(server *ServerConfig) { server.Gateway = netip.MustParseAddr("192.0.2.255") }},
		{name: "DNS network", mutate: func(server *ServerConfig) { server.DNS = netip.MustParseAddr("192.0.2.0") }},
		{name: "DNS broadcast", mutate: func(server *ServerConfig) { server.DNS = netip.MustParseAddr("192.0.2.255") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config.Server)
			if ValidConfig(config, 1500, new(policy.Policy), quota.NewAccount(quota.DefaultLimits()), true) {
				t.Fatalf("accepted non-host server configuration: %+v", config.Server)
			}
		})
	}
}

func TestServerRejectsInvalidAdvertisementsBeforeOwnership(t *testing.T) {
	for addressName, address := range map[string]netip.Addr{
		"loopback":          netip.MustParseAddr("127.0.0.1"),
		"limited broadcast": limitedBroadcast,
	} {
		for _, field := range []string{"gateway", "DNS"} {
			t.Run(addressName+"/"+field, func(t *testing.T) {
				config := defaultConfig()
				config.Server = ServerConfig{
					ServerAddr: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"),
					Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 1,
				}
				if field == "gateway" {
					config.Server.Gateway = address
				} else {
					config.Server.DNS = address
				}
				core, _, _ := newDHCPv4Core(t, config.Server.ServerAddr, [6]byte{2, 0, 0, 0, 0, 1}, serverPolicy())
				if adapter, err := New(core, config); adapter != nil || failureOf(err) != nscore.FailureInvalidArgument {
					t.Fatalf("New = %p, %v", adapter, err)
				}
				core.Lock()
				ports := core.UDPPortLeaseCountLocked()
				core.Unlock()
				if ports != 0 {
					t.Fatalf("rejected server retained %d UDP port leases", ports)
				}
			})
		}
	}
}

func TestUDPDatagramLengthMismatchIsContainedBeforeDHCPMutation(t *testing.T) {
	t.Run("client responses remain retryable", func(t *testing.T) {
		clientCore, client := newClient(t, false)
		serverCore, _ := newServer(t, 1)
		resource, _, err := client.TryAcquire(dhcpns.Request{})
		if err != nil {
			t.Fatal(err)
		}
		lease := resource.(*leaseResource)
		transferOne(t, clientCore, serverCore)
		offer := serviceEgress(t, serverCore)

		serviceIngress(t, clientCore, shortenUDPDatagram(t, offer, 1))
		if lease.state != leaseWaitOffer || lease.wait != client.config.ResponseServiceAttempts || lease.Readiness() != 0 {
			t.Fatalf("short UDP OFFER mutated lease: state=%v wait=%d readiness=%v", lease.state, lease.wait, lease.Readiness())
		}
		serviceIngress(t, clientCore, appendLinkPadding(offer))
		if lease.state != leaseRequest || lease.wait != 0 {
			t.Fatalf("padded valid OFFER = state:%v wait:%d", lease.state, lease.wait)
		}

		transferOne(t, clientCore, serverCore)
		ack := serviceEgress(t, serverCore)
		serviceIngress(t, clientCore, shortenUDPDatagram(t, ack, 1))
		if lease.state != leaseWaitACK || lease.wait != client.config.ResponseServiceAttempts || lease.Readiness() != 0 {
			t.Fatalf("short UDP ACK mutated lease: state=%v wait=%d readiness=%v", lease.state, lease.wait, lease.Readiness())
		}
		serviceIngress(t, clientCore, appendLinkPadding(ack))
		if result, state, err := lease.TryResult(); err != nil || state != dhcpns.ResultReady || !result.Valid() {
			t.Fatalf("valid padded ACK after mismatch = %+v, %v, %v", result, state, err)
		}
	})

	t.Run("server requests do not reserve or queue", func(t *testing.T) {
		clientCore, client := newClient(t, false)
		serverCore, server := newServer(t, 1)
		if _, _, err := client.TryAcquire(dhcpns.Request{}); err != nil {
			t.Fatal(err)
		}
		discover := serviceEgress(t, clientCore)

		serviceIngress(t, serverCore, shortenUDPDatagram(t, discover, 1))
		if len(server.serverClients) != 0 || server.serverPending != 0 || server.hasWorkLocked() {
			t.Fatalf("short UDP DISCOVER mutated server: clients=%d pending=%d work=%v", len(server.serverClients), server.serverPending, server.hasWorkLocked())
		}
		serviceIngress(t, serverCore, appendLinkPadding(discover))
		if len(server.serverClients) != 1 || server.serverPending != 1 || !server.hasWorkLocked() {
			t.Fatalf("valid padded DISCOVER after mismatch: clients=%d pending=%d work=%v", len(server.serverClients), server.serverPending, server.hasWorkLocked())
		}
	})
}

func TestIngressContainsTruncatedUDPOnlyForEnabledDirection(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, server := newServer(t, 1)
	combinedConfig := defaultConfig()
	combinedConfig.Server = ServerConfig{ServerAddr: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: 1}
	combinedCore, combined := newAdapter(t, combinedConfig.Server.ServerAddr, [6]byte{2, 0, 0, 0, 0, 3}, combinedConfig, policy.Merge(clientPolicy(), serverPolicy()))

	for _, adapter := range []struct {
		name string
		core *lnetocore.Namespace
		impl *Adapter
		owns func(uint16, uint16) bool
	}{
		{name: "client only", core: clientCore, impl: client, owns: func(source, destination uint16) bool {
			return source == dhcpns.ServerPort && destination == dhcpns.ClientPort
		}},
		{name: "server only", core: serverCore, impl: server, owns: func(source, destination uint16) bool {
			return source == dhcpns.ClientPort && destination == dhcpns.ServerPort
		}},
		{name: "combined", core: combinedCore, impl: combined, owns: func(source, destination uint16) bool {
			return source == dhcpns.ServerPort && destination == dhcpns.ClientPort || source == dhcpns.ClientPort && destination == dhcpns.ServerPort
		}},
	} {
		t.Run(adapter.name, func(t *testing.T) {
			for _, ports := range []struct {
				name        string
				source      uint16
				destination uint16
			}{
				{name: "server to client", source: dhcpns.ServerPort, destination: dhcpns.ClientPort},
				{name: "client to server", source: dhcpns.ClientPort, destination: dhcpns.ServerPort},
				{name: "foreign", source: 1067, destination: 1068},
			} {
				for udpBytes := 0; udpBytes < 8; udpBytes++ {
					name := ports.name + "/bytes=" + string(rune('0'+udpBytes))
					t.Run(name, func(t *testing.T) {
						frame := truncatedDHCPv4UDPFrame(t, adapter.impl.hardwareAddress, ports.source, ports.destination, udpBytes)
						adapter.core.Lock()
						handled, err := adapter.impl.ingressLocked(frame)
						adapter.core.Unlock()
						wantHandled := udpBytes >= 4 && adapter.owns(ports.source, ports.destination)
						if err != nil || handled != wantHandled {
							t.Fatalf("ingress = handled:%v err:%v, want handled:%v", handled, err, wantHandled)
						}
					})
				}
			}

			for _, ports := range [][2]uint16{{dhcpns.ServerPort, dhcpns.ClientPort}, {dhcpns.ClientPort, dhcpns.ServerPort}} {
				frame := truncatedDHCPv4UDPFrame(t, adapter.impl.hardwareAddress, ports[0], ports[1], 8)
				frame[14+20+4], frame[14+20+5] = 0, 7
				adapter.core.Lock()
				handled, err := adapter.impl.ingressLocked(frame)
				adapter.core.Unlock()
				wantHandled := adapter.owns(ports[0], ports[1])
				if err != nil || handled != wantHandled {
					t.Fatalf("malformed complete %d->%d = handled:%v err:%v, want handled:%v", ports[0], ports[1], handled, err, wantHandled)
				}
			}
			if adapter.impl.lease != nil || len(adapter.impl.serverClients) != 0 || adapter.impl.serverPending != 0 || adapter.impl.hasWorkLocked() {
				t.Fatalf("truncated traffic mutated state: lease=%p clients=%d pending=%d work=%v", adapter.impl.lease, len(adapter.impl.serverClients), adapter.impl.serverPending, adapter.impl.hasWorkLocked())
			}
		})
	}
}

func TestClientIngressDropsInvalidIPv4LengthsWithoutMutatingLease(t *testing.T) {
	for _, test := range []struct {
		name        string
		totalLength uint16
	}{
		{name: "shorter than header", totalLength: 19},
		{name: "beyond frame", totalLength: 1501},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientCore, client := newClient(t, false)
			serverCore, _ := newServer(t, 1)
			resource, _, err := client.TryAcquire(dhcpns.Request{})
			if err != nil {
				t.Fatal(err)
			}
			lease := resource.(*leaseResource)
			transferOne(t, clientCore, serverCore)
			offer := serviceEgress(t, serverCore)
			malformed := append([]byte(nil), offer...)
			eth, err := ethernet.NewFrame(malformed)
			if err != nil {
				t.Fatal(err)
			}
			ip, err := ipv4.NewFrame(eth.Payload())
			if err != nil {
				t.Fatal(err)
			}
			ip.SetTotalLength(test.totalLength)
			ip.SetCRC(0)
			ip.SetCRC(ip.CalculateHeaderCRC())

			var handled bool
			var ingressErr error
			var state leaseState
			var wait uint16
			func() {
				clientCore.Lock()
				defer clientCore.Unlock()
				handled, ingressErr = client.ingressLocked(malformed)
				state, wait = lease.state, lease.wait
			}()
			if ingressErr != nil || handled || state != leaseWaitOffer || wait != client.config.ResponseServiceAttempts {
				t.Fatalf("malformed ingress = handled:%v err:%v state:%v wait:%d", handled, ingressErr, state, wait)
			}
			serviceIngress(t, clientCore, offer)
			if lease.state != leaseRequest || lease.wait != 0 {
				t.Fatalf("valid offer after malformed length = state:%v wait:%d", lease.state, lease.wait)
			}
		})
	}
}

func TestIngressRejectsInvalidEthernetSourcesOnlyForEnabledDirection(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, server := newServer(t, 1)
	resource, _, err := client.TryAcquire(dhcpns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	discover := serviceEgress(t, clientCore)
	serviceIngress(t, serverCore, discover)
	offer := serviceEgress(t, serverCore)

	invalidDiscover := rewriteEthernetSource(t, discover, [6]byte{})
	invalidOffer := rewriteEthernetSource(t, offer, [6]byte{})
	offerToServer := append([]byte(nil), invalidOffer...)
	serverEthernet, err := ethernet.NewFrame(offerToServer)
	if err != nil {
		t.Fatal(err)
	}
	*serverEthernet.DestinationHardwareAddr() = server.hardwareAddress

	for _, test := range []struct {
		name        string
		adapter     *Adapter
		frame       []byte
		wantHandled bool
	}{
		{name: "client owns replies", adapter: client, frame: invalidOffer, wantHandled: true},
		{name: "client does not own requests", adapter: client, frame: invalidDiscover},
		{name: "server owns requests", adapter: server, frame: invalidDiscover, wantHandled: true},
		{name: "server does not own replies", adapter: server, frame: offerToServer},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.adapter.core.Lock()
			handled, ingressErr := test.adapter.ingressLocked(test.frame)
			test.adapter.core.Unlock()
			if ingressErr != nil || handled != test.wantHandled {
				t.Fatalf("ingress = handled %v, err %v; want handled %v", handled, ingressErr, test.wantHandled)
			}
		})
	}
	if lease.state != leaseWaitOffer || lease.wait != client.config.ResponseServiceAttempts || len(server.serverClients) != 1 || server.serverPending != 0 {
		t.Fatalf("disabled-direction traffic mutated state: lease=%v wait=%d clients=%d pending=%d", lease.state, lease.wait, len(server.serverClients), server.serverPending)
	}
	serviceIngress(t, clientCore, offer)
	if lease.state != leaseRequest || lease.wait != 0 {
		t.Fatalf("valid offer after disabled-direction traffic = state:%v wait:%d", lease.state, lease.wait)
	}
}

func TestClientIngressRejectsInvalidEthernetSources(t *testing.T) {
	invalid := map[string][6]byte{
		"zero":      {},
		"broadcast": broadcastMAC,
		"multicast": {1, 0, 94, 0, 0, 1},
	}
	for name, source := range invalid {
		t.Run(name, func(t *testing.T) {
			clientCore, client := newClient(t, false)
			serverCore, _ := newServer(t, 1)
			resource, _, err := client.TryAcquire(dhcpns.Request{})
			if err != nil {
				t.Fatal(err)
			}
			lease := resource.(*leaseResource)
			transferOne(t, clientCore, serverCore)
			offer := serviceEgress(t, serverCore)

			serviceIngress(t, clientCore, rewriteEthernetSource(t, offer, source))
			if lease.state != leaseWaitOffer || lease.wait != client.config.ResponseServiceAttempts {
				t.Fatalf("malformed offer mutated lease: state=%v wait=%d", lease.state, lease.wait)
			}
			serviceIngress(t, clientCore, offer)
			if lease.state != leaseRequest || lease.wait != 0 {
				t.Fatalf("valid offer not accepted after malformed source: state=%v wait=%d", lease.state, lease.wait)
			}
		})
	}
}

func TestServerInvalidClientHardwareAddressesDoNotReserveCapacity(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, server := newServer(t, 1)
	if _, _, err := client.TryAcquire(dhcpns.Request{}); err != nil {
		t.Fatal(err)
	}
	valid := serviceEgress(t, clientCore)
	for name, address := range map[string][6]byte{
		"zero": {}, "broadcast": broadcastMAC, "multicast": {1, 0, 94, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			serviceIngress(t, serverCore, rewriteDHCPClientHardwareAddress(t, valid, address))
			if len(server.serverClients) != 0 || server.serverPending != 0 {
				t.Fatalf("invalid client hardware address reserved server capacity: clients=%d pending=%d", len(server.serverClients), server.serverPending)
			}
		})
	}
	serviceIngress(t, serverCore, valid)
	if len(server.serverClients) != 1 || server.serverPending != 1 {
		t.Fatalf("valid discover after malformed frames = clients=%d pending=%d", len(server.serverClients), server.serverPending)
	}
}

func TestServerIngressRejectsInvalidIPv4SourcesAfterDirectionCorrelation(t *testing.T) {
	invalid := map[string]netip.Addr{
		"loopback":          netip.MustParseAddr("127.0.0.1"),
		"multicast":         netip.MustParseAddr("224.0.0.1"),
		"limited broadcast": limitedBroadcast,
	}
	for name, source := range invalid {
		t.Run(name, func(t *testing.T) {
			clientCore, client := newClient(t, false)
			serverCore, server := newServer(t, 1)
			if _, _, err := client.TryAcquire(dhcpns.Request{}); err != nil {
				t.Fatal(err)
			}
			discover := serviceEgress(t, clientCore)
			usageBefore, _ := server.quotas.Snapshot()
			serverCore.Lock()
			handled, ingressErr := server.ingressLocked(rewriteIPv4Source(t, discover, source))
			serverCore.Unlock()
			if ingressErr != nil || !handled {
				t.Fatalf("invalid source ingress = handled:%v err:%v", handled, ingressErr)
			}
			if len(server.serverClients) != 0 || server.serverPending != 0 || server.hasWorkLocked() {
				t.Fatalf("invalid source mutated server: clients=%d pending=%d work=%v", len(server.serverClients), server.serverPending, server.hasWorkLocked())
			}
			if usage, _ := server.quotas.Snapshot(); usage != usageBefore {
				t.Fatalf("invalid source changed quota = %+v, want %+v", usage, usageBefore)
			}
			serviceIngress(t, serverCore, discover)
			if len(server.serverClients) != 1 || server.serverPending != 1 {
				t.Fatalf("unspecified-source discover after invalid source = clients:%d pending:%d", len(server.serverClients), server.serverPending)
			}
		})
	}
}

func TestServerIngressRejectsInvalidEthernetSources(t *testing.T) {
	invalid := map[string][6]byte{
		"zero":      {},
		"broadcast": broadcastMAC,
		"multicast": {1, 0, 94, 0, 0, 1},
	}
	for name, source := range invalid {
		t.Run(name, func(t *testing.T) {
			clientCore, client := newClient(t, false)
			serverCore, server := newServer(t, 1)
			if _, _, err := client.TryAcquire(dhcpns.Request{}); err != nil {
				t.Fatal(err)
			}
			discover := serviceEgress(t, clientCore)

			serviceIngress(t, serverCore, rewriteEthernetSource(t, discover, source))
			if len(server.serverClients) != 0 || server.serverPending != 0 {
				t.Fatalf("malformed discover mutated server: clients=%d pending=%d", len(server.serverClients), server.serverPending)
			}
			serviceIngress(t, serverCore, discover)
			if len(server.serverClients) != 1 || server.serverPending != 1 {
				t.Fatalf("valid discover not accepted after malformed source: clients=%d pending=%d", len(server.serverClients), server.serverPending)
			}
		})
	}
}

func TestClientIngressAllowsRelayEthernetSource(t *testing.T) {
	clientCore, client := newClient(t, false)
	serverCore, _ := newServer(t, 1)
	resource, _, err := client.TryAcquire(dhcpns.Request{})
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	transferOne(t, clientCore, serverCore)
	offer := rewriteEthernetSource(t, serviceEgress(t, serverCore), [6]byte{2, 0, 0, 0, 0, 99})
	serviceIngress(t, clientCore, offer)
	if lease.state != leaseRequest {
		t.Fatalf("relay-delivered offer state = %v, want request", lease.state)
	}
}

func TestDHCPv4ZeroConfigRetainsTruthfulServiceSemantics(t *testing.T) {
	core, adapter := newAdapter(t, netip.MustParseAddr("192.0.2.9"), [6]byte{2, 0, 0, 0, 0, 9}, Config{}, policy.Config{})
	if _, _, err := adapter.TryAcquire(dhcpns.Request{}); failureOf(err) != nscore.FailureNotSupported {
		t.Fatalf("disabled acquire = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TryAcquire(dhcpns.Request{}); failureOf(err) != nscore.FailureClosed {
		t.Fatalf("closed disabled acquire = %v", err)
	}
}

func newClient(t testing.TB, apply bool) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	config := defaultConfig()
	config.ApplyLease = apply
	return newAdapter(t, netip.IPv4Unspecified(), [6]byte{2, 0, 0, 0, 0, 2}, config, clientPolicy())
}

func newServer(t testing.TB, clients uint16) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	config := defaultConfig()
	config.MaxLeases = 0
	config.ApplyLease = false
	config.Server = ServerConfig{ServerAddr: netip.MustParseAddr("192.0.2.1"), Gateway: netip.MustParseAddr("192.0.2.1"), DNS: netip.MustParseAddr("192.0.2.53"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600, MaxClients: clients}
	return newAdapter(t, config.Server.ServerAddr, [6]byte{2, 0, 0, 0, 0, 1}, config, serverPolicy())
}

func defaultConfig() Config {
	return Config{MaxLeases: 1, MaxPacketBytes: 576, ResponseServiceAttempts: 8, MaxDNSServers: dhcpns.MaxDNSServers}
}

func newAdapter(t testing.TB, address netip.Addr, mac [6]byte, config Config, policyConfig policy.Config) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	core, _, _ := newDHCPv4Core(t, address, mac, policyConfig)
	adapter, err := New(core, config)
	if err != nil {
		t.Fatal(err)
	}
	return core, adapter
}

func newDHCPv4Core(t testing.TB, address netip.Addr, mac [6]byte, policyConfig policy.Config) (*lnetocore.Namespace, *policy.Policy, *quota.Account) {
	t.Helper()
	compiled, err := policy.Compile(policyConfig)
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 8, DHCPv4Resources: 4, QueuedBytes: 4096, DHCPv4Work: 4})
	core, err := lnetocore.New(lnetocore.Config{Hostname: "dhcp", RandSeed: 41, HardwareAddress: mac, GatewayHardwareAddress: [6]byte{2, 0, 0, 0, 0, 1}, IPv4Address: address, MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 8, EgressFrames: 8}, Policy: compiled, Quotas: account})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	return core, compiled, account
}

func clientPolicy() policy.Config {
	return policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}, Ports: []policy.PortRange{{First: 68, Last: 68}}},
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("255.255.255.255/32")}, Ports: []policy.PortRange{{First: 67, Last: 67}}},
	}, WildcardBindTransports: []policy.Transport{policy.TransportDHCPv4}, BroadcastTransports: []policy.Transport{policy.TransportDHCPv4}, PrivilegedBindTransports: []policy.Transport{policy.TransportDHCPv4}}
}

func serverPolicy() policy.Config {
	return policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, Ports: []policy.PortRange{{First: 67, Last: 67}}},
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv4}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Ports: []policy.PortRange{{First: 68, Last: 68}}},
	}, PrivilegedBindTransports: []policy.Transport{policy.TransportDHCPv4}}
}

func transferOne(t testing.TB, from, to *lnetocore.Namespace) {
	t.Helper()
	serviceIngress(t, to, serviceEgress(t, from))
}

func serviceIngress(t testing.TB, core *lnetocore.Namespace, frame []byte) {
	t.Helper()
	if err := core.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	core.SetNextIngressLocked(true)
	core.Unlock()
	report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		t.Fatalf("ingress = %+v, %v, %v", report, progress, err)
	}
}

func truncatedDHCPv4UDPFrame(t testing.TB, destinationMAC [6]byte, sourcePort, destinationPort uint16, udpBytes int) []byte {
	t.Helper()
	frame := make([]byte, 14+20+udpBytes)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	*eth.DestinationHardwareAddr() = destinationMAC
	*eth.SourceHardwareAddr() = [6]byte{2, 0, 0, 0, 0, 99}
	eth.SetEtherType(ethernet.TypeIPv4)
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	ip.SetVersionAndIHL(4, 5)
	ip.SetTTL(64)
	ip.SetProtocol(lneto.IPProtoUDP)
	ip.SetTotalLength(uint16(20 + udpBytes))
	*ip.SourceAddr() = [4]byte{192, 0, 2, 99}
	*ip.DestinationAddr() = [4]byte{192, 0, 2, 1}
	rawUDP := ip.RawData()[20:]
	ports := [4]byte{byte(sourcePort >> 8), byte(sourcePort), byte(destinationPort >> 8), byte(destinationPort)}
	copy(rawUDP, ports[:])
	ip.SetCRC(ip.CalculateHeaderCRC())
	return frame
}

func shortenUDPDatagram(t testing.TB, frame []byte, bytes uint16) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if bytes == 0 || bytes >= udp.Length()-8 {
		t.Fatalf("invalid UDP shortening %d for length %d", bytes, udp.Length())
	}
	udp.SetLength(udp.Length() - bytes)
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func appendLinkPadding(frame []byte) []byte {
	return append(append([]byte(nil), frame...), 0xa5, 0x5a, 0xc3)
}

func truncateDHCPEndToOption(t testing.TB, frame []byte) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	dhcp, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	options := dhcp.OptionsPayload()
	end := -1
	for offset := 0; offset < len(options); {
		switch lnetodhcp.OptNum(options[offset]) {
		case lnetodhcp.OptWordAligned:
			offset++
		case lnetodhcp.OptEnd:
			end = offset
			offset = len(options)
		default:
			if offset+1 >= len(options) {
				t.Fatal("fixture has truncated DHCP option")
			}
			offset += 2 + int(options[offset+1])
		}
	}
	if end < 0 {
		t.Fatal("fixture has no DHCP end option")
	}
	options[end] = byte(lnetodhcp.OptParameterRequestList)
	payloadBytes := lnetodhcp.OptionsOffset + end + 1
	udpLength := uint16(8 + payloadBytes)
	udp.SetLength(udpLength)
	ip.SetTotalLength(uint16(ip.HeaderLength()) + udpLength)
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udpLength)
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udpLength])))
	return frame[:14+int(ip.TotalLength())]
}

func rewriteDHCPMessageType(t testing.TB, frame []byte, message lnetodhcp.MessageType) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	dhcp, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	if err := dhcp.ForEachOption(func(_ int, option lnetodhcp.OptNum, data []byte) error {
		if option == lnetodhcp.OptMessageType && len(data) == 1 {
			data[0] = byte(message)
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("DHCP message type option not found")
	}
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func appendDHCPOption(t testing.TB, frame []byte, option lnetodhcp.OptNum, data []byte) []byte {
	t.Helper()
	extra := 2 + len(data)
	frame = append(append([]byte(nil), frame...), make([]byte, extra)...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	ip.SetTotalLength(ip.TotalLength() + uint16(extra))
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp.SetLength(udp.Length() + uint16(extra))
	dhcp, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	options := dhcp.OptionsPayload()
	end := -1
	for offset := 0; offset < len(options); {
		switch lnetodhcp.OptNum(options[offset]) {
		case lnetodhcp.OptWordAligned:
			offset++
		case lnetodhcp.OptEnd:
			end = offset
			offset = len(options)
		default:
			if offset+1 >= len(options) {
				t.Fatal("truncated DHCP option header")
			}
			offset += 2 + int(options[offset+1])
		}
	}
	if end < 0 || end+3+len(data) > len(options) {
		t.Fatalf("no room to append DHCP option %v", option)
	}
	options[end] = byte(option)
	options[end+1] = byte(len(data))
	copy(options[end+2:], data)
	options[end+2+len(data)] = byte(lnetodhcp.OptEnd)
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func rewriteDHCPOptionData(t testing.TB, frame []byte, target lnetodhcp.OptNum, value []byte) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	dhcp, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	if err := dhcp.ForEachOption(func(_ int, option lnetodhcp.OptNum, data []byte) error {
		if option == target {
			if len(data) != len(value) {
				t.Fatalf("DHCP option %v length = %d, want %d", target, len(data), len(value))
			}
			copy(data, value)
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("DHCP option %v not found", target)
	}
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func rewriteIPv4Source(t testing.TB, frame []byte, source netip.Addr) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	*ip.SourceAddr() = source.As4()
	ip.SetCRC(0)
	ip.SetCRC(ip.CalculateHeaderCRC())
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func rewriteDHCPClientHardwareAddress(t testing.TB, frame []byte, address [6]byte) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	dhcp, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	*dhcp.CHAddrAs6() = address
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func rewriteEthernetSource(t testing.TB, frame []byte, source [6]byte) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	*eth.SourceHardwareAddr() = source
	return frame
}

func serviceEgress(t testing.TB, core *lnetocore.Namespace) []byte {
	t.Helper()
	core.Lock()
	core.SetNextIngressLocked(false)
	core.Unlock()
	report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		t.Fatalf("egress = %+v, %v, %v", report, progress, err)
	}
	frame := make([]byte, 1514)
	result, err := core.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready || result.Truncated {
		t.Fatalf("dequeue = %+v, %v", result, err)
	}
	return append([]byte(nil), frame[:result.FrameBytes]...)
}

func serviceNoFrame(t testing.TB, core *lnetocore.Namespace) {
	t.Helper()
	core.Lock()
	core.SetNextIngressLocked(false)
	core.Unlock()
	report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report.Operations != 1 || report.Packets != 0 {
		t.Fatalf("maintenance = %+v, %v, %v", report, progress, err)
	}
}

func failureOf(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func TestServerCanonicalClientIdentifiersRemainDistinctAcrossDiscoverRequestRelease(t *testing.T) {
	firstCore, first := newClient(t, false)
	secondCore, second := newClient(t, false)
	serverCore, server := newServer(t, 2)
	request := func(identifier string) dhcpns.Request {
		var value dhcpns.Request
		value.ClientIDLength = uint8(len(identifier))
		copy(value.ClientID[:], identifier)
		return value
	}
	firstResource, _, err := first.TryAcquire(request("client-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer firstResource.Close()
	secondResource, _, err := second.TryAcquire(request("client-b"))
	if err != nil {
		t.Fatal(err)
	}
	defer secondResource.Close()
	firstDiscover := rewriteDHCPOptionNumber(t, serviceEgress(t, firstCore), lnetodhcp.OptClientIdentifier, lnetodhcp.OptClientIdentifier1)
	secondDiscover := rewriteDHCPOptionNumber(t, serviceEgress(t, secondCore), lnetodhcp.OptClientIdentifier, lnetodhcp.OptClientIdentifier1)

	serviceIngress(t, serverCore, firstDiscover)
	serviceIngress(t, serverCore, secondDiscover)
	if len(server.serverClients) != 2 || server.serverPending != 2 {
		t.Fatalf("canonical discovers = clients:%d pending:%d", len(server.serverClients), server.serverPending)
	}
	assertResponses := func(message lnetodhcp.MessageType) {
		t.Helper()
		var assigned [2]netip.Addr
		for i := range assigned {
			response := serviceEgress(t, serverCore)
			eth, err := ethernet.NewFrame(response)
			if err != nil {
				t.Fatal(err)
			}
			ip, err := ipv4.NewFrame(eth.Payload())
			if err != nil {
				t.Fatal(err)
			}
			udp, err := lnetoudp.NewFrame(ip.Payload())
			if err != nil {
				t.Fatal(err)
			}
			frame, err := lnetodhcp.NewFrame(udp.Payload())
			if err != nil {
				t.Fatal(err)
			}
			got, _, _, ok := inspectPacket(frame)
			if !ok || got != message {
				t.Fatalf("server response type = %v, want %v", got, message)
			}
			assigned[i] = netip.AddrFrom4(*frame.YIAddr())
		}
		if !assigned[0].IsValid() || !assigned[1].IsValid() || assigned[0] == assigned[1] {
			t.Fatalf("server responses conflated canonical identities: %+v", assigned)
		}
		if server.serverPending != 0 || server.hasWorkLocked() {
			t.Fatalf("server responses retained work: pending=%d work=%v", server.serverPending, server.hasWorkLocked())
		}
	}
	assertResponses(lnetodhcp.MsgOffer)

	serviceIngress(t, serverCore, rewriteDHCPMessageType(t, firstDiscover, lnetodhcp.MsgRequest))
	serviceIngress(t, serverCore, rewriteDHCPMessageType(t, secondDiscover, lnetodhcp.MsgRequest))
	if server.serverPending != 2 {
		t.Fatalf("canonical requests pending = %d", server.serverPending)
	}
	assertResponses(lnetodhcp.MsgAck)

	serviceIngress(t, serverCore, rewriteDHCPMessageType(t, firstDiscover, lnetodhcp.MsgRelease))
	if len(server.serverClients) != 1 {
		t.Fatalf("first canonical release clients = %d", len(server.serverClients))
	}
	serviceIngress(t, serverCore, rewriteDHCPMessageType(t, secondDiscover, lnetodhcp.MsgRelease))
	if len(server.serverClients) != 0 || server.serverPending != 0 {
		t.Fatalf("canonical releases retained state: clients=%d pending=%d", len(server.serverClients), server.serverPending)
	}

	duplicate := appendDHCPOption(t, firstDiscover, lnetodhcp.OptClientIdentifier, []byte("client-a"))
	serviceIngress(t, serverCore, duplicate)
	if len(server.serverClients) != 0 || server.serverPending != 0 {
		t.Fatalf("duplicate client identifiers mutated server: clients=%d pending=%d", len(server.serverClients), server.serverPending)
	}
}

func TestServerClientIdentityUsesIdentifierKindAndLength(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 7}
	short := clientKey(testClientFrame(t, mac, lnetodhcp.OptClientIdentifier1, []byte{1}))
	trailingZero := clientKey(testClientFrame(t, mac, lnetodhcp.OptClientIdentifier1, []byte{1, 0}))
	if short == trailingZero {
		t.Fatal("client identifiers with distinct lengths collided")
	}

	hardware := clientKey(testClientFrame(t, mac, lnetodhcp.OptEnd, nil))
	identifier := clientKey(testClientFrame(t, mac, lnetodhcp.OptClientIdentifier1, mac[:]))
	if hardware == identifier {
		t.Fatal("hardware fallback collided with an explicit client identifier")
	}

	legacy := clientKey(testClientFrame(t, mac, lnetodhcp.OptClientIdentifier, []byte("client")))
	canonical := clientKey(testClientFrame(t, mac, lnetodhcp.OptClientIdentifier1, []byte("client")))
	if legacy != canonical {
		t.Fatal("legacy and canonical client identifier options produced different identities")
	}
}

func testClientFrame(t testing.TB, mac [6]byte, option lnetodhcp.OptNum, identifier []byte) lnetodhcp.Frame {
	t.Helper()
	optionBytes := 1
	if option != lnetodhcp.OptEnd {
		optionBytes += 2 + len(identifier)
	}
	payload := make([]byte, lnetodhcp.OptionsOffset+optionBytes)
	frame, err := lnetodhcp.NewFrame(payload)
	if err != nil {
		t.Fatal(err)
	}
	frame.ClearHeader()
	frame.SetMagicCookie(lnetodhcp.MagicCookie)
	*frame.CHAddrAs6() = mac
	options := frame.OptionsPayload()
	if option == lnetodhcp.OptEnd {
		options[0] = byte(lnetodhcp.OptEnd)
		return frame
	}
	options[0] = byte(option)
	options[1] = byte(len(identifier))
	copy(options[2:], identifier)
	options[2+len(identifier)] = byte(lnetodhcp.OptEnd)
	return frame
}

func rewriteDHCPOptionNumber(t testing.TB, frame []byte, from, to lnetodhcp.OptNum) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	eth, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipv4.NewFrame(eth.Payload())
	if err != nil {
		t.Fatal(err)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil {
		t.Fatal(err)
	}
	dhcp, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	if err := dhcp.ForEachOption(func(offset int, option lnetodhcp.OptNum, _ []byte) error {
		if option == from {
			udp.Payload()[offset] = byte(to)
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("DHCP option %v not found", from)
	}
	udp.SetCRC(0)
	var checksum lneto.CRC791
	ip.CRCWriteUDPPseudo(&checksum, udp.Length())
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData()[:udp.Length()])))
	return frame
}

func BenchmarkClientKey(b *testing.B) {
	frame := testClientFrame(b, [6]byte{2, 0, 0, 0, 0, 7}, lnetodhcp.OptClientIdentifier1, []byte("bounded-client"))
	b.ReportAllocs()
	for b.Loop() {
		_ = clientKey(frame)
	}
}

func BenchmarkServerClientIdentityCanonical(b *testing.B) {
	frame := testClientFrame(b, [6]byte{2, 0, 0, 0, 0, 7}, lnetodhcp.OptClientIdentifier1, []byte("bounded-client"))
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = serverClientIdentity(frame)
	}
}
