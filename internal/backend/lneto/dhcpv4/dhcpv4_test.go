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

func TestServerClientBoundAndPoolAreFinite(t *testing.T) {
	_, _ = newServer(t, 1)
	config := defaultConfig()
	config.Server = ServerConfig{ServerAddr: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600}
	if ValidConfig(config, 1500, new(policy.Policy), quota.NewAccount(quota.DefaultLimits()), true) {
		t.Fatal("zero server pool accepted")
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
	adapter, err := New(core, config)
	if err != nil {
		t.Fatal(err)
	}
	return core, adapter
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

func BenchmarkClientKey(b *testing.B) {
	frame := testClientFrame(b, [6]byte{2, 0, 0, 0, 0, 7}, lnetodhcp.OptClientIdentifier1, []byte("bounded-client"))
	b.ReportAllocs()
	for b.Loop() {
		_ = clientKey(frame)
	}
}
