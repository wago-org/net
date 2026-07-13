package dhcpv4

import (
	"net/netip"
	"testing"

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

func TestServerClientBoundAndPoolAreFinite(t *testing.T) {
	_, _ = newServer(t, 1)
	config := defaultConfig()
	config.Server = ServerConfig{ServerAddr: netip.MustParseAddr("192.0.2.1"), Subnet: netip.MustParsePrefix("192.0.2.0/24"), LeaseSeconds: 3600}
	if ValidConfig(config, 1500, new(policy.Policy), quota.NewAccount(quota.DefaultLimits()), true) {
		t.Fatal("zero server pool accepted")
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
	frame := serviceEgress(t, from)
	if err := to.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
		t.Fatal(err)
	}
	to.Lock()
	to.SetNextIngressLocked(true)
	to.Unlock()
	report, progress, err := to.TryService(nscore.ServiceBudget{Packets: 1, Bytes: 1514, Operations: 1})
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 {
		t.Fatalf("ingress = %+v, %v, %v", report, progress, err)
	}
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
