package tls

import (
	cryptotls "crypto/tls"
	"net/netip"
	"sync"
	"testing"

	"github.com/soypat/lneto/ethernet"
	gotls "github.com/wago-org/net/internal/backend/gotls"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestRawTCPThenTLSAndTLSThenRawShareLivePortDomain(t *testing.T) {
	for _, test := range []struct {
		name     string
		tlsFirst bool
		ipv6     bool
	}{
		{name: "raw TCP then TLS"},
		{name: "TLS then raw TCP", tlsFirst: true},
		{name: "raw TCP then TLS IPv6", ipv6: true},
		{name: "TLS then raw TCP IPv6", tlsFirst: true, ipv6: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			common, raw, secure := newMixedAdapters(t, 8, test.ipv6)
			remoteAddress := netip.MustParseAddr("192.0.2.80")
			if test.ipv6 {
				remoteAddress = netip.MustParseAddr("2001:db8::80")
			}
			remote := nscore.Endpoint{Address: remoteAddress, Port: 443}
			var rawResource, tlsResource nscore.Resource
			var err error
			connectRaw := func() {
				rawResource, _, err = raw.TryConnect(remote)
				if err != nil {
					t.Fatalf("raw TCP connect: %v", err)
				}
			}
			connectTLS := func() {
				tlsResource, _, err = secure.TryConnectTLS(remote, 1, "api.example.com")
				if err != nil {
					t.Fatalf("TLS connect: %v", err)
				}
			}
			if test.tlsFirst {
				connectTLS()
				connectRaw()
			} else {
				connectRaw()
				connectTLS()
			}
			rawPort := rawResource.(tcpns.Stream).LocalEndpoint().Port
			tlsPort := tlsResource.(*stream).LocalEndpoint().Port
			if rawPort == 0 || tlsPort == 0 || rawPort == tlsPort {
				t.Fatalf("mixed local ports: raw=%d TLS=%d", rawPort, tlsPort)
			}
			common.Lock()
			leases := common.TCPPortLeaseCountLocked()
			common.Unlock()
			if leases != 2 {
				t.Fatalf("shared lease count = %d", leases)
			}
			if err := tlsResource.Close(); err != nil {
				t.Fatal(err)
			}
			if err := rawResource.Close(); err != nil {
				t.Fatal(err)
			}
			common.Lock()
			leases = common.TCPPortLeaseCountLocked()
			common.Unlock()
			if leases != 0 {
				t.Fatalf("released lease count = %d", leases)
			}
		})
	}
}

func TestMixedTCPAndTLSInterleavedConnectionsUseUniquePorts(t *testing.T) {
	common, raw, secure := newMixedAdapters(t, 12, false)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.81"), Port: 443}
	resources := make([]nscore.Resource, 0, 8)
	ports := make(map[uint16]struct{})
	for index := 0; index < 4; index++ {
		rawResource, _, err := raw.TryConnect(remote)
		if err != nil {
			t.Fatal(err)
		}
		tlsResource, _, err := secure.TryConnectTLS(remote, 1, "api.example.com")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range []struct {
			resource nscore.Resource
			port     uint16
		}{
			{resource: rawResource, port: rawResource.(tcpns.Stream).LocalEndpoint().Port},
			{resource: tlsResource, port: tlsResource.(*stream).LocalEndpoint().Port},
		} {
			if _, duplicate := ports[entry.port]; duplicate {
				t.Fatalf("duplicate mixed local port %d", entry.port)
			}
			ports[entry.port] = struct{}{}
			resources = append(resources, entry.resource)
		}
	}
	common.Lock()
	leases := common.TCPPortLeaseCountLocked()
	common.Unlock()
	if leases != len(resources) {
		t.Fatalf("lease count = %d, resources=%d", leases, len(resources))
	}
	for _, resource := range resources {
		if err := resource.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMixedTCPListenerPreventsTLSOutboundPortCollision(t *testing.T) {
	common, raw, secure := newMixedAdapters(t, 4, false)
	listener, _, err := raw.TryListen(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.70"), Port: lnetocore.FirstEphemeralTCPPort})
	if err != nil {
		t.Fatal(err)
	}
	secureResource, _, err := secure.TryConnectTLS(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.82"), Port: 443}, 1, "api.example.com")
	if err != nil {
		t.Fatalf("TLS connect with live listener: %v", err)
	}
	if got := secureResource.(*stream).LocalEndpoint().Port; got == lnetocore.FirstEphemeralTCPPort {
		t.Fatalf("TLS reused listener port %d", got)
	}
	if err := secureResource.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	common.Lock()
	leases := common.TCPPortLeaseCountLocked()
	common.Unlock()
	if leases != 0 {
		t.Fatalf("listener/TLS leases after close = %d", leases)
	}
}

func TestMixedTCPListenerReportsSharedPortExhaustion(t *testing.T) {
	_, raw, secure := newMixedAdapters(t, 1, false)
	secureResource, _, err := secure.TryConnectTLS(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.87"), Port: 443}, 1, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer secureResource.Close()
	if listener, progress, err := raw.TryListen(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.70"), Port: 4500}); listener != nil || progress != 0 || failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("listener under shared exhaustion = %T, %v, %v", listener, progress, err)
	}
}

func TestMixedTCPAndTLSSharedPortExhaustionIsBounded(t *testing.T) {
	common, raw, secure := newMixedAdapters(t, 2, false)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.84"), Port: 443}
	rawResource, _, err := raw.TryConnect(remote)
	if err != nil {
		t.Fatal(err)
	}
	secureResource, _, err := secure.TryConnectTLS(remote, 1, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if resource, progress, err := raw.TryConnect(remote); resource != nil || progress != 0 || failureOf(t, err) != nscore.FailureResourceLimit {
		t.Fatalf("exhausted mixed connect = %T, %v, %v", resource, progress, err)
	}
	common.Lock()
	leases := common.TCPPortLeaseCountLocked()
	common.Unlock()
	if leases != 2 {
		t.Fatalf("exhausted lease count = %d", leases)
	}
	_ = secureResource.Close()
	_ = rawResource.Close()
}

func TestFailedTLSSetupReleasesSharedPortLease(t *testing.T) {
	common, _, secure := newMixedAdapters(t, 2, false)
	profile := secure.profiles[1]
	profile.Config = nil
	secure.profiles[1] = profile
	resource, progress, err := secure.TryConnectTLS(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.85"), Port: 443}, 1, "api.example.com")
	if resource != nil || progress != 0 || failureOf(t, err) != nscore.FailureUnsupportedConfiguration {
		t.Fatalf("failed TLS setup = %T, %v, %v", resource, progress, err)
	}
	common.Lock()
	leases := common.TCPPortLeaseCountLocked()
	common.Unlock()
	if leases != 0 {
		t.Fatalf("failed TLS setup retained %d leases", leases)
	}
	if usage, _ := secure.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("failed TLS setup quota = %+v", usage)
	}
}

func TestMixedTCPAndTLSTeardownClearsPortLeases(t *testing.T) {
	common, raw, secure := newMixedAdapters(t, 4, false)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.86"), Port: 443}
	if _, _, err := raw.TryConnect(remote); err != nil {
		t.Fatal(err)
	}
	if _, _, err := secure.TryConnectTLS(remote, 1, "api.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := common.Close(); err != nil {
		t.Fatal(err)
	}
	common.Lock()
	leases := common.TCPPortLeaseCountLocked()
	common.Unlock()
	if leases != 0 {
		t.Fatalf("teardown retained %d leases", leases)
	}
	if usage, _ := secure.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("teardown quota = %+v", usage)
	}
}

func TestMixedTCPAndTLSConcurrentConnectionAttempts(t *testing.T) {
	common, raw, secure := newMixedAdapters(t, 16, false)
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.83"), Port: 443}
	resources := make(chan nscore.Resource, 12)
	errors := make(chan error, 12)
	var workers sync.WaitGroup
	for index := 0; index < 6; index++ {
		workers.Add(2)
		go func() {
			defer workers.Done()
			resource, _, err := raw.TryConnect(remote)
			if err != nil {
				errors <- err
				return
			}
			resources <- resource
		}()
		go func() {
			defer workers.Done()
			resource, _, err := secure.TryConnectTLS(remote, 1, "api.example.com")
			if err != nil {
				errors <- err
				return
			}
			resources <- resource
		}()
	}
	workers.Wait()
	close(resources)
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent mixed connect: %v", err)
	}
	ports := make(map[uint16]struct{})
	var retained []nscore.Resource
	for resource := range resources {
		retained = append(retained, resource)
		var port uint16
		if rawStream, ok := resource.(tcpns.Stream); ok {
			port = rawStream.LocalEndpoint().Port
		} else {
			port = resource.(*stream).LocalEndpoint().Port
		}
		if _, duplicate := ports[port]; duplicate {
			t.Fatalf("duplicate concurrent mixed port %d", port)
		}
		ports[port] = struct{}{}
	}
	if len(retained) != 12 {
		t.Fatalf("resources = %d", len(retained))
	}
	for _, resource := range retained {
		if err := resource.Close(); err != nil {
			t.Fatal(err)
		}
	}
	common.Lock()
	leases := common.TCPPortLeaseCountLocked()
	common.Unlock()
	if leases != 0 {
		t.Fatalf("concurrent leases after close = %d", leases)
	}
}

func failureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("unclassified failure: %v", err)
	}
	return failure
}

func newMixedAdapters(t testing.TB, maxPorts uint16, ipv6 bool) (*lnetocore.Namespace, *tcpbackend.Adapter, *Adapter) {
	t.Helper()
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP}, Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound}},
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTLS}, Directions: []policy.Direction{policy.DirectionOutbound}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mtu := uint16(ethernet.MaxMTU)
	config := lnetocore.Config{
		Hostname: "mixed", RandSeed: 70,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 70}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 80},
		IPv4Address: netip.MustParseAddr("192.0.2.70"), MTU: mtu,
		Link:              packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 32, EgressFrames: 32},
		MaxActiveTCPPorts: maxPorts, Policy: compiled,
		Quotas: quota.NewAccount(quota.Limits{Resources: 64, TCPResources: 32, TLSResources: 16, TLSHandshakes: 16, QueuedBytes: 4 << 20, TLSPlaintextBytes: 1 << 20, TLSCiphertextBytes: 1 << 20}),
	}
	if ipv6 {
		config.IPv6Address = netip.MustParseAddr("2001:db8::70")
		config.IPv6PrefixBits = 64
	}
	common, err := lnetocore.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = common.Close() })
	raw, err := tcpbackend.New(common, tcpbackend.Config{MaxListeners: 1, MaxOutboundStreams: maxPorts, AcceptBacklog: 1, ReceiveBytes: 512, TransmitBytes: 512, TransmitPackets: 4})
	if err != nil {
		t.Fatal(err)
	}
	secure, err := New(common, Config{
		MaxStreams: maxPorts, MaxConcurrentHandshakes: maxPorts,
		MaxServerNameBytes: 253, MaxServiceAttemptsPerHandshake: 64,
		TCP:    tcpbackend.Config{MaxOutboundStreams: maxPorts, ReceiveBytes: 512, TransmitBytes: 512, TransmitPackets: 4},
		Engine: engineLimitsForTest(),
		Profiles: []gotls.Profile{{
			ID: 1, Config: &cryptotls.Config{MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13},
			MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
			AllowedNames: map[string]tlsns.IdentityType{"api.example.com": tlsns.IdentityDNS},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return common, raw, secure
}
