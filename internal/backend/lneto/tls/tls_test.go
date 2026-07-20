package tls

import (
	cryptotls "crypto/tls"
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	gotls "github.com/wago-org/net/internal/backend/gotls"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	nscore "github.com/wago-org/net/internal/namespace/core"
	tlsns "github.com/wago-org/net/internal/namespace/tls"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
	"github.com/wago-org/net/internal/tlslimits"
)

func TestTLSUsesPrivateTCPWithoutRawTCPAuthorityAndRollsBack(t *testing.T) {
	denied := netip.MustParsePrefix("192.0.2.9/32")
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTLS}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportTCP}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{denied}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	limits := quota.DefaultLimits()
	account := quota.NewAccount(limits)
	mtu := uint16(ethernet.MaxMTU)
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "tls", RandSeed: 1, HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 1},
		GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 2}, IPv4Address: netip.MustParseAddr("192.0.2.1"), MTU: mtu,
		Link:              packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
		MaxActiveTCPPorts: 1, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close()
	invalidConfig := Config{
		MaxStreams: 1, MaxConcurrentHandshakes: 1, MaxServerNameBytes: 253, MaxServiceAttemptsPerHandshake: 64,
		TCP: tcpConfigForTest(), Engine: engineLimitsForTest(),
		Profiles: []gotls.Profile{{
			ID: 1, Config: &cryptotls.Config{MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13},
			MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
			AllowedNames: map[string]tlsns.IdentityType{"api.example.com": tlsns.IdentityDNS},
		}},
	}
	invalidConfig.Engine.PlaintextReceiveBytes = int(tlslimits.MaxPlaintextQueueBytes + 1)
	if invalid, err := New(common, invalidConfig); invalid != nil || failureOf(t, err) != nscore.FailureInvalidArgument {
		t.Fatalf("invalid extreme TLS config = %p, %v", invalid, err)
	}
	common.Lock()
	invalidLeases := common.TCPPortLeaseCountLocked()
	common.Unlock()
	if invalidLeases != 0 {
		t.Fatalf("invalid config installed private TCP leases = %d", invalidLeases)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("invalid config acquired quota = %+v", usage)
	}
	adapter, err := New(common, Config{
		MaxStreams: 1, MaxConcurrentHandshakes: 1, MaxServerNameBytes: 253, MaxServiceAttemptsPerHandshake: 64,
		TCP: tcpConfigForTest(), Engine: engineLimitsForTest(),
		Profiles: []gotls.Profile{{
			ID: 1, Config: &cryptotls.Config{MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13},
			MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4,
			AllowedNames: map[string]tlsns.IdentityType{"api.example.com": tlsns.IdentityDNS},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.CheckEndpoint(policy.OperationTCPConnect, netip.MustParseAddr("192.0.2.8"), 443) {
		t.Fatal("fixture accidentally grants raw TCP")
	}
	if resource, progress, err := adapter.TryConnectTLS(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.8"), Port: 443}, 1, "api.example.com"); err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("private TLS connect = %v, %v", progress, err)
	} else if err := resource.Close(); err != nil {
		t.Fatal(err)
	}
	usage, _ := account.Snapshot()
	if usage.TLSResources != 0 || usage.TLSHandshakes != 0 || usage.TCPResources != 0 {
		t.Fatalf("usage after close = %+v", usage)
	}
	if _, _, err := adapter.TryConnectTLS(nscore.Endpoint{Address: denied.Addr(), Port: 443}, 1, "api.example.com"); err == nil {
		t.Fatal("raw TCP deny did not constrain TLS")
	}
	if _, _, err := adapter.TryConnectTLS(nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.8"), Port: 443}, 1, "other.example.com"); err == nil {
		t.Fatal("unauthorized name reached transport")
	}
}

func TestTLSLoopbackAuthorityIsScopedAndFunctional(t *testing.T) {
	for _, test := range []struct {
		name  string
		allow bool
	}{
		{name: "denied by default"},
		{name: "TLS scoped grant", allow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			policyConfig := policy.Config{Rules: []policy.Rule{
				{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTLS}, Directions: []policy.Direction{policy.DirectionOutbound}},
				{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP}, Directions: []policy.Direction{policy.DirectionOutbound}},
			}}
			if test.allow {
				policyConfig.LoopbackTransports = []policy.Transport{policy.TransportTLS}
			}
			compiled, err := policy.Compile(policyConfig)
			if err != nil {
				t.Fatal(err)
			}
			mtu := uint16(ethernet.MaxMTU)
			common, err := lnetocore.New(lnetocore.Config{
				Hostname: "tls-loopback", RandSeed: 2,
				HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 2}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 3},
				IPv4Address: netip.MustParseAddr("192.0.2.2"), MTU: mtu,
				Link:              packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
				MaxActiveTCPPorts: 2, Policy: compiled,
				Quotas: quota.NewAccount(quota.Limits{Resources: 8, TCPResources: 4, TLSResources: 2, TLSHandshakes: 2, QueuedBytes: 1 << 20, TLSPlaintextBytes: 128 << 10, TLSCiphertextBytes: 128 << 10}),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer common.Close()
			raw, err := tcpbackend.New(common, tcpConfigForTest())
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := New(common, Config{
				MaxStreams: 1, MaxConcurrentHandshakes: 1, MaxServerNameBytes: 253, MaxServiceAttemptsPerHandshake: 64,
				TCP: tcpConfigForTest(), Engine: engineLimitsForTest(),
				Profiles: []gotls.Profile{{ID: 1, Config: &cryptotls.Config{MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13}, MaxCertificateChainBytes: 64 << 10, MaxPeerCertificates: 4, AllowedNames: map[string]tlsns.IdentityType{"localhost": tlsns.IdentityDNS}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			remote := nscore.Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 443}
			resource, progress, connectErr := adapter.TryConnectTLS(remote, 1, "localhost")
			if !test.allow {
				if resource != nil || progress != 0 || failureOf(t, connectErr) != nscore.FailureAccessDenied {
					t.Fatalf("default TLS loopback = %T, %v, %v", resource, progress, connectErr)
				}
				return
			}
			if connectErr != nil || resource == nil || progress != nscore.ProgressInProgress {
				t.Fatalf("granted TLS loopback = %T, %v, %v", resource, progress, connectErr)
			}
			defer resource.Close()
			if rawResource, rawProgress, rawErr := raw.TryConnect(remote); rawResource != nil || rawProgress != 0 || failureOf(t, rawErr) != nscore.FailureAccessDenied {
				t.Fatalf("TLS grant widened raw TCP = %T, %v, %v", rawResource, rawProgress, rawErr)
			}
		})
	}
}

func tcpConfigForTest() tcpbackend.Config {
	return tcpbackend.Config{MaxOutboundStreams: 1, ReceiveBytes: 512, TransmitBytes: 512, TransmitPackets: 4}
}

func engineLimitsForTest() gotls.Limits {
	return gotls.Limits{
		PlaintextReceiveBytes: 1024, PlaintextTransmitBytes: 1024,
		CiphertextReceiveBytes: 17 << 10, CiphertextTransmitBytes: 17 << 10,
		MaxHandshakeBytes: 64 << 10, MaxRecordsPerService: 4,
	}
}
