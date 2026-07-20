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
