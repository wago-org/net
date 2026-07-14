package dhcpv6

import (
	"net/netip"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
)

func TestSupportedOperationsAreTruthful(t *testing.T) {
	if !SupportedOperations.Supports(OperationAcquire) {
		t.Fatal("acquire not advertised")
	}
	for _, operation := range []Operation{OperationRenew, OperationRebind, OperationRelease, OperationDecline, OperationConfirm, OperationInformationRequest, OperationReconfigure, OperationRapidCommit, OperationRelayAgent, OperationServer, OperationApplyIdentity, OperationRawPacket, 255} {
		if SupportedOperations.Supports(operation) {
			t.Fatalf("unsupported operation %d advertised", operation)
		}
	}
}

func TestConfigurationOwnsBoundedInlineResults(t *testing.T) {
	domain, ok := NewName("example.com")
	if !ok {
		t.Fatal("canonical domain rejected")
	}
	configuration := Configuration{
		TransactionID: 0x123456, IAID: [4]byte{2, 0, 0, 1},
		AssignedAddr: netip.MustParseAddr("2001:db8::10"), ServerAddr: netip.MustParseAddr("fe80::1"), ServerScopeID: 7,
		ServerDUIDLength: 10, RenewalSeconds: 900, RebindingSeconds: 1800,
		PreferredLifetimeSeconds: 1800, ValidLifetimeSeconds: 3600,
		DNSCount: 1, DNSServers: [MaxDNSServers]netip.Addr{netip.MustParseAddr("2001:db8::53")},
		DomainCount: 1, DomainSearch: [MaxDomainSearch]Name{domain},
		PrefixCount: 1, DelegatedPrefixes: [MaxDelegatedPrefixes]DelegatedPrefix{{Prefix: netip.MustParsePrefix("2001:db8:100::/48"), PreferredLifetime: 1800, ValidLifetime: 3600}},
		PrefixRenewalSeconds: 900, PrefixRebindingSeconds: 1800,
	}
	copy(configuration.ServerDUID[:], []byte{0, 3, 0, 1, 2, 3, 4, 5, 6, 7})
	if !configuration.Valid() {
		t.Fatalf("valid configuration rejected: %+v", configuration)
	}
	configuration.ServerDUID[20] = 1
	if configuration.Valid() {
		t.Fatal("nonzero DUID padding accepted")
	}
	configuration.ServerDUID[20] = 0
	configuration.DNSCount = 0
	if configuration.Valid() {
		t.Fatal("nonempty repeated-option padding accepted")
	}
}

func TestNameValidationRejectsNoncanonicalAndPadding(t *testing.T) {
	if _, ok := NewName("Example.COM"); ok {
		t.Fatal("uppercase name accepted")
	}
	name, ok := NewName("time.example.com")
	if !ok || name.String() != "time.example.com" || !name.Valid() {
		t.Fatalf("name = %+v, ok=%v", name, ok)
	}
	name.Bytes[100] = 1
	if name.Valid() {
		t.Fatal("name padding accepted")
	}
}

func TestResourceContractCompiles(t *testing.T) {
	var _ nscore.Resource = (Resource)(nil)
}
