package dhcpv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	lneto "github.com/soypat/lneto"
	lnetodhcp "github.com/soypat/lneto/dhcp/dhcpv6"
	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	dhcpns "github.com/wago-org/net/internal/namespace/dhcpv6"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestBoundedSolicitRequestReplyAndCopiedConfiguration(t *testing.T) {
	core, adapter, account := newTestAdapter(t, defaultConfig())
	resource, progress, err := adapter.TryAcquire()
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryAcquire = %T %v %v", resource, progress, err)
	}
	lease := resource.(*leaseResource)
	if usage, _ := account.Snapshot(); usage.Resources != 1 || usage.DHCPv6Resources != 1 || usage.DHCPv6Work != 1 || usage.QueuedBytes != retainedBytes(defaultConfig()) {
		t.Fatalf("in-flight quota = %+v", usage)
	}

	var scratch [1514]byte
	n, worked, err := adapter.egressLocked(scratch[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("Solicit egress = %d %v %v", n, worked, err)
	}
	assertClientFrame(t, scratch[:n], lnetodhcp.MsgSolicit, lease.xid)

	serverAddr := netip.MustParseAddr("fe80::2")
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	advertise := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	frame := wrapServerFrame(t, adapter, serverAddr, serverMAC, advertise)
	if handled, err := adapter.ingressLocked(frame); err != nil || !handled {
		t.Fatalf("Advertise ingress = %v %v", handled, err)
	}
	if lease.state != leaseRequestPending {
		t.Fatalf("state after Advertise = %v", lease.state)
	}

	n, worked, err = adapter.egressLocked(scratch[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("Request egress = %d %v %v", n, worked, err)
	}
	assertClientFrame(t, scratch[:n], lnetodhcp.MsgRequest, lease.xid)

	reply := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, true)
	frame = wrapServerFrame(t, adapter, serverAddr, serverMAC, reply)
	if handled, err := adapter.ingressLocked(frame); err != nil || !handled {
		t.Fatalf("Reply ingress = %v %v", handled, err)
	}
	configuration, state, err := lease.TryResult()
	if err != nil || state != dhcpns.ResultReady || !configuration.Valid() {
		t.Fatalf("result = %+v %v %v", configuration, state, err)
	}
	if configuration.AssignedAddr != assigned || configuration.ServerAddr != serverAddr || configuration.ServerScopeID != adapter.scopeID ||
		configuration.DNSCount != 1 || configuration.DNSServers[0] != netip.MustParseAddr("2001:db8::53") ||
		configuration.DomainCount != 1 || configuration.DomainSearch[0].String() != "example.com" ||
		configuration.NTPCount != 1 || configuration.NTPNameCount != 1 || configuration.NTPServerNames[0].String() != "time.example.com" ||
		configuration.PrefixCount != 1 || configuration.DelegatedPrefixes[0].Prefix != netip.MustParsePrefix("2001:db8:100::/48") {
		t.Fatalf("copied configuration = %+v", configuration)
	}
	if usage, _ := account.Snapshot(); usage.DHCPv6Work != 0 || usage.DHCPv6Resources != 1 || usage.QueuedBytes == 0 {
		t.Fatalf("completed quota = %+v", usage)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed quota = %+v", usage)
	}
	core.Lock()
	if got := core.UDPPortLeaseCountLocked(); got != 1 {
		t.Fatalf("module port lease count after resource close = %d", got)
	}
	core.Unlock()
}

func TestOperationalRetriesMalformedTransportAndNamespaceClosePreserveLifecycle(t *testing.T) {
	core, adapter, account := newTestAdapter(t, defaultConfig())
	resource, progress, err := adapter.TryAcquire()
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryAcquire = %T %v %v", resource, progress, err)
	}
	lease := resource.(*leaseResource)
	inFlight, _ := account.Snapshot()
	if inFlight.Resources != 1 || inFlight.DHCPv6Resources != 1 || inFlight.DHCPv6Work != 1 || inFlight.QueuedBytes != retainedBytes(defaultConfig()) {
		t.Fatalf("initial quota = %+v", inFlight)
	}

	frameBytes := 14 + 40 + 8 + len(lease.packet)
	short := bytes.Repeat([]byte{0xa5}, frameBytes-1)
	packetBefore := append([]byte(nil), lease.packet...)
	if n, worked, err := adapter.egressLocked(short); n != 0 || worked || !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short Solicit = %d %v %v", n, worked, err)
	}
	if lease.state != leaseSolicitPending || lease.attempts != 0 || lease.wait != 0 || !bytes.Equal(lease.packet, packetBefore) || !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
		t.Fatalf("short Solicit mutated lifecycle: state=%v attempts=%d wait=%d", lease.state, lease.attempts, lease.wait)
	}
	if usage, _ := account.Snapshot(); usage != inFlight {
		t.Fatalf("short Solicit changed quota = %+v, want %+v", usage, inFlight)
	}

	wire := make([]byte, 1514)
	n, worked, err := adapter.egressLocked(wire)
	if err != nil || !worked || n != frameBytes || lease.state != leaseWaitAdvertise || lease.attempts != 1 || lease.wait != adapter.config.ResponseServiceAttempts {
		t.Fatalf("Solicit = %d %v %v state=%v attempts=%d wait=%d", n, worked, err, lease.state, lease.attempts, lease.wait)
	}
	assertClientFrame(t, wire[:n], lnetodhcp.MsgSolicit, lease.xid)

	serverAddr := netip.MustParseAddr("fe80::2")
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")
	advertise := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, advertise)); err != nil || !handled || lease.state != leaseRequestPending {
		t.Fatalf("Advertise = %v %v state=%v", handled, err, lease.state)
	}
	if lease.attempts != 0 || lease.wait != 0 || lease.serverAddr != serverAddr || lease.serverMAC != serverMAC || !bytes.Equal(lease.serverDUID[:lease.serverLen], serverDUID) {
		t.Fatalf("selected server state = attempts=%d wait=%d addr=%v mac=%v duid=%x", lease.attempts, lease.wait, lease.serverAddr, lease.serverMAC, lease.serverDUID[:lease.serverLen])
	}

	requestBefore := append([]byte(nil), lease.packet...)
	requestBytes := 14 + 40 + 8 + len(lease.packet)
	short = bytes.Repeat([]byte{0x5a}, requestBytes-1)
	if n, worked, err := adapter.egressLocked(short); n != 0 || worked || !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short Request = %d %v %v", n, worked, err)
	}
	if lease.state != leaseRequestPending || lease.attempts != 0 || lease.wait != 0 || !bytes.Equal(lease.packet, requestBefore) || !bytes.Equal(short, bytes.Repeat([]byte{0x5a}, len(short))) {
		t.Fatalf("short Request mutated lifecycle: state=%v attempts=%d wait=%d", lease.state, lease.attempts, lease.wait)
	}

	n, worked, err = adapter.egressLocked(wire)
	if err != nil || !worked || n != requestBytes || lease.state != leaseWaitReply || lease.attempts != 1 || lease.wait != adapter.config.ResponseServiceAttempts {
		t.Fatalf("Request = %d %v %v state=%v attempts=%d wait=%d", n, worked, err, lease.state, lease.attempts, lease.wait)
	}
	assertClientFrame(t, wire[:n], lnetodhcp.MsgRequest, lease.xid)

	reply := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, true)
	badChecksum := wrapServerFrame(t, adapter, serverAddr, serverMAC, reply)
	badChecksum[len(badChecksum)-1] ^= 1
	wrongDUID := append([]byte(nil), serverDUID...)
	wrongDUID[len(wrongDUID)-1] ^= 1
	malformedNested := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	malformedNested = appendToLastOption(t, malformedNested, lnetodhcp.OptIANA, []byte{0, byte(lnetodhcp.OptStatusCode), 0, 2, 0})
	for name, frame := range map[string][]byte{
		"bad checksum":        badChecksum,
		"wrong source":        wrapServerFrame(t, adapter, netip.MustParseAddr("fe80::3"), serverMAC, reply),
		"wrong source MAC":    wrapServerFrame(t, adapter, serverAddr, [6]byte{0x02, 0, 0, 0, 0, 3}, reply),
		"wrong server DUID":   wrapServerFrame(t, adapter, serverAddr, serverMAC, buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], wrongDUID, lease.iaid, assigned, true)),
		"malformed IA option": wrapServerFrame(t, adapter, serverAddr, serverMAC, malformedNested),
	} {
		t.Run(name, func(t *testing.T) {
			before, _ := account.Snapshot()
			if handled, err := adapter.ingressLocked(frame); err != nil || !handled {
				t.Fatalf("ingress = %v %v", handled, err)
			}
			if lease.state != leaseWaitReply || lease.attempts != 1 || lease.wait != adapter.config.ResponseServiceAttempts || !bytes.Equal(lease.packet, requestBefore) {
				t.Fatalf("rejected Reply mutated lifecycle: state=%v attempts=%d wait=%d", lease.state, lease.attempts, lease.wait)
			}
			if usage, _ := account.Snapshot(); usage != before {
				t.Fatalf("rejected Reply changed quota = %+v, want %+v", usage, before)
			}
		})
	}

	if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, reply)); err != nil || !handled || lease.state != leaseBound {
		t.Fatalf("Reply = %v %v state=%v", handled, err, lease.state)
	}
	if lease.attempts != 1 || lease.wait != 0 || len(lease.packet) != 0 {
		t.Fatalf("bound lifecycle = attempts=%d wait=%d packet=%d", lease.attempts, lease.wait, len(lease.packet))
	}
	completed, _ := account.Snapshot()
	if completed.Resources != 1 || completed.DHCPv6Resources != 1 || completed.DHCPv6Work != 0 || completed.QueuedBytes != retainedBytes(defaultConfig()) {
		t.Fatalf("completed quota = %+v", completed)
	}
	configuration, state, err := lease.TryResult()
	if err != nil || state != dhcpns.ResultReady || !configuration.Valid() || configuration.AssignedAddr != assigned {
		t.Fatalf("result = %+v %v %v", configuration, state, err)
	}

	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if lease.state != leaseClosed || lease.owner != nil || lease.packet != nil || lease.result != (dhcpns.Configuration{}) {
		t.Fatalf("namespace close retained lease state: state=%v owner=%p packet=%v result=%+v", lease.state, lease.owner, lease.packet, lease.result)
	}
	if usage, closed := account.Snapshot(); usage != (quota.Usage{}) || closed {
		t.Fatalf("namespace close quota = %+v closed=%v", usage, closed)
	}
	core.Lock()
	if got := core.UDPPortLeaseCountLocked(); got != 0 {
		t.Fatalf("namespace close retained UDP port 546: %d", got)
	}
	core.Unlock()
}

func TestMalformedCorrelationStatusAndRepeatedBoundsDoNotMutate(t *testing.T) {
	_, adapter, account := newTestAdapter(t, defaultConfig())
	resource, _, err := adapter.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	var scratch [1514]byte
	_, _, _ = adapter.egressLocked(scratch[:])
	serverAddr := netip.MustParseAddr("fe80::2")
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")

	wrongClient := append([]byte(nil), lease.clientDUID[:]...)
	wrongClient[9] ^= 1
	bad := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, wrongClient, serverDUID, lease.iaid, assigned, false)
	if handled, _ := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, bad)); !handled || lease.state != leaseWaitAdvertise {
		t.Fatalf("wrong client correlation mutated state: handled=%v state=%v", handled, lease.state)
	}

	bad = buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	bad = appendOption(bad, lnetodhcp.OptStatusCode, []byte{0, byte(lnetodhcp.StatusNoAddrsAvail)})
	if handled, _ := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, bad)); !handled || lease.state != leaseWaitAdvertise {
		t.Fatalf("failure status mutated state: handled=%v state=%v", handled, lease.state)
	}

	good := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, good))
	_, _, _ = adapter.egressLocked(scratch[:])
	reply := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	var flooded []byte
	for i := 0; i < int(adapter.config.MaxDNSServers)+1; i++ {
		address := netip.MustParseAddr("2001:db8::53").As16()
		address[15] += byte(i)
		flooded = append(flooded, address[:]...)
	}
	reply = appendOption(reply, lnetodhcp.OptDNSServers, flooded)
	adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, reply))
	if lease.state != leaseWaitReply {
		t.Fatalf("option overflow mutated state = %v", lease.state)
	}
	if usage, _ := account.Snapshot(); usage.DHCPv6Work != 1 {
		t.Fatalf("rejected packet changed work quota = %+v", usage)
	}
}

func TestWireNamesAreCanonicalizedWithoutRetainingInput(t *testing.T) {
	wire := encodeName("EXAMPLE.Com")
	var names [dhcpns.MaxDomainSearch]dhcpns.Name
	var count uint8
	if !parseNames(wire, names[:], dhcpns.MaxDomainSearch, &count) || count != 1 || names[0].String() != "example.com" {
		t.Fatalf("canonicalized names = %q count=%d", names[0].String(), count)
	}
	for i := range wire {
		wire[i] = 0xff
	}
	if names[0].String() != "example.com" || !names[0].Valid() {
		t.Fatalf("wire input was retained: %q", names[0].String())
	}
}

func TestDuplicateStatusOptionsAreRejectedAtEverySupportedNesting(t *testing.T) {
	config := defaultConfig()
	xid := uint32(0x123456)
	iaid := [4]byte{2, 0, 0, 1}
	clientDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")
	status := []byte{0, 0}

	top := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, false)
	top = appendOption(top, lnetodhcp.OptStatusCode, status)
	if _, ok := inspectMessage(top, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); !ok {
		t.Fatal("single top-level success status rejected")
	}
	top = appendOption(top, lnetodhcp.OptStatusCode, status)
	if _, ok := inspectMessage(top, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); ok {
		t.Fatal("duplicate top-level status accepted")
	}

	iana := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, false)
	iana = appendToLastOption(t, iana, lnetodhcp.OptIANA, appendSuboption(nil, uint16(lnetodhcp.OptStatusCode), status))
	if _, ok := inspectMessage(iana, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); !ok {
		t.Fatal("single IA_NA success status rejected")
	}
	iana = appendToLastOption(t, iana, lnetodhcp.OptIANA, appendSuboption(nil, uint16(lnetodhcp.OptStatusCode), status))
	if _, ok := inspectMessage(iana, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); ok {
		t.Fatal("duplicate IA_NA status accepted")
	}

	iapd := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, true)
	iapd = appendToLastOption(t, iapd, lnetodhcp.OptIAPD, appendSuboption(nil, uint16(lnetodhcp.OptStatusCode), status))
	if _, ok := inspectMessage(iapd, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); !ok {
		t.Fatal("single IA_PD success status rejected")
	}
	iapd = appendToLastOption(t, iapd, lnetodhcp.OptIAPD, appendSuboption(nil, uint16(lnetodhcp.OptStatusCode), status))
	if _, ok := inspectMessage(iapd, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); ok {
		t.Fatal("duplicate IA_PD status accepted")
	}
}

func FuzzDHCPv6WireReply(f *testing.F) {
	config := defaultConfig()
	xid := uint32(0x123456)
	iaid := [4]byte{2, 0, 0, 1}
	clientDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	seed := buildServerPayload(f, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, netip.MustParseAddr("2001:db8::10"), true)
	f.Add(seed)
	f.Add([]byte{byte(lnetodhcp.MsgReply), byte(xid >> 16), byte(xid >> 8), byte(xid)})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > config.MaxPacketBytes {
			return
		}
		info, ok := inspectMessage(payload, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID)
		if !ok {
			return
		}
		if len(info.serverDUID) == 0 || info.assigned == (netip.Addr{}) || info.dnsCount > config.MaxDNSServers ||
			info.domainCount > config.MaxDomainSearch || info.ntpCount > config.MaxNTPServers ||
			info.ntpMulticastCount > config.MaxNTPMulticastServers || info.ntpNameCount > config.MaxNTPServerNames ||
			info.prefixCount > config.MaxDelegatedPrefixes {
			t.Fatalf("accepted invalid packet info: %+v", info)
		}
		if configuration, valid := info.configuration(xid, iaid, netip.MustParseAddr("fe80::2"), 7, serverDUID); !valid || !configuration.Valid() {
			t.Fatalf("accepted reply produced invalid configuration: %+v", configuration)
		}
	})
}

func TestTimeoutCancellationPortOwnershipAndDeterministicClose(t *testing.T) {
	config := defaultConfig()
	config.MaxAttempts = 1
	config.ResponseServiceAttempts = 1
	core, adapter, account := newTestAdapter(t, config)
	resource, _, err := adapter.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	var scratch [1514]byte
	_, _, _ = adapter.egressLocked(scratch[:])
	_, worked, err := adapter.egressLocked(scratch[:])
	if err != nil || !worked || lease.state != leaseFailed {
		t.Fatalf("timeout = worked=%v state=%v err=%v", worked, lease.state, err)
	}
	if _, _, err := lease.TryResult(); nscoreFailure(err) != nscore.FailureTimedOut {
		t.Fatalf("timeout result = %v", err)
	}
	if usage, _ := account.Snapshot(); usage.DHCPv6Work != 0 || usage.DHCPv6Resources != 1 {
		t.Fatalf("timeout quota = %+v", usage)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	second, _, err := adapter.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	if err := second.(dhcpns.Resource).Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	core.Lock()
	adapter.CloseLocked()
	if got := core.UDPPortLeaseCountLocked(); got != 0 {
		t.Fatalf("port leases after close = %d", got)
	}
	core.Unlock()
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("close leaked quota = %+v", usage)
	}
}

func TestZeroConfigRetainsTruthfulServiceSemantics(t *testing.T) {
	core, adapter, _ := newTestAdapter(t, Config{})
	if operations := adapter.Operations(); operations != 0 {
		t.Fatalf("disabled operations = %v", operations)
	}
	if _, _, err := adapter.TryAcquire(); nscoreFailure(err) != nscore.FailureNotSupported {
		t.Fatalf("disabled acquire = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TryAcquire(); nscoreFailure(err) != nscore.FailureClosed {
		t.Fatalf("closed disabled acquire = %v", err)
	}
}

func TestNoIPv6OrGlobalIPv6IsTruthfullyUnsupported(t *testing.T) {
	for _, address := range []netip.Addr{netip.Addr{}, netip.MustParseAddr("2001:db8::1")} {
		core, adapter, _ := newTestAdapterAddress(t, defaultConfig(), address)
		if operations := adapter.Operations(); operations != 0 {
			t.Fatalf("address %v operations = %v", address, operations)
		}
		if _, _, err := adapter.TryAcquire(); nscoreFailure(err) != nscore.FailureNotSupported {
			t.Fatalf("address %v acquire = %v", address, err)
		}
		core.Lock()
		if got := core.UDPPortLeaseCountLocked(); got != 0 {
			t.Fatalf("address %v port leases = %d", address, got)
		}
		core.Unlock()
		if err := core.Close(); err != nil {
			t.Fatal(err)
		}
		if adapter.closed {
			t.Fatalf("address %v unexpectedly installed a close participant", address)
		}
		if operations := adapter.Operations(); operations != 0 {
			t.Fatalf("closed address %v operations = %v", address, operations)
		}
		if _, _, err := adapter.TryAcquire(); nscoreFailure(err) != nscore.FailureClosed {
			t.Fatalf("closed address %v acquire = %v", address, err)
		}
	}
}

func defaultConfig() Config {
	return Config{
		MaxLeases: 1, MaxPacketBytes: 1024, MaxAttempts: 2, ResponseServiceAttempts: 2,
		MaxServerDUIDBytes: dhcpns.MaxServerDUIDBytes, MaxDNSServers: dhcpns.MaxDNSServers,
		MaxDomainSearch: dhcpns.MaxDomainSearch, MaxNTPServers: dhcpns.MaxNTPServers,
		MaxNTPMulticastServers: dhcpns.MaxNTPMulticastServers, MaxNTPServerNames: dhcpns.MaxNTPServerNames,
		MaxDelegatedPrefixes: dhcpns.MaxDelegatedPrefixes,
	}
}

func newTestAdapter(t testing.TB, config Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	return newTestAdapterAddress(t, config, netip.MustParseAddr("fe80::1"))
}

func newTestAdapterAddress(t testing.TB, config Config, address netip.Addr) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	local := address
	if !local.IsValid() {
		local = netip.MustParseAddr("fe80::1")
	}
	compiled, err := policy.Compile(policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(local, 128)}, Ports: []policy.PortRange{{First: dhcpns.ClientPort, Last: dhcpns.ClientPort}}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("::/0")}, Ports: []policy.PortRange{{First: dhcpns.ServerPort, Last: dhcpns.ServerPort}}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDHCPv6}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(allServersAndRelays, 128)}, Ports: []policy.PortRange{{First: dhcpns.ServerPort, Last: dhcpns.ServerPort}}},
		},
		MulticastTransports: []policy.Transport{policy.TransportDHCPv6}, PrivilegedBindTransports: []policy.Transport{policy.TransportDHCPv6},
	})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 4, DHCPv6Resources: 4, DHCPv6Work: 4, QueuedBytes: 1 << 20, ServiceUnits: 64})
	coreConfig := lnetocore.Config{
		Hostname: "dhcp6", RandSeed: 41, HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 1}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 9},
		IPv4Address: netip.MustParseAddr("192.0.2.1"), MTU: 1500,
		Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4}, Policy: compiled, Quotas: account,
	}
	if address.IsValid() {
		coreConfig.IPv6Address = address
		coreConfig.IPv6PrefixBits = 64
		if address.IsLinkLocalUnicast() {
			coreConfig.IPv6ScopeID = 7
		}
	}
	core, err := lnetocore.New(coreConfig)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core, config)
	if err != nil {
		t.Fatal(err)
	}
	return core, adapter, account
}

func assertClientFrame(t testing.TB, frame []byte, want lnetodhcp.MsgType, xid uint32) {
	t.Helper()
	eth, err := ethernet.NewFrame(frame)
	if err != nil || eth.EtherTypeOrSize() != ethernet.TypeIPv6 || *eth.DestinationHardwareAddr() != allServersMAC {
		t.Fatalf("Ethernet frame = %v %+v", err, eth)
	}
	ip, err := lnetoipv6.NewFrame(eth.Payload())
	if err != nil || ip.NextHeader() != lneto.IPProtoUDP || ip.HopLimit() != 1 || netip.AddrFrom16(*ip.DestinationAddr()) != allServersAndRelays {
		t.Fatalf("IPv6 frame = %v %+v", err, ip)
	}
	udp, err := lnetoudp.NewFrame(ip.Payload())
	if err != nil || udp.SourcePort() != dhcpns.ClientPort || udp.DestinationPort() != dhcpns.ServerPort || udp.CRC() == 0 {
		t.Fatalf("UDP frame = %v %+v", err, udp)
	}
	var checksum lneto.CRC791
	ip.CRCWritePseudo(&checksum)
	if checksum.PayloadSum16(udp.RawData()) != 0 {
		t.Fatal("bad UDP checksum")
	}
	dhcp, err := lnetodhcp.NewFrame(udp.Payload())
	if err != nil || dhcp.MsgType() != want || dhcp.TransactionID() != xid {
		t.Fatalf("DHCP frame = %v type=%v xid=%x", err, dhcp.MsgType(), dhcp.TransactionID())
	}
	if err := dhcp.ForEachOption(func(_ int, code lnetodhcp.OptCode, _ []byte) error {
		if code == lnetodhcp.OptReconfAccept {
			t.Fatal("unsupported Reconfigure Accept was advertised")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func buildServerPayload(t testing.TB, typ lnetodhcp.MsgType, xid uint32, clientDUID, serverDUID []byte, iaid [4]byte, assigned netip.Addr, full bool) []byte {
	t.Helper()
	payload := []byte{byte(typ), byte(xid >> 16), byte(xid >> 8), byte(xid)}
	payload = appendOption(payload, lnetodhcp.OptClientID, clientDUID)
	payload = appendOption(payload, lnetodhcp.OptServerID, serverDUID)
	address := assigned.As16()
	iaAddr := make([]byte, 24)
	copy(iaAddr[:16], address[:])
	binary.BigEndian.PutUint32(iaAddr[16:20], 1800)
	binary.BigEndian.PutUint32(iaAddr[20:24], 3600)
	iana := make([]byte, 12)
	copy(iana[:4], iaid[:])
	binary.BigEndian.PutUint32(iana[4:8], 900)
	binary.BigEndian.PutUint32(iana[8:12], 1800)
	iana = appendOption(iana, lnetodhcp.OptIAAddr, iaAddr)
	payload = appendOption(payload, lnetodhcp.OptIANA, iana)
	if !full {
		return payload
	}
	dns := netip.MustParseAddr("2001:db8::53").As16()
	payload = appendOption(payload, lnetodhcp.OptDNSServers, dns[:])
	payload = appendOption(payload, lnetodhcp.OptDomainList, encodeName("example.com"))
	ntpAddress := netip.MustParseAddr("2001:db8::123").As16()
	ntp := appendSuboption(nil, 1, ntpAddress[:])
	ntp = appendSuboption(ntp, 3, encodeName("time.example.com"))
	payload = appendOption(payload, lnetodhcp.OptNTPServer, ntp)
	prefix := netip.MustParsePrefix("2001:db8:100::/48")
	prefixAddress := prefix.Addr().As16()
	prefixData := make([]byte, 25)
	binary.BigEndian.PutUint32(prefixData[:4], 1800)
	binary.BigEndian.PutUint32(prefixData[4:8], 3600)
	prefixData[8] = byte(prefix.Bits())
	copy(prefixData[9:], prefixAddress[:])
	iapd := make([]byte, 12)
	copy(iapd[:4], iaid[:])
	binary.BigEndian.PutUint32(iapd[4:8], 900)
	binary.BigEndian.PutUint32(iapd[8:12], 1800)
	iapd = appendOption(iapd, lnetodhcp.OptIAPrefix, prefixData)
	payload = appendOption(payload, lnetodhcp.OptIAPD, iapd)
	return payload
}

func appendOption(dst []byte, code lnetodhcp.OptCode, data []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(dst[start:start+2], uint16(code))
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(data)))
	return append(dst, data...)
}

func appendSuboption(dst []byte, code uint16, data []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(dst[start:start+2], code)
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(data)))
	return append(dst, data...)
}

func appendToLastOption(t testing.TB, payload []byte, want lnetodhcp.OptCode, nested []byte) []byte {
	t.Helper()
	payload = append([]byte(nil), payload...)
	last := -1
	for ptr := lnetodhcp.OptionsOffset; ptr < len(payload); {
		code, _, next, ok := nextOption(payload, ptr)
		if !ok {
			t.Fatal("malformed test payload")
		}
		if code == want {
			last = ptr
		}
		ptr = next
	}
	if last < 0 || last+4+int(binary.BigEndian.Uint16(payload[last+2:last+4])) != len(payload) {
		t.Fatalf("option %v is not last", want)
	}
	length := int(binary.BigEndian.Uint16(payload[last+2 : last+4]))
	if length+len(nested) > int(^uint16(0)) {
		t.Fatal("nested test option too large")
	}
	binary.BigEndian.PutUint16(payload[last+2:last+4], uint16(length+len(nested)))
	return append(payload, nested...)
}

func encodeName(name string) []byte {
	var result []byte
	for len(name) != 0 {
		dot := -1
		for i := range name {
			if name[i] == '.' {
				dot = i
				break
			}
		}
		label := name
		if dot >= 0 {
			label, name = name[:dot], name[dot+1:]
		} else {
			name = ""
		}
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	return append(result, 0)
}

func wrapServerFrame(t testing.TB, adapter *Adapter, source netip.Addr, sourceMAC [6]byte, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, 14+40+8+len(payload))
	eth, _ := ethernet.NewFrame(frame)
	*eth.DestinationHardwareAddr() = adapter.hardwareAddress
	*eth.SourceHardwareAddr() = sourceMAC
	eth.SetEtherType(ethernet.TypeIPv6)
	ip, _ := lnetoipv6.NewFrame(frame[14:])
	ip.SetVersionTrafficAndFlow(6, 0, 0)
	ip.SetPayloadLength(uint16(8 + len(payload)))
	ip.SetNextHeader(lneto.IPProtoUDP)
	ip.SetHopLimit(1)
	*ip.SourceAddr() = source.As16()
	*ip.DestinationAddr() = adapter.address.As16()
	udp, _ := lnetoudp.NewFrame(frame[54:])
	udp.SetSourcePort(dhcpns.ServerPort)
	udp.SetDestinationPort(dhcpns.ClientPort)
	udp.SetLength(uint16(8 + len(payload)))
	copy(udp.RawData()[8:], payload)
	var checksum lneto.CRC791
	ip.CRCWritePseudo(&checksum)
	udp.SetCRC(0)
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData())))
	return frame
}

func nscoreFailure(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func TestConfigRejectsUnboundedOrOversizedValues(t *testing.T) {
	config := defaultConfig()
	if !ValidConfig(config, 1500, new(policy.Policy), quota.NewAccount(quota.DefaultLimits()), true) {
		t.Fatal("default config rejected")
	}
	config.MaxLeases = 2
	if ValidConfig(config, 1500, new(policy.Policy), quota.NewAccount(quota.DefaultLimits()), true) {
		t.Fatal("multiple port-546 leases accepted")
	}
	small := defaultConfig()
	small.MaxPacketBytes = 256
	large := defaultConfig()
	large.MaxPacketBytes = 1200
	if retainedBytes(small) != retainedBytes(defaultConfig()) || retainedBytes(large) != retainedBytes(defaultConfig())+1200 {
		t.Fatalf("inline packet accounting = small:%d default:%d large:%d", retainedBytes(small), retainedBytes(defaultConfig()), retainedBytes(large))
	}
	if _, ok := nscore.FailureOf(errors.New("plain")); ok {
		t.Fatal("plain errors unexpectedly categorized")
	}
}
