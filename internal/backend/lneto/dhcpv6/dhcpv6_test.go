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

func TestIngressAcceptsTrafficClassAndFlowLabels(t *testing.T) {
	_, adapter, _ := newTestAdapter(t, defaultConfig())
	resource, progress, err := adapter.TryAcquire()
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryAcquire = %T %v %v", resource, progress, err)
	}
	lease := resource.(*leaseResource)
	var scratch [1514]byte
	if _, worked, err := adapter.egressLocked(scratch[:]); err != nil || !worked || lease.state != leaseWaitAdvertise {
		t.Fatalf("Solicit egress = worked:%v err:%v state:%v", worked, err, lease.state)
	}

	serverAddr := netip.MustParseAddr("fe80::2")
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")
	advertise := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	malformedAdvertise := wrapServerFrame(t, adapter, serverAddr, serverMAC, advertise)
	malformedIP, _ := lnetoipv6.NewFrame(malformedAdvertise[14:])
	malformedIP.SetHopLimit(0)
	if handled, err := adapter.ingressLocked(malformedAdvertise); err != nil || !handled || lease.state != leaseWaitAdvertise {
		t.Fatalf("malformed Advertise = handled:%v err:%v state:%v", handled, err, lease.state)
	}
	advertiseFrame := wrapServerFrame(t, adapter, serverAddr, serverMAC, advertise)
	advertiseIP, _ := lnetoipv6.NewFrame(advertiseFrame[14:])
	advertiseIP.SetVersionTrafficAndFlow(6, 0xa5, 0xabcde)
	if handled, err := adapter.ingressLocked(advertiseFrame); err != nil || !handled || lease.state != leaseRequestPending {
		t.Fatalf("labeled Advertise = handled:%v err:%v state:%v", handled, err, lease.state)
	}

	if _, worked, err := adapter.egressLocked(scratch[:]); err != nil || !worked || lease.state != leaseWaitReply {
		t.Fatalf("Request egress = worked:%v err:%v state:%v", worked, err, lease.state)
	}
	reply := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, true)
	malformedReply := wrapServerFrame(t, adapter, serverAddr, serverMAC, reply)
	malformedIP, _ = lnetoipv6.NewFrame(malformedReply[14:])
	malformedIP.SetVersionTrafficAndFlow(5, 0x5a, 0x54321)
	if handled, err := adapter.ingressLocked(malformedReply); err != nil || !handled || lease.state != leaseWaitReply {
		t.Fatalf("malformed Reply = handled:%v err:%v state:%v", handled, err, lease.state)
	}
	replyFrame := wrapServerFrame(t, adapter, serverAddr, serverMAC, reply)
	replyIP, _ := lnetoipv6.NewFrame(replyFrame[14:])
	replyIP.SetVersionTrafficAndFlow(6, 0x5a, 0x54321)
	if handled, err := adapter.ingressLocked(replyFrame); err != nil || !handled || lease.state != leaseBound {
		t.Fatalf("labeled Reply = handled:%v err:%v state:%v", handled, err, lease.state)
	}
	configuration, state, err := lease.TryResult()
	if err != nil || state != dhcpns.ResultReady || configuration.AssignedAddr != assigned {
		t.Fatalf("result = %+v %v %v", configuration, state, err)
	}
}

func TestUDPAndIPv6PayloadLengthsContainDHCPBeforeMutation(t *testing.T) {
	_, adapter, _ := newTestAdapter(t, defaultConfig())
	resource, progress, err := adapter.TryAcquire()
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryAcquire = %T %v %v", resource, progress, err)
	}
	lease := resource.(*leaseResource)
	var scratch [1514]byte
	if _, worked, err := adapter.egressLocked(scratch[:]); err != nil || !worked || lease.state != leaseWaitAdvertise {
		t.Fatalf("Solicit egress = worked:%v err:%v state:%v", worked, err, lease.state)
	}

	serverAddr := netip.MustParseAddr("fe80::2")
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")
	advertise := wrapServerFrame(t, adapter, serverAddr, serverMAC, buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false))
	if handled, err := adapter.ingressLocked(shortenIPv6UDPDatagram(t, advertise, 1)); err != nil || !handled || lease.state != leaseWaitAdvertise || lease.Readiness() != 0 {
		t.Fatalf("short UDP Advertise = handled:%v err:%v state:%v readiness:%v", handled, err, lease.state, lease.Readiness())
	}
	if handled, err := adapter.ingressLocked(appendIPv6LinkPadding(advertise)); err != nil || !handled || lease.state != leaseRequestPending {
		t.Fatalf("padded Advertise = handled:%v err:%v state:%v", handled, err, lease.state)
	}

	if _, worked, err := adapter.egressLocked(scratch[:]); err != nil || !worked || lease.state != leaseWaitReply {
		t.Fatalf("Request egress = worked:%v err:%v state:%v", worked, err, lease.state)
	}
	reply := wrapServerFrame(t, adapter, serverAddr, serverMAC, buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, true))
	if handled, err := adapter.ingressLocked(shortenIPv6UDPDatagram(t, reply, 1)); err != nil || !handled || lease.state != leaseWaitReply || lease.Readiness() != 0 {
		t.Fatalf("short UDP Reply = handled:%v err:%v state:%v readiness:%v", handled, err, lease.state, lease.Readiness())
	}
	if handled, err := adapter.ingressLocked(appendIPv6LinkPadding(reply)); err != nil || !handled || lease.state != leaseBound {
		t.Fatalf("padded Reply = handled:%v err:%v state:%v", handled, err, lease.state)
	}
	if configuration, state, err := lease.TryResult(); err != nil || state != dhcpns.ResultReady || configuration.AssignedAddr != assigned {
		t.Fatalf("result = %+v %v %v", configuration, state, err)
	}
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
	duplicateClientID := appendOption(append([]byte(nil), reply...), lnetodhcp.OptClientID, lease.clientDUID[:])
	duplicateServerID := appendOption(append([]byte(nil), reply...), lnetodhcp.OptServerID, serverDUID)
	iana := optionData(t, reply, lnetodhcp.OptIANA)
	duplicateIANA := appendOption(append([]byte(nil), reply...), lnetodhcp.OptIANA, iana)
	code, iaAddress, _, ok := nextOption(iana, 12)
	if !ok || code != lnetodhcp.OptIAAddr {
		t.Fatal("missing IA Address fixture")
	}
	duplicateIAAddress := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	duplicateIAAddress = appendToLastOption(t, duplicateIAAddress, lnetodhcp.OptIANA, appendOption(nil, lnetodhcp.OptIAAddr, iaAddress))
	malformedNested := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	malformedNested = appendToLastOption(t, malformedNested, lnetodhcp.OptIANA, []byte{0, byte(lnetodhcp.OptStatusCode), 0, 2, 0})
	clientState := lease.client.State()
	for name, frame := range map[string][]byte{
		"bad checksum":         badChecksum,
		"wrong source":         wrapServerFrame(t, adapter, netip.MustParseAddr("fe80::3"), serverMAC, reply),
		"wrong source MAC":     wrapServerFrame(t, adapter, serverAddr, [6]byte{0x02, 0, 0, 0, 0, 3}, reply),
		"wrong server DUID":    wrapServerFrame(t, adapter, serverAddr, serverMAC, buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], wrongDUID, lease.iaid, assigned, true)),
		"duplicate client ID":  wrapServerFrame(t, adapter, serverAddr, serverMAC, duplicateClientID),
		"duplicate server ID":  wrapServerFrame(t, adapter, serverAddr, serverMAC, duplicateServerID),
		"duplicate IA":         wrapServerFrame(t, adapter, serverAddr, serverMAC, duplicateIANA),
		"duplicate IA address": wrapServerFrame(t, adapter, serverAddr, serverMAC, duplicateIAAddress),
		"malformed IA option":  wrapServerFrame(t, adapter, serverAddr, serverMAC, malformedNested),
	} {
		t.Run(name, func(t *testing.T) {
			before, _ := account.Snapshot()
			if handled, err := adapter.ingressLocked(frame); err != nil || !handled {
				t.Fatalf("ingress = %v %v", handled, err)
			}
			if lease.state != leaseWaitReply || lease.attempts != 1 || lease.wait != adapter.config.ResponseServiceAttempts || !bytes.Equal(lease.packet, requestBefore) ||
				lease.serverAddr != serverAddr || lease.serverMAC != serverMAC || !bytes.Equal(lease.serverDUID[:lease.serverLen], serverDUID) ||
				lease.client.State() != clientState || lease.result != (dhcpns.Configuration{}) || lease.failure != nil {
				t.Fatalf("rejected Reply mutated lifecycle: state=%v attempts=%d wait=%d server=%v/%x client=%v result=%+v failure=%v", lease.state, lease.attempts, lease.wait, lease.serverAddr, lease.serverMAC, lease.client.State(), lease.result, lease.failure)
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
	if lease.state != leaseClosed || lease.owner != nil || lease.packet != nil || lease.packetInline != ([inlinePacketBytes]byte{}) ||
		lease.client.State() != 0 || *lease.client.ConnectionID() != 0 || lease.result != (dhcpns.Configuration{}) || lease.failure != nil ||
		lease.xid != 0 || lease.iaid != ([4]byte{}) || lease.clientDUID != ([10]byte{}) || lease.serverLen != 0 ||
		lease.serverDUID != ([dhcpns.MaxServerDUIDBytes]byte{}) || lease.serverAddr.IsValid() || lease.serverMAC != ([6]byte{}) ||
		lease.attempts != 0 || lease.wait != 0 {
		t.Fatalf("namespace close retained correlation or packet state")
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

func TestIngressConsumesRelevantInvalidEthernetSources(t *testing.T) {
	_, adapter, _ := newTestAdapter(t, defaultConfig())
	resource, _, err := adapter.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	var scratch [1514]byte
	if _, _, err := adapter.egressLocked(scratch[:]); err != nil {
		t.Fatal(err)
	}
	serverAddr := netip.MustParseAddr("fe80::2")
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	advertise := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, netip.MustParseAddr("2001:db8::10"), false)

	for name, source := range map[string][6]byte{
		"zero": {}, "broadcast": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "multicast": {1, 0, 94, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			frame := wrapServerFrame(t, adapter, serverAddr, source, advertise)
			if handled, err := adapter.ingressLocked(frame); err != nil || !handled {
				t.Fatalf("relevant invalid source = handled:%v err:%v", handled, err)
			}
			if lease.state != leaseWaitAdvertise || lease.serverLen != 0 || lease.result != (dhcpns.Configuration{}) || lease.failure != nil {
				t.Fatalf("invalid source mutated lease: state=%v serverLen=%d result=%+v failure=%v", lease.state, lease.serverLen, lease.result, lease.failure)
			}
		})
	}

	foreign := wrapServerFrame(t, adapter, serverAddr, [6]byte{}, advertise)
	eth, err := ethernet.NewFrame(foreign)
	if err != nil {
		t.Fatal(err)
	}
	*eth.DestinationHardwareAddr() = [6]byte{0x02, 0, 0, 0, 0, 99}
	if handled, err := adapter.ingressLocked(foreign); err != nil || handled {
		t.Fatalf("foreign destination = handled:%v err:%v", handled, err)
	}

	valid := wrapServerFrame(t, adapter, serverAddr, [6]byte{0x02, 0, 0, 0, 0, 2}, advertise)
	if handled, err := adapter.ingressLocked(valid); err != nil || !handled || lease.state != leaseRequestPending {
		t.Fatalf("valid advertise after drops = handled:%v err:%v state:%v", handled, err, lease.state)
	}
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

func TestReplyDropsNonUnicastDelegatedPrefixesBeforePinnedMutation(t *testing.T) {
	for _, value := range []string{"::/64", "::1/128", "fe80::/64", "ff05::/64"} {
		t.Run(value, func(t *testing.T) {
			_, adapter, account := newTestAdapter(t, defaultConfig())
			resource, _, err := adapter.TryAcquire()
			if err != nil {
				t.Fatal(err)
			}
			lease := resource.(*leaseResource)
			var scratch [1514]byte
			if _, _, err := adapter.egressLocked(scratch[:]); err != nil {
				t.Fatal(err)
			}
			serverAddr := netip.MustParseAddr("fe80::2")
			serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
			serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
			assigned := netip.MustParseAddr("2001:db8::10")
			advertise := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
			if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, advertise)); err != nil || !handled || lease.state != leaseRequestPending {
				t.Fatalf("Advertise = %v %v state=%v", handled, err, lease.state)
			}
			if _, _, err := adapter.egressLocked(scratch[:]); err != nil || lease.state != leaseWaitReply {
				t.Fatalf("Request = %v state=%v", err, lease.state)
			}

			requestBefore := append([]byte(nil), lease.packet...)
			clientState := lease.client.State()
			before, _ := account.Snapshot()
			bad := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
			bad = appendDelegatedPrefix(bad, lease.iaid, netip.MustParsePrefix(value), 1800, 3600)
			if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, bad)); err != nil || !handled {
				t.Fatalf("invalid Reply ingress = %v %v", handled, err)
			}
			if lease.state != leaseWaitReply || lease.client.State() != clientState || !bytes.Equal(lease.packet, requestBefore) || lease.result != (dhcpns.Configuration{}) || lease.failure != nil {
				t.Fatalf("invalid delegated prefix mutated lifecycle: state=%v client=%v result=%+v failure=%v", lease.state, lease.client.State(), lease.result, lease.failure)
			}
			if usage, _ := account.Snapshot(); usage != before {
				t.Fatalf("invalid delegated prefix changed quota = %+v, want %+v", usage, before)
			}

			good := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, true)
			if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, good)); err != nil || !handled || lease.state != leaseBound {
				t.Fatalf("valid Reply after drop = %v %v state=%v", handled, err, lease.state)
			}
		})
	}
}

func TestReplyAcceptsAddressWhenDelegationIsUnavailable(t *testing.T) {
	_, adapter, account := newTestAdapter(t, defaultConfig())
	resource, _, err := adapter.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	var scratch [1514]byte
	if _, _, err := adapter.egressLocked(scratch[:]); err != nil {
		t.Fatal(err)
	}
	serverAddr := netip.MustParseAddr("fe80::2")
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")
	advertise := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, advertise)); err != nil || !handled || lease.state != leaseRequestPending {
		t.Fatalf("Advertise = %v %v state=%v", handled, err, lease.state)
	}
	if _, _, err := adapter.egressLocked(scratch[:]); err != nil || lease.state != leaseWaitReply {
		t.Fatalf("Request = %v state=%v", err, lease.state)
	}

	conflicting := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, true)
	conflicting = appendToLastOption(t, conflicting, lnetodhcp.OptIAPD, appendOption(nil, lnetodhcp.OptStatusCode, []byte{0, statusNoPrefixAvailable}))
	before, _ := account.Snapshot()
	if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, conflicting)); err != nil || !handled {
		t.Fatalf("conflicting Reply = %v %v", handled, err)
	}
	if lease.state != leaseWaitReply || lease.result != (dhcpns.Configuration{}) || lease.failure != nil {
		t.Fatalf("conflicting delegation mutated lease: state=%v result=%+v failure=%v", lease.state, lease.result, lease.failure)
	}
	if usage, _ := account.Snapshot(); usage != before {
		t.Fatalf("conflicting delegation changed quota = %+v, want %+v", usage, before)
	}

	reply := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	iapd := make([]byte, 12)
	copy(iapd[:4], lease.iaid[:])
	binary.BigEndian.PutUint32(iapd[4:8], 900)
	binary.BigEndian.PutUint32(iapd[8:12], 1800)
	iapd = appendOption(iapd, lnetodhcp.OptStatusCode, []byte{0, statusNoPrefixAvailable})
	reply = appendOption(reply, lnetodhcp.OptIAPD, iapd)
	if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, reply)); err != nil || !handled || lease.state != leaseBound {
		t.Fatalf("NoPrefixAvail Reply = %v %v state=%v", handled, err, lease.state)
	}
	configuration, state, err := lease.TryResult()
	if err != nil || state != dhcpns.ResultReady || !configuration.Valid() || configuration.AssignedAddr != assigned || configuration.PrefixCount != 0 || configuration.PrefixRenewalSeconds != 0 || configuration.PrefixRebindingSeconds != 0 {
		t.Fatalf("NoPrefixAvail result = %+v %v %v", configuration, state, err)
	}
	if usage, _ := account.Snapshot(); usage.DHCPv6Work != 0 || usage.DHCPv6Resources != 1 {
		t.Fatalf("NoPrefixAvail quota = %+v", usage)
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

func TestNTPServerOptionsRequireOneSourceAndAllowRepetition(t *testing.T) {
	config := defaultConfig()
	xid := uint32(0x123456)
	iaid := [4]byte{2, 0, 0, 1}
	clientDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")

	valid := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, true)
	secondAddress := netip.MustParseAddr("2001:db8::124").As16()
	valid = appendOption(valid, lnetodhcp.OptNTPServer, appendSuboption(nil, 1, secondAddress[:]))
	unknown := appendSuboption(nil, 65000, []byte{1, 2, 3})
	valid = appendOption(valid, lnetodhcp.OptNTPServer, unknown)
	info, ok := inspectMessage(valid, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID)
	if !ok || info.ntpCount != 2 || info.ntp[1] != netip.AddrFrom16(secondAddress) || info.ntpNameCount != 1 {
		t.Fatalf("repeated NTP server options = ok:%v info:%+v", ok, info)
	}

	grouped := stripOption(buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, false), lnetodhcp.OptNTPServer)
	firstAddress := netip.MustParseAddr("2001:db8::123").As16()
	multipleSources := appendSuboption(nil, 1, firstAddress[:])
	multipleSources = appendSuboption(multipleSources, 3, encodeName("time.example.com"))
	grouped = appendOption(grouped, lnetodhcp.OptNTPServer, multipleSources)
	if _, ok := inspectMessage(grouped, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); ok {
		t.Fatal("one NTP server option containing multiple time sources accepted")
	}

	malformedUnknown := appendOption(buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, false), lnetodhcp.OptNTPServer, []byte{0xfd, 0xe8, 0, 2, 1})
	if _, ok := inspectMessage(malformedUnknown, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); ok {
		t.Fatal("malformed unknown NTP time source accepted")
	}
}

func TestIAAddressAndPrefixNestedOptionsAreValidated(t *testing.T) {
	config := defaultConfig()
	xid := uint32(0x123456)
	iaid := [4]byte{2, 0, 0, 1}
	clientDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 1}
	serverDUID := []byte{0, 3, 0, 1, 2, 0, 0, 0, 0, 2}
	assigned := netip.MustParseAddr("2001:db8::10")

	address := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, false)
	address = appendToLastNestedOption(t, address, lnetodhcp.OptIANA, lnetodhcp.OptIAAddr, appendOption(nil, lnetodhcp.OptStatusCode, []byte{0, 0}))
	if _, ok := inspectMessage(address, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); !ok {
		t.Fatal("IA Address success status rejected")
	}
	failedAddress := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, false)
	failedAddress = appendToLastNestedOption(t, failedAddress, lnetodhcp.OptIANA, lnetodhcp.OptIAAddr, appendOption(nil, lnetodhcp.OptStatusCode, []byte{0, byte(lnetodhcp.StatusNoAddrsAvail)}))
	if _, ok := inspectMessage(failedAddress, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); ok {
		t.Fatal("IA Address failure status accepted")
	}

	prefix := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, true)
	prefix = appendToLastNestedOption(t, prefix, lnetodhcp.OptIAPD, lnetodhcp.OptIAPrefix, appendOption(nil, lnetodhcp.OptCode(65000), []byte{1, 2, 3}))
	if _, ok := inspectMessage(prefix, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); !ok {
		t.Fatal("unknown IA Prefix option rejected")
	}
	malformedPrefix := buildServerPayload(t, lnetodhcp.MsgReply, xid, clientDUID, serverDUID, iaid, assigned, true)
	malformedPrefix = appendToLastNestedOption(t, malformedPrefix, lnetodhcp.OptIAPD, lnetodhcp.OptIAPrefix, []byte{0, byte(lnetodhcp.OptStatusCode), 0})
	if _, ok := inspectMessage(malformedPrefix, lnetodhcp.MsgReply, xid, clientDUID, iaid, config, serverDUID); ok {
		t.Fatal("malformed IA Prefix option accepted")
	}

	_, adapter, _ := newTestAdapter(t, config)
	resource, _, err := adapter.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	lease := resource.(*leaseResource)
	var scratch [1514]byte
	if _, _, err := adapter.egressLocked(scratch[:]); err != nil {
		t.Fatal(err)
	}
	serverAddr := netip.MustParseAddr("fe80::2")
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 2}
	advertise := buildServerPayload(t, lnetodhcp.MsgAdvertise, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, false)
	if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, advertise)); err != nil || !handled || lease.state != leaseRequestPending {
		t.Fatalf("Advertise = %v %v state=%v", handled, err, lease.state)
	}
	if _, _, err := adapter.egressLocked(scratch[:]); err != nil {
		t.Fatal(err)
	}
	reply := buildServerPayload(t, lnetodhcp.MsgReply, lease.xid, lease.clientDUID[:], serverDUID, lease.iaid, assigned, true)
	reply = appendToLastNestedOption(t, reply, lnetodhcp.OptIAPD, lnetodhcp.OptIAPrefix, appendOption(nil, lnetodhcp.OptCode(65000), []byte{1, 2, 3}))
	if handled, err := adapter.ingressLocked(wrapServerFrame(t, adapter, serverAddr, serverMAC, reply)); err != nil || !handled || lease.state != leaseBound {
		t.Fatalf("Reply with nested IA Prefix option = %v %v state=%v", handled, err, lease.state)
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

func TestAcquireQuotaFailureRollsBackOnlyAttemptedOwnership(t *testing.T) {
	baseLimits := quota.Limits{Resources: 4, DHCPv6Resources: 4, DHCPv6Work: 4, QueuedBytes: 1 << 20, ServiceUnits: 64}
	for _, test := range []struct {
		name   string
		limits quota.Limits
	}{
		{name: "retained resource denied", limits: func() quota.Limits { limits := baseLimits; limits.DHCPv6Resources = 0; return limits }()},
		{name: "queued bytes denied", limits: func() quota.Limits {
			limits := baseLimits
			limits.QueuedBytes = retainedBytes(defaultConfig()) - 1
			return limits
		}()},
		{name: "work denied after retained acquisition", limits: func() quota.Limits { limits := baseLimits; limits.DHCPv6Work = 0; return limits }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, adapter, account := newTestAdapterLimits(t, defaultConfig(), test.limits)
			if resource, progress, err := adapter.TryAcquire(); resource != nil || progress != 0 || nscoreFailure(err) != nscore.FailureResourceLimit {
				t.Fatalf("TryAcquire = %T %v %v", resource, progress, err)
			}
			if adapter.lease != nil {
				t.Fatalf("failed acquisition published lease %p", adapter.lease)
			}
			if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
				t.Fatalf("failed acquisition retained quota = %+v", usage)
			}
			core.Lock()
			ports := core.UDPPortLeaseCountLocked()
			core.Unlock()
			if ports != 1 {
				t.Fatalf("failed acquisition changed module port ownership = %d", ports)
			}
		})
	}
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
	return newTestAdapterLimits(t, config, quota.Limits{Resources: 4, DHCPv6Resources: 4, DHCPv6Work: 4, QueuedBytes: 1 << 20, ServiceUnits: 64})
}

func newTestAdapterLimits(t testing.TB, config Config, limits quota.Limits) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	return newTestAdapterAddressLimits(t, config, netip.MustParseAddr("fe80::1"), limits)
}

func newTestAdapterAddress(t testing.TB, config Config, address netip.Addr) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	return newTestAdapterAddressLimits(t, config, address, quota.Limits{Resources: 4, DHCPv6Resources: 4, DHCPv6Work: 4, QueuedBytes: 1 << 20, ServiceUnits: 64})
}

func newTestAdapterAddressLimits(t testing.TB, config Config, address netip.Addr, limits quota.Limits) (*lnetocore.Namespace, *Adapter, *quota.Account) {
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
	account := quota.NewAccount(limits)
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
	payload = appendOption(payload, lnetodhcp.OptNTPServer, appendSuboption(nil, 1, ntpAddress[:]))
	payload = appendOption(payload, lnetodhcp.OptNTPServer, appendSuboption(nil, 3, encodeName("time.example.com")))
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

func appendDelegatedPrefix(payload []byte, iaid [4]byte, prefix netip.Prefix, preferred, valid uint32) []byte {
	prefixData := make([]byte, 25)
	binary.BigEndian.PutUint32(prefixData[:4], preferred)
	binary.BigEndian.PutUint32(prefixData[4:8], valid)
	prefixData[8] = byte(prefix.Bits())
	address := prefix.Addr().As16()
	copy(prefixData[9:], address[:])
	iapd := make([]byte, 12)
	copy(iapd[:4], iaid[:])
	binary.BigEndian.PutUint32(iapd[4:8], preferred/2)
	binary.BigEndian.PutUint32(iapd[8:12], preferred)
	iapd = appendOption(iapd, lnetodhcp.OptIAPrefix, prefixData)
	return appendOption(payload, lnetodhcp.OptIAPD, iapd)
}

func appendOption(dst []byte, code lnetodhcp.OptCode, data []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(dst[start:start+2], uint16(code))
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(data)))
	return append(dst, data...)
}

func optionData(t testing.TB, payload []byte, want lnetodhcp.OptCode) []byte {
	t.Helper()
	for ptr := lnetodhcp.OptionsOffset; ptr < len(payload); {
		code, data, next, ok := nextOption(payload, ptr)
		if !ok {
			t.Fatal("malformed test payload")
		}
		if code == want {
			return append([]byte(nil), data...)
		}
		ptr = next
	}
	t.Fatalf("option %v missing", want)
	return nil
}

func appendSuboption(dst []byte, code uint16, data []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(dst[start:start+2], code)
	binary.BigEndian.PutUint16(dst[start+2:start+4], uint16(len(data)))
	return append(dst, data...)
}

func appendToLastNestedOption(t testing.TB, payload []byte, outer, inner lnetodhcp.OptCode, nested []byte) []byte {
	t.Helper()
	payload = append([]byte(nil), payload...)
	outerOffset := -1
	for ptr := lnetodhcp.OptionsOffset; ptr < len(payload); {
		code, _, next, ok := nextOption(payload, ptr)
		if !ok {
			t.Fatal("malformed test payload")
		}
		if code == outer {
			outerOffset = ptr
		}
		ptr = next
	}
	if outerOffset < 0 || outerOffset+4+int(binary.BigEndian.Uint16(payload[outerOffset+2:outerOffset+4])) != len(payload) {
		t.Fatalf("outer option %v is not last", outer)
	}
	innerOffset := -1
	for ptr := outerOffset + 4 + 12; ptr < len(payload); {
		code, _, next, ok := nextOption(payload, ptr)
		if !ok {
			t.Fatal("malformed nested test payload")
		}
		if code == inner {
			innerOffset = ptr
		}
		ptr = next
	}
	if innerOffset < 0 || innerOffset+4+int(binary.BigEndian.Uint16(payload[innerOffset+2:innerOffset+4])) != len(payload) {
		t.Fatalf("inner option %v is not last", inner)
	}
	outerLength := int(binary.BigEndian.Uint16(payload[outerOffset+2 : outerOffset+4]))
	innerLength := int(binary.BigEndian.Uint16(payload[innerOffset+2 : innerOffset+4]))
	if outerLength+len(nested) > int(^uint16(0)) || innerLength+len(nested) > int(^uint16(0)) {
		t.Fatal("nested test option too large")
	}
	binary.BigEndian.PutUint16(payload[outerOffset+2:outerOffset+4], uint16(outerLength+len(nested)))
	binary.BigEndian.PutUint16(payload[innerOffset+2:innerOffset+4], uint16(innerLength+len(nested)))
	return append(payload, nested...)
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

func shortenIPv6UDPDatagram(t testing.TB, frame []byte, bytes uint16) []byte {
	t.Helper()
	frame = append([]byte(nil), frame...)
	ip, err := lnetoipv6.NewFrame(frame[14:])
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
	ip.CRCWritePseudo(&checksum)
	udp.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udp.RawData())))
	return frame
}

func appendIPv6LinkPadding(frame []byte) []byte {
	return append(append([]byte(nil), frame...), 0xa5, 0x5a, 0xc3)
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
