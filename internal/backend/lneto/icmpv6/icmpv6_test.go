package icmpv6

import (
	"bytes"
	"errors"
	"net/netip"
	"strconv"
	"testing"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	lnetoipv6 "github.com/soypat/lneto/ipv6"
	lnetoicmp "github.com/soypat/lneto/ipv6/icmpv6"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	ipv6backend "github.com/wago-org/net/internal/backend/lneto/ipv6"
	nscore "github.com/wago-org/net/internal/namespace/core"
	icmpns "github.com/wago-org/net/internal/namespace/icmpv6"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestLinkLocalEchoRequiresResolvedNeighborInsteadOfGateway(t *testing.T) {
	core, adapter := newTestAdapter(t, 8, "fe80::8")
	defer core.Close()
	target := netip.MustParseAddr("fe80::99")
	request := icmpns.EchoRequest{Destination: target, ScopeID: adapter.scopeID, Payload: []byte("on-link")}
	before, _ := adapter.quotas.Snapshot()
	if resource, progress, err := adapter.TryEcho(request); resource != nil || progress != 0 || nscoreFailure(err) != nscore.FailureInvalidState {
		t.Fatalf("unresolved link-local echo = %T, %v, %v", resource, progress, err)
	}
	if usage, _ := adapter.quotas.Snapshot(); usage != before || len(adapter.echoes) != 0 || len(adapter.byIdentity) != 0 {
		t.Fatalf("unresolved link-local echo retained state: usage=%+v before=%+v echoes=%d identities=%d", usage, before, len(adapter.echoes), len(adapter.byIdentity))
	}

	neighborMAC := [6]byte{0x02, 0, 0, 0, 0, 99}
	if err := adapter.SeedNeighbor(icmpns.Neighbor{Address: target, ScopeID: adapter.scopeID, MAC: neighborMAC}); err != nil {
		t.Fatal(err)
	}
	resource, progress, err := adapter.TryEcho(request)
	if err != nil || progress != nscore.ProgressInProgress || resource == nil {
		t.Fatalf("resolved link-local echo = %T, %v, %v", resource, progress, err)
	}
	frame := make([]byte, core.Link().MaxFrameBytes())
	written, worked, err := adapter.egressLocked(frame)
	if err != nil || !worked || written == 0 || [6]byte(frame[:6]) != neighborMAC {
		t.Fatalf("resolved link-local egress = %d, %v, %v destination=%x", written, worked, err, frame[:6])
	}
}

func TestEchoRequiresAUsableGatewayOrResolvedNeighbor(t *testing.T) {
	target := netip.MustParseAddr("2001:db8::99")
	neighborMAC := [6]byte{0x02, 0, 0, 0, 0, 99}
	for name, gateway := range map[string][6]byte{
		"zero":      {},
		"multicast": {0x01, 0, 0, 0, 0, 1},
		"broadcast": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			core, adapter := newTestAdapterWithGateway(t, 9, "2001:db8::9", gateway)
			before, _ := adapter.quotas.Snapshot()
			if _, _, err := adapter.TryEcho(icmpns.EchoRequest{Destination: target, Payload: []byte("unresolved")}); nscoreFailure(err) != nscore.FailureInvalidState {
				t.Fatalf("echo without usable layer-2 destination = %v", err)
			}
			if usage, _ := adapter.quotas.Snapshot(); usage != before || len(adapter.echoes) != 0 || len(adapter.byIdentity) != 0 {
				t.Fatalf("rejected echo retained state: usage=%+v before=%+v echoes=%d identities=%d", usage, before, len(adapter.echoes), len(adapter.byIdentity))
			}

			neighbor := icmpns.Neighbor{Address: target, MAC: neighborMAC}
			if err := adapter.SeedNeighbor(neighbor); err != nil {
				t.Fatal(err)
			}
			resource, progress, err := adapter.TryEcho(icmpns.EchoRequest{Destination: target, Payload: []byte("removed")})
			if err != nil || progress != nscore.ProgressInProgress {
				t.Fatalf("seeded echo = %T, %v, %v", resource, progress, err)
			}
			exchange := resource.(*echo)
			if err := adapter.RemoveNeighbor(icmpns.NeighborRequest{Address: target}); err != nil {
				t.Fatal(err)
			}
			frame := bytes.Repeat([]byte{0xa5}, core.Link().MaxFrameBytes())
			written, worked, err := adapter.egressLocked(frame)
			if err != nil || !worked || written != 0 || !bytes.Equal(frame, bytes.Repeat([]byte{0xa5}, len(frame))) {
				t.Fatalf("removed-neighbor egress = %d, %v, %v frame-prefix=%x", written, worked, err, frame[:6])
			}
			if _, _, err := exchange.TryResult(nil); nscoreFailure(err) != nscore.FailureInvalidState {
				t.Fatalf("removed-neighbor result = %v", err)
			}
			if err := exchange.Close(); err != nil {
				t.Fatal(err)
			}

			if err := adapter.SeedNeighbor(neighbor); err != nil {
				t.Fatal(err)
			}
			resource, progress, err = adapter.TryEcho(icmpns.EchoRequest{Destination: target, Payload: []byte("seeded")})
			if err != nil || progress != nscore.ProgressInProgress {
				t.Fatalf("reseeded echo = %T, %v, %v", resource, progress, err)
			}
			clear(frame)
			written, worked, err = adapter.egressLocked(frame)
			if err != nil || !worked || written == 0 || [6]byte(frame[:6]) != neighborMAC {
				t.Fatalf("seeded-neighbor egress = %d, %v, %v destination=%x", written, worked, err, frame[:6])
			}
			if err := resource.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEchoAndNDPExchange(t *testing.T) {
	coreA, a := newTestAdapter(t, 1, "2001:db8::1")
	coreB, b := newTestAdapter(t, 2, "2001:db8::2")
	defer coreA.Close()
	defer coreB.Close()

	neighborResource, progress, err := a.TryResolve(icmpns.NeighborRequest{Address: b.address})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryResolve = %T %v %v", neighborResource, progress, err)
	}
	resolved := neighborResource.(*resolution)
	var frame [1514]byte
	n, worked, err := a.egressLocked(frame[:])
	if err != nil || !worked || n != 14+40+ndpSize {
		t.Fatalf("NS egress = %d %v %v", n, worked, err)
	}
	assertNDPFrame(t, frame[:n], lnetoicmp.TypeNeighborSolicitation, 255, solicitedNodeMAC(b.address))
	if handled, err := b.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("NS ingress = %v %v", handled, err)
	}
	n, worked, err = b.egressLocked(frame[:])
	if err != nil || !worked || n != 14+40+ndpSize {
		t.Fatalf("NA egress = %d %v %v", n, worked, err)
	}
	assertNDPFrame(t, frame[:n], lnetoicmp.TypeNeighborAdvertisement, 255, a.hardwareAddress)
	if handled, err := a.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("NA ingress = %v %v", handled, err)
	}
	neighbor, next, err := resolved.TryResult()
	if err != nil || next != icmpns.NextReady || neighbor.Address != b.address || neighbor.MAC != b.hardwareAddress || resolved.Readiness() != nscore.ReadyICMPv6Neighbor {
		t.Fatalf("neighbor result = %+v %v %v readiness=%v", neighbor, next, err, resolved.Readiness())
	}

	echoResource, progress, err := a.TryEcho(icmpns.EchoRequest{Destination: b.address, Payload: []byte("bounded ping6")})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryEcho = %T %v %v", echoResource, progress, err)
	}
	echo := echoResource.(*echo)
	n, worked, err = a.egressLocked(frame[:])
	if err != nil || !worked || n == 0 || [6]byte(frame[0:6]) != b.hardwareAddress {
		t.Fatalf("echo egress = %d %v %v dst=%x", n, worked, err, frame[:6])
	}
	if handled, err := b.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("echo request ingress = %v %v", handled, err)
	}
	n, worked, err = b.egressLocked(frame[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo response egress = %d %v %v", n, worked, err)
	}
	if handled, err := a.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("echo reply ingress = %v %v", handled, err)
	}
	var copied [7]byte
	result, next, err := echo.TryResult(copied[:])
	if err != nil || next != icmpns.NextReady || result.Source != b.address || result.Copied != len(copied) || result.PayloadBytes != len("bounded ping6") || string(copied[:]) != "bounded" || echo.Readiness() != nscore.ReadyICMPv6Reply {
		t.Fatalf("echo result = %+v %v %v payload=%q readiness=%v", result, next, err, copied[:], echo.Readiness())
	}
}

func TestEchoReplyAcceptsNonzeroIPv6FlowLabel(t *testing.T) {
	coreA, a := newTestAdapter(t, 11, "2001:db8::11")
	coreB, b := newTestAdapter(t, 12, "2001:db8::12")
	defer coreA.Close()
	defer coreB.Close()
	if err := a.SeedNeighbor(icmpns.Neighbor{Address: b.address, MAC: b.hardwareAddress}); err != nil {
		t.Fatal(err)
	}
	resource, progress, err := a.TryEcho(icmpns.EchoRequest{Destination: b.address, Payload: []byte("flow label")})
	if err != nil || progress != nscore.ProgressInProgress {
		t.Fatalf("TryEcho = %T %v %v", resource, progress, err)
	}
	exchange := resource.(*echo)
	var frame [1514]byte
	n, worked, err := a.egressLocked(frame[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo request egress = %d %v %v", n, worked, err)
	}
	if handled, err := b.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("echo request ingress = %v %v", handled, err)
	}
	n, worked, err = b.egressLocked(frame[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo reply egress = %d %v %v", n, worked, err)
	}
	ipFrame, err := lnetoipv6.NewFrame(frame[14:n])
	if err != nil {
		t.Fatal(err)
	}
	version, traffic, _ := ipFrame.VersionTrafficAndFlow()
	ipFrame.SetVersionTrafficAndFlow(version, traffic, 0xabcde)
	if handled, err := a.ingressLocked(frame[:n]); err != nil || !handled {
		t.Fatalf("echo reply ingress = %v %v", handled, err)
	}
	result, next, err := exchange.TryResult(nil)
	if err != nil || next != icmpns.NextReady || result.Source != b.address || exchange.Readiness() != nscore.ReadyICMPv6Reply {
		t.Fatalf("echo result = %+v %v %v readiness=%v", result, next, err, exchange.Readiness())
	}
}

func TestEchoShortBufferPreservesRoundRobinStateAndPendingExchanges(t *testing.T) {
	core, adapter := newTestAdapter(t, 31, "2001:db8::31")
	defer core.Close()
	firstRequest := icmpns.EchoRequest{Destination: netip.MustParseAddr("2001:db8::41"), Payload: []byte("first")}
	secondRequest := icmpns.EchoRequest{Destination: netip.MustParseAddr("2001:db8::42"), Payload: []byte("second")}
	firstResource, _, err := adapter.TryEcho(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondResource, _, err := adapter.TryEcho(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	first := firstResource.(*echo)
	second := secondResource.(*echo)
	firstPayload := append([]byte(nil), first.payload...)
	secondPayload := append([]byte(nil), second.payload...)
	firstReady, secondReady := first.Readiness(), second.Readiness()
	usageBefore, _ := adapter.quotas.Snapshot()
	short := bytes.Repeat([]byte{0xa5}, 14+40+icmpHeader+len(first.payload)-1)

	core.Lock()
	written, worked, err := adapter.egressLocked(short)
	cursor := adapter.cursor
	core.Unlock()
	if written != 0 || worked || !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short echo egress = %d, %v, %v", written, worked, err)
	}
	if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
		t.Fatalf("short echo egress mutated destination = %x", short)
	}
	if cursor != 0 || first.state != statePending || second.state != statePending || first.attempts != 0 || second.attempts != 0 || first.retry != 0 || second.retry != 0 || first.destination != firstRequest.Destination || second.destination != secondRequest.Destination || !bytes.Equal(first.payload, firstPayload) || !bytes.Equal(second.payload, secondPayload) {
		t.Fatalf("short echo egress mutated scheduler or exchanges: cursor=%d first=%v/%d/%d second=%v/%d/%d", cursor, first.state, first.attempts, first.retry, second.state, second.attempts, second.retry)
	}
	if first.Readiness() != firstReady || second.Readiness() != secondReady {
		t.Fatalf("short echo egress changed readiness: first=%v/%v second=%v/%v", first.Readiness(), firstReady, second.Readiness(), secondReady)
	}
	if usage, _ := adapter.quotas.Snapshot(); usage != usageBefore {
		t.Fatalf("short echo egress changed quota = %+v, want %+v", usage, usageBefore)
	}

	frame := make([]byte, core.Link().MaxFrameBytes())
	core.Lock()
	firstBytes, firstWorked, err := adapter.egressLocked(frame)
	cursorAfterFirst := adapter.cursor
	core.Unlock()
	if err != nil || !firstWorked || firstBytes == 0 || cursorAfterFirst != 1 {
		t.Fatalf("first echo retry = %d, %v, %v, cursor=%d", firstBytes, firstWorked, err, cursorAfterFirst)
	}
	firstIP, err := lnetoipv6.NewFrame(frame[14:firstBytes])
	if err != nil {
		t.Fatal(err)
	}
	firstICMP, err := lnetoicmp.NewFrame(firstIP.Payload())
	if err != nil {
		t.Fatal(err)
	}
	firstEcho := lnetoicmp.FrameEcho{Frame: firstICMP}
	if netip.AddrFrom16(*firstIP.DestinationAddr()) != first.destination || firstEcho.Identifier() != first.identifier || firstEcho.SequenceNumber() != first.sequence || !bytes.Equal(firstEcho.Data(), firstPayload) {
		t.Fatalf("first echo retry frame = destination=%v identity=%d/%d payload=%q", netip.AddrFrom16(*firstIP.DestinationAddr()), firstEcho.Identifier(), firstEcho.SequenceNumber(), firstEcho.Data())
	}

	core.Lock()
	secondBytes, secondWorked, err := adapter.egressLocked(frame)
	cursorAfterSecond := adapter.cursor
	core.Unlock()
	if err != nil || !secondWorked || secondBytes == 0 || cursorAfterSecond != 0 {
		t.Fatalf("second echo egress = %d, %v, %v, cursor=%d", secondBytes, secondWorked, err, cursorAfterSecond)
	}
	secondIP, err := lnetoipv6.NewFrame(frame[14:secondBytes])
	if err != nil {
		t.Fatal(err)
	}
	secondICMP, err := lnetoicmp.NewFrame(secondIP.Payload())
	if err != nil {
		t.Fatal(err)
	}
	secondEcho := lnetoicmp.FrameEcho{Frame: secondICMP}
	if netip.AddrFrom16(*secondIP.DestinationAddr()) != second.destination || secondEcho.Identifier() != second.identifier || secondEcho.SequenceNumber() != second.sequence || !bytes.Equal(secondEcho.Data(), secondPayload) {
		t.Fatalf("second echo frame = destination=%v identity=%d/%d payload=%q", netip.AddrFrom16(*secondIP.DestinationAddr()), secondEcho.Identifier(), secondEcho.SequenceNumber(), secondEcho.Data())
	}
}

func TestResolutionAndEchoEgressRoundRobinBoundsPendingWorkDelay(t *testing.T) {
	core, adapter := newTestAdapter(t, 32, "2001:db8::32")
	defer core.Close()
	firstTarget := netip.MustParseAddr("2001:db8::51")
	secondTarget := netip.MustParseAddr("2001:db8::52")
	firstResource, _, err := adapter.TryResolve(icmpns.NeighborRequest{Address: firstTarget})
	if err != nil {
		t.Fatal(err)
	}
	secondResource, _, err := adapter.TryResolve(icmpns.NeighborRequest{Address: secondTarget})
	if err != nil {
		t.Fatal(err)
	}
	echoResource, _, err := adapter.TryEcho(icmpns.EchoRequest{Destination: netip.MustParseAddr("2001:db8::53"), Payload: []byte("fair")})
	if err != nil {
		t.Fatal(err)
	}
	first := firstResource.(*resolution)
	second := secondResource.(*resolution)
	echo := echoResource.(*echo)
	frame := make([]byte, core.Link().MaxFrameBytes())
	wantDestinations := []netip.Addr{solicitedNode(firstTarget), solicitedNode(secondTarget), echo.destination}
	for i, want := range wantDestinations {
		core.Lock()
		written, worked, err := adapter.egressLocked(frame)
		cursor := adapter.cursor
		core.Unlock()
		if err != nil || !worked || written == 0 {
			t.Fatalf("egress %d = %d, %v, %v", i, written, worked, err)
		}
		ipFrame, err := lnetoipv6.NewFrame(frame[14:written])
		if err != nil {
			t.Fatal(err)
		}
		if got := netip.AddrFrom16(*ipFrame.DestinationAddr()); got != want {
			t.Fatalf("egress %d destination = %v, want %v (cursor=%d)", i, got, want, cursor)
		}
	}
	if first.state != stateWaiting || second.state != stateWaiting || echo.state != stateWaiting || first.attempts != 1 || second.attempts != 1 || echo.attempts != 1 || adapter.cursor != 0 {
		t.Fatalf("round robin state = first %v/%d second %v/%d echo %v/%d cursor=%d", first.state, first.attempts, second.state, second.attempts, echo.state, echo.attempts, adapter.cursor)
	}
}

func TestNeighborResolutionAcceptsRouterFlaggedAdvertisement(t *testing.T) {
	coreA, a := newTestAdapter(t, 19, "2001:db8::19")
	coreB, b := newTestAdapter(t, 20, "2001:db8::20")
	defer coreA.Close()
	defer coreB.Close()
	resource, _, err := a.TryResolve(icmpns.NeighborRequest{Address: b.address})
	if err != nil {
		t.Fatal(err)
	}
	resolved := resource.(*resolution)
	var storage [1514]byte
	n, worked, err := a.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("neighbor solicitation = %d, %v, %v", n, worked, err)
	}
	if handled, err := b.ingressLocked(storage[:n]); err != nil || !handled {
		t.Fatalf("neighbor solicitation ingress = %v, %v", handled, err)
	}
	n, worked, err = b.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("neighbor advertisement = %d, %v, %v", n, worked, err)
	}
	advertisement := append([]byte(nil), storage[:n]...)
	ethernetFrame, _ := ethernet.NewFrame(advertisement)
	ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
	icmpFrame, _ := lnetoicmp.NewFrame(ipFrame.Payload())
	ipFrame.Payload()[4] |= 0x80
	setChecksum(ipFrame, icmpFrame, ipFrame.Payload())
	if handled, err := a.ingressLocked(advertisement); err != nil || !handled {
		t.Fatalf("router-flagged neighbor advertisement ingress = %v, %v", handled, err)
	}
	neighbor, next, err := resolved.TryResult()
	if err != nil || next != icmpns.NextReady || neighbor.Address != b.address || neighbor.MAC != b.hardwareAddress {
		t.Fatalf("router-flagged neighbor result = %+v, %v, %v", neighbor, next, err)
	}
}

func TestICMPv6ReplyIgnoresBytesBeyondIPv6PayloadLength(t *testing.T) {
	coreA, a := newTestAdapter(t, 21, "2001:db8::21")
	coreB, b := newTestAdapter(t, 22, "2001:db8::22")
	defer coreA.Close()
	defer coreB.Close()
	if err := a.SeedNeighbor(icmpns.Neighbor{Address: b.address, MAC: b.hardwareAddress}); err != nil {
		t.Fatal(err)
	}
	resource, _, err := a.TryEcho(icmpns.EchoRequest{Destination: b.address, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	exchange := resource.(*echo)
	var storage [1514]byte
	n, worked, err := a.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo request = %d, %v, %v", n, worked, err)
	}
	if handled, err := b.ingressLocked(storage[:n]); err != nil || !handled {
		t.Fatalf("echo request ingress = %v, %v", handled, err)
	}
	n, worked, err = b.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo reply = %d, %v, %v", n, worked, err)
	}
	reply := append([]byte(nil), storage[:n]...)
	reply = append(reply, bytes.Repeat([]byte{0xa5}, 17)...)
	if handled, err := a.ingressLocked(reply); err != nil || !handled {
		t.Fatalf("echo reply ingress = %v, %v", handled, err)
	}
	if got := exchange.Readiness(); got != nscore.ReadyICMPv6Reply {
		t.Fatalf("reply with trailing link bytes readiness = %v", got)
	}
	result, next, err := exchange.TryResult(nil)
	if err != nil || next != icmpns.NextReady || result.PayloadBytes != 1 {
		t.Fatalf("reply with trailing link bytes = %+v, %v, %v", result, next, err)
	}
}

func TestMalformedCorrelatedEchoRepliesAreDroppedWithoutRetiringExchange(t *testing.T) {
	coreA, a := newTestAdapter(t, 23, "2001:db8::23")
	coreB, b := newTestAdapter(t, 24, "2001:db8::24")
	defer coreA.Close()
	defer coreB.Close()
	if err := a.SeedNeighbor(icmpns.Neighbor{Address: b.address, MAC: b.hardwareAddress}); err != nil {
		t.Fatal(err)
	}
	resource, _, err := a.TryEcho(icmpns.EchoRequest{Destination: b.address, Payload: []byte("correlated")})
	if err != nil {
		t.Fatal(err)
	}
	exchange := resource.(*echo)
	key := identityKey(exchange.identifier, exchange.sequence)
	var storage [1514]byte
	n, worked, err := a.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo request = %d, %v, %v", n, worked, err)
	}
	if handled, err := b.ingressLocked(storage[:n]); err != nil || !handled {
		t.Fatalf("echo request ingress = %v, %v", handled, err)
	}
	n, worked, err = b.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo reply = %d, %v, %v", n, worked, err)
	}
	valid := append([]byte(nil), storage[:n]...)
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "bad checksum", mutate: func(frame []byte) {
			frame[14+40+2] ^= 0x80
		}},
		{name: "declared payload exceeds frame", mutate: func(frame []byte) {
			ethernetFrame, _ := ethernet.NewFrame(frame)
			ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
			ipFrame.SetPayloadLength(ipFrame.PayloadLength() + 1)
		}},
		{name: "payload mismatch", mutate: func(frame []byte) {
			ethernetFrame, _ := ethernet.NewFrame(frame)
			ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
			icmpFrame, _ := lnetoicmp.NewFrame(ipFrame.Payload())
			ipFrame.Payload()[icmpHeader] ^= 0x01
			setChecksum(ipFrame, icmpFrame, ipFrame.Payload())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := append([]byte(nil), valid...)
			test.mutate(frame)
			if handled, err := a.ingressLocked(frame); err != nil || !handled {
				t.Fatalf("malformed ingress = %v, %v", handled, err)
			}
			if exchange.Readiness() != 0 || a.byIdentity[key] != exchange || exchange.state != stateWaiting {
				t.Fatalf("malformed reply retired exchange: readiness=%v mapped=%p state=%v", exchange.Readiness(), a.byIdentity[key], exchange.state)
			}
			if usage, _ := a.quotas.Snapshot(); usage.ICMPv6Work != 1 {
				t.Fatalf("malformed reply released work quota: %+v", usage)
			}
		})
	}
	if handled, err := a.ingressLocked(valid); err != nil || !handled {
		t.Fatalf("valid ingress = %v, %v", handled, err)
	}
	if exchange.Readiness() != nscore.ReadyICMPv6Reply || a.byIdentity[key] != nil {
		t.Fatalf("valid reply completion: readiness=%v mapped=%p", exchange.Readiness(), a.byIdentity[key])
	}
	if usage, _ := a.quotas.Snapshot(); usage.ICMPv6Work != 0 {
		t.Fatalf("valid reply retained work quota: %+v", usage)
	}
}

func FuzzICMPv6OwnedEchoReplyLifecycle(f *testing.F) {
	f.Add([]byte("fuzz"), []byte("fuzz"))
	f.Add([]byte("expected"), []byte("mismatch"))
	f.Add([]byte{0}, []byte{})
	f.Fuzz(func(t *testing.T, expected, replyPayload []byte) {
		if len(expected) == 0 || len(expected) > 64 || len(replyPayload) > 64 {
			return
		}
		coreA, a := newTestAdapter(t, 71, "2001:db8::71")
		coreB, b := newTestAdapter(t, 72, "2001:db8::72")
		resource, progress, err := a.TryEcho(icmpns.EchoRequest{Destination: b.address, Payload: expected})
		if err != nil || progress != nscore.ProgressInProgress {
			t.Fatalf("TryEcho = %T, %v, %v", resource, progress, err)
		}
		exchange := resource.(*echo)
		key := identityKey(exchange.identifier, exchange.sequence)
		storage := make([]byte, coreA.Link().MaxFrameBytes())
		coreA.Lock()
		written, worked, err := a.egressLocked(storage)
		coreA.Unlock()
		if err != nil || !worked || written == 0 || exchange.state != stateWaiting {
			t.Fatalf("echo request egress = %d, %v, %v state=%v", written, worked, err, exchange.state)
		}
		coreB.Lock()
		written, err = b.writeEchoLocked(storage, a.address, a.hardwareAddress, lnetoicmp.TypeEchoReply, exchange.identifier, exchange.sequence, replyPayload, 64)
		coreB.Unlock()
		if err != nil || written == 0 {
			t.Fatalf("echo reply build = %d, %v", written, err)
		}
		coreA.Lock()
		handled, ingressErr := a.ingressLocked(storage[:written])
		mapped := a.byIdentity[key]
		coreA.Unlock()
		if ingressErr != nil || !handled {
			t.Fatalf("owned reply ingress = handled:%v err:%v", handled, ingressErr)
		}
		wantUsage := quota.Usage{Resources: 1, ICMPv6Resources: 1, QueuedBytes: uint64(len(expected))}
		if bytes.Equal(expected, replyPayload) {
			if exchange.state != stateDone || exchange.failure != nil || mapped != nil || exchange.Readiness() != nscore.ReadyICMPv6Reply {
				t.Fatalf("matching reply state = %v failure=%v mapped=%p readiness=%v", exchange.state, exchange.failure, mapped, exchange.Readiness())
			}
			dst := bytes.Repeat([]byte{0xa5}, len(expected)+1)
			result, next, err := exchange.TryResult(dst)
			if err != nil || next != icmpns.NextReady || result.Source != b.address || result.ScopeID != 0 || result.Identifier != exchange.identifier || result.Sequence != exchange.sequence || result.Copied != len(expected) || result.PayloadBytes != len(expected) || !bytes.Equal(dst[:len(expected)], expected) || dst[len(expected)] != 0xa5 {
				t.Fatalf("matching reply result = %+v, %v, %v payload=%x", result, next, err, dst)
			}
		} else {
			wantUsage.ICMPv6Work = 1
			if exchange.state != stateWaiting || exchange.failure != nil || mapped != exchange || exchange.Readiness() != 0 {
				t.Fatalf("mismatching reply state = %v failure=%v mapped=%p readiness=%v", exchange.state, exchange.failure, mapped, exchange.Readiness())
			}
			if result, next, err := exchange.TryResult(nil); err != nil || next != icmpns.NextWouldBlock || result != (icmpns.EchoResult{}) {
				t.Fatalf("mismatching reply result = %+v, %v, %v", result, next, err)
			}
		}
		if usage, closed := a.quotas.Snapshot(); closed || usage != wantUsage {
			t.Fatalf("reply quota = %+v, closed=%v; want %+v", usage, closed, wantUsage)
		}
		if err := coreA.Close(); err != nil {
			t.Fatal(err)
		}
		if err := coreB.Close(); err != nil {
			t.Fatal(err)
		}
		if usage, _ := a.quotas.Snapshot(); usage != (quota.Usage{}) {
			t.Fatalf("namespace close quota = %+v", usage)
		}
		if exchange.owner != nil || exchange.payload != nil || len(a.echoes) != 0 || a.byIdentity != nil {
			t.Fatalf("namespace close retained fuzzed echo state: exchange=%+v echoes=%d identities=%v", exchange, len(a.echoes), a.byIdentity)
		}
	})
}

func TestQueuedEchoResponsesPreserveQuotaAcrossSaturationRetryDrainAndClose(t *testing.T) {
	coreA, a := newTestAdapter(t, 25, "2001:db8::25")
	coreB, b := newTestAdapter(t, 26, "2001:db8::26")
	defer coreA.Close()
	if err := a.SeedNeighbor(icmpns.Neighbor{Address: b.address, MAC: b.hardwareAddress}); err != nil {
		t.Fatal(err)
	}
	resource, _, err := a.TryEcho(icmpns.EchoRequest{Destination: b.address, Payload: []byte("queued")})
	if err != nil {
		t.Fatal(err)
	}
	defer resource.Close()
	var storage [1514]byte
	n, worked, err := a.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo request = %d, %v, %v", n, worked, err)
	}
	request := append([]byte(nil), storage[:n]...)
	for i := 0; i < int(b.config.MaxQueuedResponses)+1; i++ {
		frame := append([]byte(nil), request...)
		ethernetFrame, _ := ethernet.NewFrame(frame)
		ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
		icmpFrame, _ := lnetoicmp.NewFrame(ipFrame.Payload())
		echoFrame := lnetoicmp.FrameEcho{Frame: icmpFrame}
		echoFrame.SetSequenceNumber(uint16(i + 1))
		setChecksum(ipFrame, icmpFrame, ipFrame.Payload())
		if handled, err := b.ingressLocked(frame); err != nil || !handled {
			t.Fatalf("echo request %d ingress = %v, %v", i, handled, err)
		}
	}
	queued := int(b.config.MaxQueuedResponses)
	if len(b.responses) != queued {
		t.Fatalf("queued responses = %d, want %d", len(b.responses), queued)
	}
	wantUsage := quota.Usage{Resources: uint64(queued), ICMPv6Resources: uint64(queued), QueuedBytes: uint64(queued * len("queued"))}
	if usage, _ := b.quotas.Snapshot(); usage != wantUsage {
		t.Fatalf("saturated response quota = %+v, want %+v", usage, wantUsage)
	}

	first := b.responses[0]
	frameBytes := 14 + 40 + icmpHeader + len(first.payload)
	short := bytes.Repeat([]byte{0xa5}, frameBytes-1)
	if n, worked, err := b.egressLocked(short); !errors.Is(err, lneto.ErrShortBuffer) || worked || n != 0 {
		t.Fatalf("short response egress = %d, %v, %v", n, worked, err)
	}
	if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) || len(b.responses) != queued || b.responses[0] != first {
		t.Fatalf("short response egress mutated output or queue: responses=%d first=%p", len(b.responses), b.responses[0])
	}
	if usage, _ := b.quotas.Snapshot(); usage != wantUsage {
		t.Fatalf("short response egress changed quota = %+v, want %+v", usage, wantUsage)
	}

	n, worked, err = b.egressLocked(storage[:])
	if err != nil || !worked || n != frameBytes {
		t.Fatalf("response retry = %d, %v, %v", n, worked, err)
	}
	wantUsage.Resources--
	wantUsage.ICMPv6Resources--
	wantUsage.QueuedBytes -= uint64(len("queued"))
	if len(b.responses) != queued-1 || first.payload != nil || first.retained.ResetReleased() {
		t.Fatalf("drained response retained state: queued=%d response=%+v", len(b.responses), first)
	}
	if usage, _ := b.quotas.Snapshot(); usage != wantUsage {
		t.Fatalf("drained response quota = %+v, want %+v", usage, wantUsage)
	}

	if err := coreB.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.responses) != 0 || b.responses != nil {
		t.Fatalf("closed response queue = %#v", b.responses)
	}
	if usage, _ := b.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed response quota = %+v", usage)
	}
}

func TestQueuedNeighborAdvertisementsPreservePassiveStateQuotaRetryRemoveAndClose(t *testing.T) {
	coreA, a := newTestAdapter(t, 27, "2001:db8::27")
	coreB, b := newTestAdapter(t, 28, "2001:db8::28")
	defer coreA.Close()
	request := icmpns.NeighborRequest{Address: b.address}
	resource, _, err := a.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resource.Close()
	var storage [1514]byte
	n, worked, err := a.egressLocked(storage[:])
	if err != nil || !worked || n != 14+40+ndpSize {
		t.Fatalf("neighbor solicitation = %d, %v, %v", n, worked, err)
	}
	solicitation := append([]byte(nil), storage[:n]...)
	for i := 0; i < int(b.config.MaxQueuedResponses)+1; i++ {
		if handled, err := b.ingressLocked(solicitation); err != nil || !handled {
			t.Fatalf("neighbor solicitation %d ingress = %v, %v", i, handled, err)
		}
	}
	queued := int(b.config.MaxQueuedResponses)
	passive, ok := b.neighbors[a.address]
	if !ok || !passive.complete || passive.mac != a.hardwareAddress || len(b.responses) != queued {
		t.Fatalf("saturated advertisement state: passive=%+v queued=%d", passive, len(b.responses))
	}
	wantUsage := quota.Usage{Resources: uint64(queued + 1), ICMPv6Resources: uint64(queued + 1)}
	if usage, _ := b.quotas.Snapshot(); usage != wantUsage {
		t.Fatalf("saturated advertisement quota = %+v, want %+v", usage, wantUsage)
	}

	first := b.responses[0]
	short := bytes.Repeat([]byte{0xa5}, 14+40+ndpSize-1)
	if n, worked, err := b.egressLocked(short); !errors.Is(err, lneto.ErrShortBuffer) || worked || n != 0 {
		t.Fatalf("short advertisement egress = %d, %v, %v", n, worked, err)
	}
	if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) || len(b.responses) != queued || b.responses[0] != first {
		t.Fatalf("short advertisement egress mutated output or queue: queued=%d first=%p", len(b.responses), b.responses[0])
	}
	if usage, _ := b.quotas.Snapshot(); usage != wantUsage {
		t.Fatalf("short advertisement egress changed quota = %+v, want %+v", usage, wantUsage)
	}

	n, worked, err = b.egressLocked(storage[:])
	if err != nil || !worked || n != 14+40+ndpSize {
		t.Fatalf("advertisement retry = %d, %v, %v", n, worked, err)
	}
	wantUsage.Resources--
	wantUsage.ICMPv6Resources--
	if len(b.responses) != queued-1 || first.retained.ResetReleased() {
		t.Fatalf("drained advertisement retained state: queued=%d response=%+v", len(b.responses), first)
	}
	if usage, _ := b.quotas.Snapshot(); usage != wantUsage {
		t.Fatalf("drained advertisement quota = %+v, want %+v", usage, wantUsage)
	}

	if err := b.RemoveNeighbor(icmpns.NeighborRequest{Address: a.address}); err != nil {
		t.Fatal(err)
	}
	wantUsage.Resources--
	wantUsage.ICMPv6Resources--
	if b.neighbors[a.address] != nil || len(b.responses) != queued-1 {
		t.Fatalf("passive remove disturbed queued responses: neighbor=%+v queued=%d", b.neighbors[a.address], len(b.responses))
	}
	if usage, _ := b.quotas.Snapshot(); usage != wantUsage {
		t.Fatalf("passive remove quota = %+v, want %+v", usage, wantUsage)
	}

	if err := coreB.Close(); err != nil {
		t.Fatal(err)
	}
	if len(b.responses) != 0 || b.responses != nil || len(b.neighbors) != 0 || b.neighbors != nil {
		t.Fatalf("closed NDP state: responses=%#v neighbors=%#v", b.responses, b.neighbors)
	}
	if usage, _ := b.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed NDP quota = %+v", usage)
	}
}

func TestNeighborSolicitationRetainsPassiveLearningWhenResponseQuotaIsFull(t *testing.T) {
	coreA, a := newTestAdapter(t, 29, "2001:db8::29")
	coreB, b := newTestAdapter(t, 30, "2001:db8::30")
	defer coreA.Close()
	defer coreB.Close()
	resource, _, err := a.TryResolve(icmpns.NeighborRequest{Address: b.address})
	if err != nil {
		t.Fatal(err)
	}
	defer resource.Close()
	var storage [1514]byte
	n, worked, err := a.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("neighbor solicitation = %d, %v, %v", n, worked, err)
	}
	var blocker quota.Charge
	if err := b.quotas.AcquireResource(&blocker, quota.ResourceICMPv6, 127); err != nil {
		t.Fatal(err)
	}
	if handled, err := b.ingressLocked(storage[:n]); err != nil || !handled {
		t.Fatalf("quota-saturated solicitation ingress = %v, %v", handled, err)
	}
	passive := b.neighbors[a.address]
	if passive == nil || !passive.complete || passive.mac != a.hardwareAddress || len(b.responses) != 0 {
		t.Fatalf("quota-saturated solicitation state: passive=%+v responses=%d", passive, len(b.responses))
	}
	if usage, _ := b.quotas.Snapshot(); usage != (quota.Usage{Resources: 128, ICMPv6Resources: 128}) {
		t.Fatalf("quota-saturated passive learning = %+v", usage)
	}
	if !blocker.Release() {
		t.Fatal("blocker release failed")
	}
	blocker.ResetReleased()
	if handled, err := b.ingressLocked(storage[:n]); err != nil || !handled {
		t.Fatalf("solicitation retry ingress = %v, %v", handled, err)
	}
	if b.neighbors[a.address] != passive || len(b.responses) != 1 {
		t.Fatalf("solicitation retry duplicated passive state: passive=%p current=%p responses=%d", passive, b.neighbors[a.address], len(b.responses))
	}
	if usage, _ := b.quotas.Snapshot(); usage != (quota.Usage{Resources: 2, ICMPv6Resources: 2}) {
		t.Fatalf("solicitation retry quota = %+v", usage)
	}
}

func TestDuplicateAddressDetectionSolicitationProducesUnsolicitedAdvertisement(t *testing.T) {
	coreA, a := newTestAdapter(t, 34, "fe80::34")
	coreB, b := newTestAdapter(t, 35, "fe80::35")
	defer coreA.Close()
	defer coreB.Close()

	buildDAD := func(includeSourceOption bool) []byte {
		payloadBytes := 24
		if includeSourceOption {
			payloadBytes = ndpSize
		}
		frame := make([]byte, 14+40+payloadBytes)
		payload, ipFrame := a.baseFrameLocked(frame, solicitedNode(b.address), solicitedNodeMAC(b.address), payloadBytes, 255)
		*ipFrame.SourceAddr() = [16]byte{}
		icmpFrame, err := lnetoicmp.NewFrame(payload)
		if err != nil {
			t.Fatal(err)
		}
		icmpFrame.SetType(lnetoicmp.TypeNeighborSolicitation)
		icmpFrame.SetCode(0)
		copy(payload[8:24], b.address.AsSlice())
		if includeSourceOption {
			payload[24], payload[25] = 1, 1
			copy(payload[26:32], a.hardwareAddress[:])
		}
		setChecksum(ipFrame, icmpFrame, payload)
		return frame
	}

	if handled, err := b.ingressLocked(buildDAD(true)); err != nil || !handled {
		t.Fatalf("DAD solicitation with source option ingress = %v, %v", handled, err)
	}
	if len(b.responses) != 0 || b.neighbors[a.address] != nil {
		t.Fatalf("malformed DAD solicitation mutated state: responses=%d neighbor=%+v", len(b.responses), b.neighbors[a.address])
	}

	if handled, err := b.ingressLocked(buildDAD(false)); err != nil || !handled {
		t.Fatalf("DAD solicitation ingress = %v, %v", handled, err)
	}
	if len(b.responses) != 1 || b.responses[0].destination != allNodes() || b.responses[0].dstMAC != allNodesMAC() || b.responses[0].solicited || b.neighbors[a.address] != nil {
		t.Fatalf("DAD response state = responses=%+v neighbor=%+v", b.responses, b.neighbors[a.address])
	}

	var storage [1514]byte
	n, worked, err := b.egressLocked(storage[:])
	if err != nil || !worked || n != 14+40+ndpSize {
		t.Fatalf("DAD advertisement egress = %d, %v, %v", n, worked, err)
	}
	ethernetFrame, err := ethernet.NewFrame(storage[:n])
	if err != nil || *ethernetFrame.DestinationHardwareAddr() != allNodesMAC() {
		t.Fatalf("DAD advertisement ethernet = %v destination=%x", err, *ethernetFrame.DestinationHardwareAddr())
	}
	ipFrame, err := lnetoipv6.NewFrame(ethernetFrame.Payload())
	if err != nil || netip.AddrFrom16(*ipFrame.DestinationAddr()) != allNodes() || ipFrame.HopLimit() != 255 {
		t.Fatalf("DAD advertisement IPv6 = %v destination=%v hop=%d", err, netip.AddrFrom16(*ipFrame.DestinationAddr()), ipFrame.HopLimit())
	}
	icmpFrame, err := lnetoicmp.NewFrame(ipFrame.Payload())
	if err != nil || icmpFrame.Type() != lnetoicmp.TypeNeighborAdvertisement || ipFrame.Payload()[4] != 0x20 || netip.AddrFrom16(*(*[16]byte)(ipFrame.Payload()[8:24])) != b.address {
		t.Fatalf("DAD advertisement ICMPv6 = %v type=%v flags=%#x target=%v", err, icmpFrame.Type(), ipFrame.Payload()[4], netip.AddrFrom16(*(*[16]byte)(ipFrame.Payload()[8:24])))
	}
	if usage, _ := b.quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("drained DAD response quota = %+v", usage)
	}
}

func TestDuplicateAddressDetectionSurvivesIPv6ModuleComposition(t *testing.T) {
	coreA, a := newTestAdapter(t, 36, "fe80::36")
	coreB, b := newTestAdapter(t, 37, "fe80::37")
	defer coreA.Close()
	defer coreB.Close()
	if _, err := ipv6backend.New(coreB, ipv6backend.Config{Address: b.address, PrefixBits: 64, ScopeID: b.scopeID}); err != nil {
		t.Fatal(err)
	}

	frame := make([]byte, 14+40+24)
	payload, ipFrame := a.baseFrameLocked(frame, solicitedNode(b.address), solicitedNodeMAC(b.address), 24, 255)
	*ipFrame.SourceAddr() = [16]byte{}
	icmpFrame, err := lnetoicmp.NewFrame(payload)
	if err != nil {
		t.Fatal(err)
	}
	icmpFrame.SetType(lnetoicmp.TypeNeighborSolicitation)
	icmpFrame.SetCode(0)
	copy(payload[8:24], b.address.AsSlice())
	setChecksum(ipFrame, icmpFrame, payload)
	if err := coreB.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
		t.Fatal(err)
	}
	coreB.Lock()
	coreB.SetNextIngressLocked(true)
	coreB.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(coreB.Link().MaxFrameBytes()), Operations: 1}
	report, progress, err := coreB.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report != (nscore.ServiceReport{Packets: 1, Bytes: uint32(len(frame)), Operations: 1}) {
		t.Fatalf("composed DAD ingress = %+v, %v, %v", report, progress, err)
	}
	if len(b.responses) != 1 || b.responses[0].destination != allNodes() || b.responses[0].dstMAC != allNodesMAC() || b.responses[0].solicited {
		t.Fatalf("composed DAD response state = %+v", b.responses)
	}

	coreB.Lock()
	coreB.SetNextIngressLocked(false)
	coreB.Unlock()
	report, progress, err = coreB.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Bytes != 14+40+ndpSize || report.Operations != 1 {
		t.Fatalf("composed DAD advertisement = %+v, %v, %v", report, progress, err)
	}
	advertisement := make([]byte, coreB.Link().MaxFrameBytes())
	dequeued, err := coreB.Link().TryDequeue(packetlink.Egress, advertisement)
	if err != nil || !dequeued.Ready || dequeued.Truncated || dequeued.Copied != 14+40+ndpSize {
		t.Fatalf("dequeue composed DAD advertisement = %+v, %v", dequeued, err)
	}
	assertNDPFrame(t, advertisement[:dequeued.Copied], lnetoicmp.TypeNeighborAdvertisement, 255, allNodesMAC())
}

func TestStrictNDPValidationAndTimeoutCancellation(t *testing.T) {
	coreA, a := newTestAdapter(t, 3, "fe80::3")
	coreB, b := newTestAdapter(t, 4, "fe80::4")
	defer coreA.Close()
	defer coreB.Close()
	request := icmpns.NeighborRequest{Address: b.address, ScopeID: a.scopeID}
	resource, _, err := a.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	resolved := resource.(*resolution)
	var frame [1514]byte
	n, _, err := a.egressLocked(frame[:])
	if err != nil {
		t.Fatal(err)
	}
	ipFrame, _ := lnetoipv6.NewFrame(frame[14:n])
	ipFrame.SetHopLimit(64)
	if handled, err := b.ingressLocked(frame[:n]); err != nil || !handled || len(b.responses) != 0 {
		t.Fatalf("bad hop limit accepted: handled=%v err=%v responses=%d", handled, err, len(b.responses))
	}
	if err := resolved.Cancel(); err != nil {
		t.Fatal(err)
	}
	if resolved.Readiness() != nscore.ReadyError {
		t.Fatalf("canceled readiness = %v", resolved.Readiness())
	}
	if _, _, err := resolved.TryResult(); err == nil {
		t.Fatal("canceled resolution returned no error")
	}
	if _, ok, err := a.LookupNeighbor(request); err != nil || ok {
		t.Fatalf("canceled cache lookup = %v %v", ok, err)
	}

	resource, _, err = a.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	resolved = resource.(*resolution)
	for i := 0; i < int(a.config.MaxAttempts)*int(a.config.RetryServiceAttempts)+int(a.config.MaxAttempts)+2; i++ {
		_, _, _ = a.egressLocked(frame[:])
	}
	if _, _, err := resolved.TryResult(); err == nil || !errors.Is(err, resolved.failure) {
		t.Fatalf("timeout result = %v", err)
	}
}

func TestICMPv6OwnershipUsesOnlyDeclaredPayloadBytes(t *testing.T) {
	core, adapter := newTestAdapter(t, 38, "2001:db8::38")
	defer core.Close()

	storage := make([]byte, core.Link().MaxFrameBytes())
	core.Lock()
	n, err := adapter.writeEchoLocked(storage, adapter.address, adapter.hardwareAddress, lnetoicmp.TypeEchoRequest, 7, 9, []byte("x"), 64)
	core.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	valid := append([]byte(nil), storage[:n]...)
	foreign := netip.MustParseAddr("2001:db8::99").As16()

	for declared := 0; declared <= icmpHeader; declared++ {
		for _, test := range []struct {
			name        string
			typ         lnetoicmp.Type
			local       bool
			wantHandled bool
		}{
			{name: "owned local", typ: lnetoicmp.TypeEchoRequest, local: true, wantHandled: declared != 0},
			{name: "unsupported local", typ: lnetoicmp.Type(1), local: true},
			{name: "owned foreign", typ: lnetoicmp.TypeEchoRequest},
		} {
			t.Run(test.name+"/declared="+strconv.Itoa(declared), func(t *testing.T) {
				frame := append([]byte(nil), valid...)
				ethernetFrame, err := ethernet.NewFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				ipFrame, err := lnetoipv6.NewFrame(ethernetFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				ipFrame.SetPayloadLength(uint16(declared))
				ipFrame.RawData()[40] = byte(test.typ)
				if !test.local {
					*ipFrame.DestinationAddr() = foreign
				}
				handled, err := adapter.ingressLocked(frame)
				if err != nil || handled != test.wantHandled {
					t.Fatalf("ingress = %v, %v; want handled %v", handled, err, test.wantHandled)
				}
				if len(adapter.responses) != 0 || len(adapter.neighbors) != 0 {
					t.Fatalf("short or unowned ingress mutated state: responses=%d neighbors=%d", len(adapter.responses), len(adapter.neighbors))
				}
			})
		}
	}
}

func TestUnsupportedLocalICMPv6FallsThroughBeforeStrictOwnedValidation(t *testing.T) {
	core, adapter := newTestAdapter(t, 10, "2001:db8::10")
	defer core.Close()
	observed := 0
	if err := core.Install(lnetocore.Participant{
		IngressOrder: serviceOrder + 1,
		Ingress: func([]byte) (bool, error) {
			observed++
			return true, nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	storage := make([]byte, core.Link().MaxFrameBytes())
	core.Lock()
	n, err := adapter.writeEchoLocked(storage, adapter.address, adapter.hardwareAddress, lnetoicmp.TypeEchoRequest, 7, 9, []byte("x"), 64)
	core.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	valid := append([]byte(nil), storage[:n]...)
	unsupported := append([]byte(nil), valid...)
	ethernetFrame, _ := ethernet.NewFrame(unsupported)
	ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
	icmpFrame, _ := lnetoicmp.NewFrame(ipFrame.Payload())
	icmpFrame.SetType(lnetoicmp.Type(1))
	setChecksum(ipFrame, icmpFrame, ipFrame.Payload())
	badChecksumUnsupported := append([]byte(nil), unsupported...)
	badChecksumUnsupported[len(badChecksumUnsupported)-1] ^= 0xff
	shortOwned := append([]byte(nil), valid...)
	shortEthernet, _ := ethernet.NewFrame(shortOwned)
	shortIP, _ := lnetoipv6.NewFrame(shortEthernet.Payload())
	shortIP.SetPayloadLength(1)
	localOverrunOwned := append([]byte(nil), valid...)
	localOverrunEthernet, _ := ethernet.NewFrame(localOverrunOwned)
	localOverrunIP, _ := lnetoipv6.NewFrame(localOverrunEthernet.Payload())
	localOverrunIP.SetPayloadLength(512)
	unsupportedOverrun := append([]byte(nil), unsupported...)
	unsupportedOverrunEthernet, _ := ethernet.NewFrame(unsupportedOverrun)
	unsupportedOverrunIP, _ := lnetoipv6.NewFrame(unsupportedOverrunEthernet.Payload())
	unsupportedOverrunIP.SetPayloadLength(512)
	foreignOverrunOwned := append([]byte(nil), localOverrunOwned...)
	foreignOverrunEthernet, _ := ethernet.NewFrame(foreignOverrunOwned)
	foreignOverrunIP, _ := lnetoipv6.NewFrame(foreignOverrunEthernet.Payload())
	*foreignOverrunIP.DestinationAddr() = netip.MustParseAddr("2001:db8::99").As16()

	service := func(frame []byte) {
		t.Helper()
		core.Lock()
		core.SetNextIngressLocked(true)
		core.Unlock()
		if err := core.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
			t.Fatal(err)
		}
		report, progress, err := core.TryService(nscore.ServiceBudget{Packets: 1, Bytes: uint32(len(frame)), Operations: 1})
		if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 || report.Bytes != uint32(len(frame)) {
			t.Fatalf("service = %+v, %v, %v", report, progress, err)
		}
	}

	service(unsupported)
	service(badChecksumUnsupported)
	if observed != 2 || len(adapter.responses) != 0 {
		t.Fatalf("unsupported local traffic = observed %d responses %d", observed, len(adapter.responses))
	}
	service(shortOwned)
	service(localOverrunOwned)
	if observed != 2 || len(adapter.responses) != 0 {
		t.Fatalf("malformed owned traffic = observed %d responses %d", observed, len(adapter.responses))
	}
	service(unsupportedOverrun)
	service(foreignOverrunOwned)
	if observed != 4 || len(adapter.responses) != 0 {
		t.Fatalf("uncorrelated overrun traffic = observed %d responses %d", observed, len(adapter.responses))
	}
	service(valid)
	if observed != 4 || len(adapter.responses) != 1 {
		t.Fatalf("valid owned traffic = observed %d responses %d", observed, len(adapter.responses))
	}
}

func TestForeignICMPv6DestinationsRemainUnhandled(t *testing.T) {
	coreA, a := newTestAdapter(t, 11, "2001:db8::11")
	coreB, b := newTestAdapter(t, 12, "2001:db8::12")
	defer coreA.Close()
	defer coreB.Close()
	if err := b.SeedNeighbor(icmpns.Neighbor{Address: a.address, MAC: a.hardwareAddress}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.TryEcho(icmpns.EchoRequest{Destination: a.address, Payload: []byte("foreign")}); err != nil {
		t.Fatal(err)
	}
	var storage [1514]byte
	n, worked, err := b.egressLocked(storage[:])
	if err != nil || !worked || n == 0 {
		t.Fatalf("echo request = %d, %v, %v", n, worked, err)
	}
	request := append([]byte(nil), storage[:n]...)

	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "foreign ethernet destination", mutate: func(frame []byte) {
			ethernetFrame, _ := ethernet.NewFrame(frame)
			*ethernetFrame.DestinationHardwareAddr() = [6]byte{0x02, 0, 0, 0, 0, 99}
		}},
		{name: "foreign IPv6 destination", mutate: func(frame []byte) {
			ethernetFrame, _ := ethernet.NewFrame(frame)
			ipFrame, _ := lnetoipv6.NewFrame(ethernetFrame.Payload())
			*ipFrame.DestinationAddr() = netip.MustParseAddr("2001:db8::99").As16()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := append([]byte(nil), request...)
			test.mutate(frame)
			handled, err := a.ingressLocked(frame)
			if err != nil || handled {
				t.Fatalf("foreign frame = handled:%v err:%v", handled, err)
			}
			if len(a.responses) != 0 {
				t.Fatalf("foreign frame queued responses: %d", len(a.responses))
			}
		})
	}
}

func TestTerminalEchoAndResolutionCleanupIsolateFreshResources(t *testing.T) {
	core, adapter := newTestAdapter(t, 13, "2001:db8::13")
	account := adapter.quotas
	destination := netip.MustParseAddr("2001:db8::14")
	resource, _, err := adapter.TryEcho(icmpns.EchoRequest{Destination: destination, Payload: []byte("retained")})
	if err != nil {
		t.Fatal(err)
	}
	staleEcho := resource.(*echo)
	staleKey := identityKey(staleEcho.identifier, staleEcho.sequence)
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, ICMPv6Resources: 1, QueuedBytes: 8, ICMPv6Work: 1}) {
		t.Fatalf("active echo quota = %+v", usage)
	}
	if err := staleEcho.Cancel(); err != nil {
		t.Fatal(err)
	}
	if adapter.byIdentity[staleKey] != nil || staleEcho.Readiness() != nscore.ReadyError {
		t.Fatalf("canceled echo transport = mapped:%p readiness:%v", adapter.byIdentity[staleKey], staleEcho.Readiness())
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, ICMPv6Resources: 1, QueuedBytes: 8}) {
		t.Fatalf("terminal echo quota = %+v", usage)
	}
	if err := staleEcho.Close(); err != nil {
		t.Fatal(err)
	}
	if staleEcho.owner != nil || staleEcho.payload != nil || staleEcho.work.ResetReleased() || staleEcho.retained.ResetReleased() {
		t.Fatalf("closed echo retained state: %+v", staleEcho)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed echo quota = %+v", usage)
	}

	resource, _, err = adapter.TryEcho(icmpns.EchoRequest{Destination: destination, Payload: []byte("fresh")})
	if err != nil {
		t.Fatal(err)
	}
	freshEcho := resource.(*echo)
	if freshEcho == staleEcho {
		t.Fatal("fresh echo reused stale wrapper")
	}
	if err := staleEcho.Close(); err != nil {
		t.Fatal(err)
	}
	if len(adapter.echoes) != 1 || adapter.echoes[0] != freshEcho {
		t.Fatalf("stale echo close affected fresh resource: %+v", adapter.echoes)
	}
	if err := freshEcho.Close(); err != nil {
		t.Fatal(err)
	}

	request := icmpns.NeighborRequest{Address: destination}
	resource, _, err = adapter.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	staleResolution := resource.(*resolution)
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 2, ICMPv6Resources: 2, ICMPv6Work: 1}) {
		t.Fatalf("active resolution quota = %+v", usage)
	}
	if err := staleResolution.Cancel(); err != nil {
		t.Fatal(err)
	}
	if adapter.byTarget[destination] != nil || adapter.neighbors[destination] != nil || staleResolution.entry != nil || staleResolution.Readiness() != nscore.ReadyError {
		t.Fatalf("canceled resolution retained transport/cache: target=%p neighbor=%p entry=%p readiness=%v", adapter.byTarget[destination], adapter.neighbors[destination], staleResolution.entry, staleResolution.Readiness())
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{Resources: 1, ICMPv6Resources: 1}) {
		t.Fatalf("terminal resolution quota = %+v", usage)
	}
	if err := staleResolution.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed resolution quota = %+v", usage)
	}

	resource, _, err = adapter.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	freshResolution := resource.(*resolution)
	if freshResolution == staleResolution {
		t.Fatal("fresh resolution reused stale wrapper")
	}
	if err := staleResolution.Close(); err != nil {
		t.Fatal(err)
	}
	if len(adapter.resolutions) != 1 || adapter.resolutions[0] != freshResolution || adapter.byTarget[destination] != freshResolution {
		t.Fatalf("stale resolution close affected fresh resource: resolutions=%+v target=%p", adapter.resolutions, adapter.byTarget[destination])
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if freshResolution.owner != nil || freshResolution.entry != nil || freshResolution.state != stateClosed || freshResolution.Readiness() != nscore.ReadyClosed {
		t.Fatalf("namespace close retained fresh resolution: %+v", freshResolution)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close quota = %+v", usage)
	}
}

func TestCompletedResolutionRetainsResultAcrossCacheMutation(t *testing.T) {
	for _, alreadyCached := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "cached"}[alreadyCached], func(t *testing.T) {
			core, adapter := newTestAdapter(t, 33, "2001:db8::33")
			defer core.Close()
			target := netip.MustParseAddr("2001:db8::44")
			request := icmpns.NeighborRequest{Address: target}
			first := icmpns.Neighbor{Address: target, MAC: [6]byte{0x02, 0, 0, 0, 0, 44}}
			second := icmpns.Neighbor{Address: target, MAC: [6]byte{0x02, 0, 0, 0, 0, 45}}
			if alreadyCached {
				if err := adapter.SeedNeighbor(first); err != nil {
					t.Fatal(err)
				}
			}
			resource, progress, err := adapter.TryResolve(request)
			if err != nil {
				t.Fatal(err)
			}
			resolved := resource.(*resolution)
			if alreadyCached && progress != nscore.ProgressDone {
				t.Fatalf("cached progress = %v", progress)
			}
			if !alreadyCached {
				if progress != nscore.ProgressInProgress {
					t.Fatalf("pending progress = %v", progress)
				}
				if err := adapter.SeedNeighbor(first); err != nil {
					t.Fatal(err)
				}
			}
			if resolved.Readiness() != nscore.ReadyICMPv6Neighbor {
				t.Fatalf("completed readiness = %v", resolved.Readiness())
			}
			if err := adapter.RemoveNeighbor(request); err != nil {
				t.Fatal(err)
			}
			if err := adapter.SeedNeighbor(second); err != nil {
				t.Fatal(err)
			}
			neighbor, next, err := resolved.TryResult()
			if err != nil || next != icmpns.NextReady || neighbor != first {
				t.Fatalf("retained result = %+v, %v, %v; want %+v", neighbor, next, err, first)
			}
			if err := resolved.Close(); err != nil {
				t.Fatal(err)
			}
			if err := adapter.RemoveNeighbor(request); err != nil {
				t.Fatal(err)
			}
			if usage, _ := adapter.quotas.Snapshot(); usage != (quota.Usage{}) {
				t.Fatalf("cleanup quota = %+v", usage)
			}
		})
	}
}

func TestSeedLookupRemoveAndQuotaCleanup(t *testing.T) {
	core, adapter := newTestAdapter(t, 5, "2001:db8::5")
	if operations := adapter.Operations(); operations != icmpns.SupportedOperations {
		t.Fatalf("operational operations = %v", operations)
	}
	neighbor := icmpns.Neighbor{Address: netip.MustParseAddr("2001:db8::55"), MAC: [6]byte{0x02, 5, 5, 5, 5, 5}}
	if err := adapter.SeedNeighbor(neighbor); err != nil {
		t.Fatal(err)
	}
	got, ok, err := adapter.LookupNeighbor(icmpns.NeighborRequest{Address: neighbor.Address})
	if err != nil || !ok || got != neighbor {
		t.Fatalf("lookup = %+v %v %v", got, ok, err)
	}
	if err := adapter.RemoveNeighbor(icmpns.NeighborRequest{Address: neighbor.Address}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := adapter.LookupNeighbor(icmpns.NeighborRequest{Address: neighbor.Address}); err != nil || ok {
		t.Fatalf("post-remove lookup = %v %v", ok, err)
	}
	account := adapter.quotas
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{}) {
		t.Fatalf("close usage = %+v closed=%v", usage, closed)
	}
	if operations := adapter.Operations(); operations != 0 {
		t.Fatalf("closed operations = %v", operations)
	}
}

func TestConfigRejectsUnrepresentableEchoPayload(t *testing.T) {
	config := testConfig()
	config.MaxPayloadBytes = icmpns.MaxEchoPayloadBytes + 1
	if ValidConfig(config, config.MaxPayloadBytes+40+icmpHeader, nil, nil, false) {
		t.Fatal("unrepresentable ICMPv6 payload config accepted")
	}
}

func TestZeroConfigRetainsTruthfulServiceSemantics(t *testing.T) {
	core, _ := newTestAdapter(t, 8, "2001:db8::8")
	adapter, err := New(core, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if operations := adapter.Operations(); operations != 0 {
		t.Fatalf("disabled operations = %v", operations)
	}
	if _, _, err := adapter.TryEcho(icmpns.EchoRequest{}); nscoreFailure(err) != nscore.FailureNotSupported {
		t.Fatalf("disabled echo = %v", err)
	}
	if _, _, err := adapter.TryResolve(icmpns.NeighborRequest{}); nscoreFailure(err) != nscore.FailureNotSupported {
		t.Fatalf("disabled resolve = %v", err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapter.TryEcho(icmpns.EchoRequest{}); nscoreFailure(err) != nscore.FailureClosed {
		t.Fatalf("closed disabled echo = %v", err)
	}
}

func TestUnconfiguredIPv6IsTruthfullyUnsupported(t *testing.T) {
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportICMPv6}, Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound}}}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.DefaultLimits())
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "icmp6-disabled", RandSeed: 9, HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 9}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 10},
		IPv4Address: netip.MustParseAddr("192.0.2.9"), MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 2, EgressFrames: 2}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	adapter, err := New(core, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if operations := adapter.Operations(); operations != 0 {
		t.Fatalf("unconfigured operations = %v", operations)
	}
	if _, _, err := adapter.TryEcho(icmpns.EchoRequest{Destination: netip.MustParseAddr("2001:db8::1"), Payload: []byte{1}}); err == nil {
		t.Fatal("disabled echo unexpectedly succeeded")
	} else if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureNotSupported {
		t.Fatalf("disabled echo = %v", err)
	}
	if len(adapter.echoes) != 0 || adapter.byIdentity != nil || adapter.resolutions != nil || adapter.byTarget != nil || adapter.neighbors != nil || adapter.responses != nil {
		t.Fatal("unconfigured adapter allocated operational backing")
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if adapter.closed {
		t.Fatal("unconfigured adapter unexpectedly installed a close participant")
	}
	if _, _, err := adapter.TryEcho(icmpns.EchoRequest{}); nscoreFailure(err) != nscore.FailureClosed {
		t.Fatalf("closed unconfigured echo = %v", err)
	}
}

func nscoreFailure(err error) nscore.Failure {
	failure, _ := nscore.FailureOf(err)
	return failure
}

func newTestAdapter(t testing.TB, id byte, addressText string) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	return newTestAdapterWithGateway(t, id, addressText, [6]byte{0x02, 0, 0, 0, 0, id ^ 1})
}

func newTestAdapterWithGateway(t testing.TB, id byte, addressText string, gateway [6]byte) (*lnetocore.Namespace, *Adapter) {
	t.Helper()
	address := netip.MustParseAddr(addressText)
	scopeID := uint32(0)
	if address.IsLinkLocalUnicast() {
		scopeID = 7
	}
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportICMPv6}, Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.MustParsePrefix("::/0")}},
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportIPv6}, Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(address, 128)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 128, ICMPv6Resources: 128, ICMPv6Work: 32, QueuedBytes: 1 << 16, IPv6Resources: 1, ServiceUnits: 128})
	core, err := lnetocore.New(lnetocore.Config{
		Hostname: "icmp6", RandSeed: int64(id) + 1,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id}, GatewayHardwareAddress: gateway,
		IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), IPv6Address: address, IPv6PrefixBits: 64, IPv6ScopeID: scopeID,
		MTU: 1500, Link: packetlink.Config{MaxFrameBytes: 1514, IngressFrames: 4, EgressFrames: 4}, Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(core, testConfig())
	if err != nil {
		core.Close()
		t.Fatal(err)
	}
	return core, adapter
}

func testConfig() Config {
	return Config{MaxEchoes: 4, MaxPayloadBytes: 256, MaxNeighbors: 8, MaxResolutions: 4, MaxQueuedResponses: 4, MaxAttempts: 2, RetryServiceAttempts: 2}
}

func assertNDPFrame(t testing.TB, frame []byte, typ lnetoicmp.Type, hop uint8, destinationMAC [6]byte) {
	t.Helper()
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil || *ethernetFrame.DestinationHardwareAddr() != destinationMAC {
		t.Fatalf("ethernet frame = %v dst=%x", err, *ethernetFrame.DestinationHardwareAddr())
	}
	ipFrame, err := lnetoipv6.NewFrame(ethernetFrame.Payload())
	if err != nil || ipFrame.HopLimit() != hop {
		t.Fatalf("IPv6 frame = %v hop=%d", err, ipFrame.HopLimit())
	}
	icmpFrame, err := lnetoicmp.NewFrame(ipFrame.Payload())
	if err != nil || icmpFrame.Type() != typ || icmpFrame.Code() != 0 {
		t.Fatalf("ICMPv6 frame = %v type=%v code=%d", err, icmpFrame.Type(), icmpFrame.Code())
	}
}
