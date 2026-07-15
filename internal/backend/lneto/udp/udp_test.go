package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	nscore "github.com/wago-org/net/internal/namespace/core"
	udpns "github.com/wago-org/net/internal/namespace/udp"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestAdapterRequiresUnicastGatewayHardwareAddressWhenEnabled(t *testing.T) {
	config := Config{MaxSockets: 1, ReceiveBytes: 32, TransmitBytes: 32, ReceiveDatagrams: 1, TransmitDatagrams: 1, MaxPayloadBytes: 32}
	for name, gateway := range map[string][6]byte{
		"zero":      {},
		"multicast": {0x01, 0, 0, 0, 0, 1},
		"broadcast": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			common := newGatewayConfigTestCore(t, gateway)
			defer common.Close()
			if _, err := New(common, config); err == nil {
				t.Fatalf("enabled UDP accepted gateway hardware address %v", gateway)
			}
			if _, err := New(common, Config{}); err != nil {
				t.Fatalf("disabled UDP rejected irrelevant gateway hardware address %v: %v", gateway, err)
			}
		})
	}
}

func TestAdapterExchangeTruncationPortLeaseAndClose(t *testing.T) {
	aCore, aAdapter, aAccount := newTestAdapter(t, 31)
	bCore, bAdapter, _ := newTestAdapter(t, 32)
	aLocal := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.31"), Port: 4031}
	bLocal := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.32"), Port: 4032}
	a := bindTestSocket(t, aAdapter, aLocal).(*udpSocket)
	b := bindTestSocket(t, bAdapter, bLocal).(*udpSocket)
	if _, _, err := aAdapter.TryBind(aLocal); err == nil {
		t.Fatal("duplicate bind succeeded")
	} else if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureAddressInUse {
		t.Fatalf("duplicate bind error = %v", err)
	}
	if progress, err := a.TrySend([]byte("abcdef"), bLocal); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("send = %v, %v", progress, err)
	}

	aCore.Lock()
	aCore.SetNextIngressLocked(false)
	aCore.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(aCore.Link().MaxFrameBytes()), Operations: 1}
	report, progress, err := aCore.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("egress = %+v, %v, %v", report, progress, err)
	}
	frame := make([]byte, aCore.Link().MaxFrameBytes())
	result, err := aCore.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready {
		t.Fatalf("dequeue = %+v, %v", result, err)
	}
	ingressFrame, err := ethernet.NewFrame(frame[:result.FrameBytes])
	if err != nil {
		t.Fatal(err)
	}
	*ingressFrame.DestinationHardwareAddr() = bAdapter.hardwareAddress
	if err := bCore.Link().TryEnqueue(packetlink.Ingress, frame[:result.FrameBytes]); err != nil {
		t.Fatal(err)
	}
	bCore.Lock()
	bCore.SetNextIngressLocked(true)
	bCore.Unlock()
	report, progress, err = bCore.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("ingress = %+v, %v, %v", report, progress, err)
	}
	buf := make([]byte, 3)
	datagram, err := b.TryReceive(buf)
	if err != nil || !datagram.Ready || datagram.DatagramBytes != 6 || datagram.Copied != 3 || !datagram.Truncated || string(buf) != "abc" || datagram.Source != aLocal {
		t.Fatalf("receive = %+v %q, %v", datagram, buf, err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	aCore.Lock()
	if count := aCore.UDPPortLeaseCountLocked(); count != 0 {
		aCore.Unlock()
		t.Fatalf("closed socket retained %d port leases", count)
	}
	aCore.Unlock()
	if usage, _ := aAccount.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed socket retained quota = %+v", usage)
	}
	retainedReset := a.retained.ResetReleased()
	if retainedReset || a.rx.storage != nil || a.tx.storage != nil {
		t.Fatalf("closed socket retained graph state: retained_reset=%v rx=%v tx=%v", retainedReset, a.rx.storage != nil, a.tx.storage != nil)
	}
}

func TestEgressShortBufferPreservesRoundRobinStateAndQueuedDatagrams(t *testing.T) {
	common, adapter, account := newTestAdapter(t, 71)
	firstLocal := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: 4071}
	secondLocal := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.71"), Port: 4072}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.72"), Port: 53}
	first := bindTestSocket(t, adapter, firstLocal).(*udpSocket)
	second := bindTestSocket(t, adapter, secondLocal).(*udpSocket)
	firstPayload := []byte("first")
	secondPayload := []byte("second")
	if progress, err := first.TrySend(firstPayload, remote); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("first send = %v, %v", progress, err)
	}
	if progress, err := second.TrySend(secondPayload, remote); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("second send = %v, %v", progress, err)
	}
	usageBefore, _ := account.Snapshot()
	firstReady := first.Readiness()
	secondReady := second.Readiness()
	short := bytes.Repeat([]byte{0xa5}, 14+20+8+len(firstPayload)-1)

	common.Lock()
	n, err := adapter.egressLocked(short)
	cursor := adapter.cursor
	firstQueued, _, firstOK := first.tx.peek()
	secondQueued, _, secondOK := second.tx.peek()
	common.Unlock()
	if n != 0 || !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short egress = %d, %v", n, err)
	}
	if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
		t.Fatalf("short egress mutated destination = %x", short)
	}
	if cursor != 0 || !firstOK || !secondOK || !bytes.Equal(firstQueued, firstPayload) || !bytes.Equal(secondQueued, secondPayload) {
		t.Fatalf("short egress mutated scheduler or queues: cursor=%d first=%q/%v second=%q/%v", cursor, firstQueued, firstOK, secondQueued, secondOK)
	}
	if first.Readiness() != firstReady || second.Readiness() != secondReady {
		t.Fatalf("short egress changed readiness: first=%v/%v second=%v/%v", first.Readiness(), firstReady, second.Readiness(), secondReady)
	}
	if usage, _ := account.Snapshot(); usage != usageBefore {
		t.Fatalf("short egress changed quota = %+v, want %+v", usage, usageBefore)
	}

	frame := make([]byte, common.Link().MaxFrameBytes())
	common.Lock()
	firstBytes, err := adapter.egressLocked(frame)
	cursorAfterFirst := adapter.cursor
	common.Unlock()
	if err != nil || firstBytes != 14+20+8+len(firstPayload) || cursorAfterFirst != 1 {
		t.Fatalf("first retry = %d, %v, cursor=%d", firstBytes, err, cursorAfterFirst)
	}
	firstIP, firstUDP := decodeUDPFrame(t, frame[:firstBytes])
	if firstIP.ID() != 72 || firstUDP.SourcePort() != firstLocal.Port || string(firstUDP.Payload()) != string(firstPayload) {
		t.Fatalf("first retry frame = id=%d source=%d payload=%q", firstIP.ID(), firstUDP.SourcePort(), firstUDP.Payload())
	}

	common.Lock()
	secondBytes, err := adapter.egressLocked(frame)
	cursorAfterSecond := adapter.cursor
	common.Unlock()
	if err != nil || secondBytes != 14+20+8+len(secondPayload) || cursorAfterSecond != 0 {
		t.Fatalf("second egress = %d, %v, cursor=%d", secondBytes, err, cursorAfterSecond)
	}
	secondIP, secondUDP := decodeUDPFrame(t, frame[:secondBytes])
	if secondIP.ID() != 73 || secondUDP.SourcePort() != secondLocal.Port || string(secondUDP.Payload()) != string(secondPayload) {
		t.Fatalf("second frame = id=%d source=%d payload=%q", secondIP.ID(), secondUDP.SourcePort(), secondUDP.Payload())
	}
}

func TestUDPIngressRequiresLocalEthernetDestinationAndValidSource(t *testing.T) {
	for _, test := range []struct {
		name        string
		mutate      func(*ethernet.Frame)
		wantHandled bool
	}{
		{
			name: "foreign destination",
			mutate: func(frame *ethernet.Frame) {
				*frame.DestinationHardwareAddr() = [6]byte{0x02, 0, 0, 0, 0, 99}
			},
		},
		{
			name: "zero source",
			mutate: func(frame *ethernet.Frame) {
				*frame.SourceHardwareAddr() = [6]byte{}
			},
			wantHandled: true,
		},
		{
			name: "broadcast source",
			mutate: func(frame *ethernet.Frame) {
				*frame.SourceHardwareAddr() = ethernet.BroadcastAddr()
			},
			wantHandled: true,
		},
		{
			name: "multicast source",
			mutate: func(frame *ethernet.Frame) {
				*frame.SourceHardwareAddr() = [6]byte{0x01, 0, 0, 0, 0, 1}
			},
			wantHandled: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceCore, sourceAdapter, _ := newTestAdapter(t, 51)
			_, destinationAdapter, _ := newTestAdapter(t, 52)
			sourceEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.51"), Port: 4051}
			destinationEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.52"), Port: 4052}
			source := bindTestSocket(t, sourceAdapter, sourceEndpoint)
			destination := bindTestSocket(t, destinationAdapter, destinationEndpoint).(*udpSocket)
			if progress, err := source.TrySend([]byte("payload"), destinationEndpoint); err != nil || progress != nscore.ProgressDone {
				t.Fatalf("send = %v, %v", progress, err)
			}
			frame := serviceUDPFrame(t, sourceCore)
			ethernetFrame, err := ethernet.NewFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			*ethernetFrame.DestinationHardwareAddr() = destinationAdapter.hardwareAddress
			test.mutate(&ethernetFrame)

			destinationAdapter.core.Lock()
			handled, err := destinationAdapter.ingressLocked(frame)
			queued := destination.rx.count
			destinationAdapter.core.Unlock()
			if err != nil || handled != test.wantHandled {
				t.Fatalf("ingress = handled %v, err %v; want handled %v", handled, err, test.wantHandled)
			}
			if queued != 0 || destination.Readiness()&nscore.ReadyReadable != 0 {
				t.Fatalf("foreign L2 frame queued datagram: queued=%d readiness=%v", queued, destination.Readiness())
			}
		})
	}
}

func TestUDPIngressLeavesUnownedOrUncorrelatableInvalidSourceTrafficUnhandled(t *testing.T) {
	sourceCore, sourceAdapter, _ := newTestAdapter(t, 57)
	_, destinationAdapter, _ := newTestAdapter(t, 58)
	sourceEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.57"), Port: 4057}
	destinationEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.58"), Port: 4058}
	source := bindTestSocket(t, sourceAdapter, sourceEndpoint)
	destination := bindTestSocket(t, destinationAdapter, destinationEndpoint).(*udpSocket)
	if progress, err := source.TrySend([]byte("payload"), destinationEndpoint); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("send = %v, %v", progress, err)
	}
	valid := serviceUDPFrame(t, sourceCore)
	ethernetFrame, err := ethernet.NewFrame(valid)
	if err != nil {
		t.Fatal(err)
	}
	*ethernetFrame.DestinationHardwareAddr() = destinationAdapter.hardwareAddress

	unowned := append([]byte(nil), valid...)
	unownedEthernet, err := ethernet.NewFrame(unowned)
	if err != nil {
		t.Fatal(err)
	}
	*unownedEthernet.SourceHardwareAddr() = [6]byte{}
	unownedIP, unownedUDP := decodeUDPFrame(t, unowned)
	unownedUDP.SetDestinationPort(destinationEndpoint.Port + 1)
	rechecksumUDPFrame(unownedIP, unownedUDP)

	short := append([]byte(nil), valid[:14+20+3]...)
	shortEthernet, err := ethernet.NewFrame(short)
	if err != nil {
		t.Fatal(err)
	}
	*shortEthernet.SourceHardwareAddr() = [6]byte{}
	shortIP, err := ipv4.NewFrame(shortEthernet.Payload())
	if err != nil {
		t.Fatal(err)
	}
	shortIP.SetTotalLength(23)
	shortIP.SetCRC(0)
	shortIP.SetCRC(shortIP.CalculateHeaderCRC())

	for _, test := range []struct {
		name  string
		frame []byte
	}{
		{name: "unowned port", frame: unowned},
		{name: "truncated before destination port", frame: short},
	} {
		t.Run(test.name, func(t *testing.T) {
			destinationAdapter.core.Lock()
			handled, ingressErr := destinationAdapter.ingressLocked(test.frame)
			queued := destination.rx.count
			destinationAdapter.core.Unlock()
			if ingressErr != nil || handled || queued != 0 {
				t.Fatalf("unowned ingress = handled %v, err %v, queued %d", handled, ingressErr, queued)
			}
		})
	}

	destinationAdapter.core.Lock()
	handled, ingressErr := destinationAdapter.ingressLocked(valid)
	queued := destination.rx.count
	destinationAdapter.core.Unlock()
	if ingressErr != nil || !handled || queued != 1 {
		t.Fatalf("valid ingress after unowned traffic = handled %v, err %v, queued %d", handled, ingressErr, queued)
	}
	buffer := make([]byte, 16)
	result, err := destination.TryReceive(buffer)
	if err != nil || !result.Ready || result.Source != sourceEndpoint || string(buffer[:result.Copied]) != "payload" {
		t.Fatalf("receive after unowned traffic = %+v, %q, %v", result, buffer[:result.Copied], err)
	}
}

func TestUDPIngressConsumesInvalidIPv4SourcesWithoutQueueing(t *testing.T) {
	for _, sourceAddress := range []netip.Addr{
		netip.IPv4Unspecified(),
		netip.MustParseAddr("127.0.0.1"),
		netip.AddrFrom4([4]byte{255, 255, 255, 255}),
		netip.MustParseAddr("224.0.0.1"),
	} {
		t.Run(sourceAddress.String(), func(t *testing.T) {
			sourceCore, sourceAdapter, _ := newTestAdapter(t, 53)
			_, destinationAdapter, _ := newTestAdapter(t, 54)
			sourceEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.53"), Port: 4053}
			destinationEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.54"), Port: 4054}
			source := bindTestSocket(t, sourceAdapter, sourceEndpoint)
			destination := bindTestSocket(t, destinationAdapter, destinationEndpoint).(*udpSocket)
			if progress, err := source.TrySend([]byte("payload"), destinationEndpoint); err != nil || progress != nscore.ProgressDone {
				t.Fatalf("send = %v, %v", progress, err)
			}
			valid := serviceUDPFrame(t, sourceCore)
			ethernetFrame, err := ethernet.NewFrame(valid)
			if err != nil {
				t.Fatal(err)
			}
			*ethernetFrame.DestinationHardwareAddr() = destinationAdapter.hardwareAddress
			malformed := append([]byte(nil), valid...)
			ipFrame, udpFrame := decodeUDPFrame(t, malformed)
			*ipFrame.SourceAddr() = sourceAddress.As4()
			ipFrame.SetCRC(0)
			ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
			rechecksumUDPFrame(ipFrame, udpFrame)

			destinationAdapter.core.Lock()
			handled, err := destinationAdapter.ingressLocked(malformed)
			queued := destination.rx.count
			destinationAdapter.core.Unlock()
			if err != nil || !handled || queued != 0 {
				t.Fatalf("invalid source ingress = handled %v, err %v, queued %d", handled, err, queued)
			}
			if ready := destination.Readiness(); ready&nscore.ReadyReadable != 0 {
				t.Fatalf("invalid source became readable: %v", ready)
			}

			destinationAdapter.core.Lock()
			handled, err = destinationAdapter.ingressLocked(valid)
			queued = destination.rx.count
			destinationAdapter.core.Unlock()
			if err != nil || !handled || queued != 1 {
				t.Fatalf("valid ingress after invalid source = handled %v, err %v, queued %d", handled, err, queued)
			}
			buffer := make([]byte, 16)
			result, err := destination.TryReceive(buffer)
			if err != nil || !result.Ready || result.Source != sourceEndpoint || string(buffer[:result.Copied]) != "payload" {
				t.Fatalf("receive after invalid source = %+v, %q, %v", result, buffer[:result.Copied], err)
			}
		})
	}
}

func TestUDPIngressDropsMalformedLocalDatagramsAndAcceptsFollowingValidFrame(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, []byte)
	}{
		{
			name: "bad IPv4 checksum",
			mutate: func(_ *testing.T, frame []byte) {
				frame[14+8] ^= 1
			},
		},
		{
			name: "oversized UDP length",
			mutate: func(t *testing.T, frame []byte) {
				_, udpFrame := decodeUDPFrame(t, frame)
				udpFrame.SetLength(udpFrame.Length() + 1)
			},
		},
		{
			name: "undersized UDP length",
			mutate: func(t *testing.T, frame []byte) {
				ipFrame, udpFrame := decodeUDPFrame(t, frame)
				udpFrame.SetLength(udpFrame.Length() - 1)
				rechecksumUDPFrame(ipFrame, udpFrame)
			},
		},
		{
			name: "bad UDP checksum",
			mutate: func(t *testing.T, frame []byte) {
				_, udpFrame := decodeUDPFrame(t, frame)
				udpFrame.Payload()[0] ^= 1
			},
		},
		{
			name: "zero source port",
			mutate: func(t *testing.T, frame []byte) {
				ipFrame, udpFrame := decodeUDPFrame(t, frame)
				udpFrame.SetSourcePort(0)
				rechecksumUDPFrame(ipFrame, udpFrame)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceCore, sourceAdapter, _ := newTestAdapter(t, 61)
			_, destinationAdapter, _ := newTestAdapter(t, 62)
			sourceEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.61"), Port: 4061}
			destinationEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.62"), Port: 4062}
			source := bindTestSocket(t, sourceAdapter, sourceEndpoint)
			destination := bindTestSocket(t, destinationAdapter, destinationEndpoint).(*udpSocket)
			if progress, err := source.TrySend([]byte("payload"), destinationEndpoint); err != nil || progress != nscore.ProgressDone {
				t.Fatalf("send = %v, %v", progress, err)
			}
			valid := serviceUDPFrame(t, sourceCore)
			ethernetFrame, err := ethernet.NewFrame(valid)
			if err != nil {
				t.Fatal(err)
			}
			*ethernetFrame.DestinationHardwareAddr() = destinationAdapter.hardwareAddress
			malformed := append([]byte(nil), valid...)
			test.mutate(t, malformed)

			destinationAdapter.core.Lock()
			handled, err := destinationAdapter.ingressLocked(malformed)
			queued := destination.rx.count
			destinationAdapter.core.Unlock()
			if err != nil || !handled || queued != 0 {
				t.Fatalf("malformed ingress = handled %v, err %v, queued %d", handled, err, queued)
			}

			destinationAdapter.core.Lock()
			handled, err = destinationAdapter.ingressLocked(valid)
			queued = destination.rx.count
			destinationAdapter.core.Unlock()
			if err != nil || !handled || queued != 1 {
				t.Fatalf("valid ingress after malformed = handled %v, err %v, queued %d", handled, err, queued)
			}
			buffer := make([]byte, 16)
			result, err := destination.TryReceive(buffer)
			if err != nil || !result.Ready || result.Source != sourceEndpoint || string(buffer[:result.Copied]) != "payload" {
				t.Fatalf("receive after malformed = %+v, %q, %v", result, buffer[:result.Copied], err)
			}
		})
	}
}

func FuzzUDPBoundWireIngressLifecycle(f *testing.F) {
	f.Add(false, byte(0), uint16(20), []byte(nil))
	f.Add(true, byte(1), uint16(24), []byte{0, 53, 0, 0})
	f.Add(true, byte(2), uint16(28), []byte{0, 53, 0, 0, 0, 8, 0, 0})
	f.Add(false, byte(3), ^uint16(0), bytes.Repeat([]byte{0xa5}, 32))
	f.Fuzz(func(t *testing.T, owned bool, sourceClass byte, declaredLength uint16, raw []byte) {
		if len(raw) > 128 {
			raw = raw[:128]
		}
		wire := append([]byte(nil), raw...)
		common, adapter, account := newTestAdapter(t, 82)
		local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.82"), Port: 4082}
		socket := bindTestSocket(t, adapter, local).(*udpSocket)
		if len(wire) >= 4 {
			port := local.Port + 1
			if owned {
				port = local.Port
			}
			binary.BigEndian.PutUint16(wire[2:4], port)
		}

		frame := make([]byte, 14+20+len(wire))
		ethernetFrame, err := ethernet.NewFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		*ethernetFrame.DestinationHardwareAddr() = adapter.hardwareAddress
		switch sourceClass % 4 {
		case 0:
			*ethernetFrame.SourceHardwareAddr() = [6]byte{0x02, 0, 0, 0, 0, 81}
		case 1:
			*ethernetFrame.SourceHardwareAddr() = [6]byte{}
		case 2:
			*ethernetFrame.SourceHardwareAddr() = ethernet.BroadcastAddr()
		case 3:
			*ethernetFrame.SourceHardwareAddr() = [6]byte{0x01, 0, 0, 0, 0, 81}
		}
		ethernetFrame.SetEtherType(ethernet.TypeIPv4)
		ipFrame, err := ipv4.NewFrame(frame[14:])
		if err != nil {
			t.Fatal(err)
		}
		ipFrame.SetVersionAndIHL(4, 5)
		ipFrame.SetTotalLength(declaredLength)
		ipFrame.SetTTL(64)
		ipFrame.SetProtocol(lneto.IPProtoUDP)
		*ipFrame.SourceAddr() = [4]byte{192, 0, 2, 81}
		*ipFrame.DestinationAddr() = local.Address.As4()
		copy(frame[34:], wire)
		ipFrame.SetCRC(0)
		ipFrame.SetCRC(ipFrame.CalculateHeaderCRC() ^ 1)

		before := append([]byte(nil), frame...)
		usageBefore, closedBefore := account.Snapshot()
		common.Lock()
		handled, ingressErr := adapter.ingressLocked(frame)
		queued := socket.rx.count
		common.Unlock()
		wantHandled := len(wire) >= 4 && owned
		if ingressErr != nil || handled != wantHandled {
			t.Fatalf("ingress = handled %v, err %v; want handled %v", handled, ingressErr, wantHandled)
		}
		if !bytes.Equal(frame, before) {
			t.Fatal("ingress mutated caller-owned frame")
		}
		if queued != 0 || socket.Readiness()&nscore.ReadyReadable != 0 {
			t.Fatalf("malformed ingress queued datagram: queued=%d readiness=%v", queued, socket.Readiness())
		}
		if usage, closed := account.Snapshot(); usage != usageBefore || closed != closedBefore {
			t.Fatalf("ingress quota = %+v, closed=%v; want %+v, closed=%v", usage, closed, usageBefore, closedBefore)
		}
		if err := socket.Close(); err != nil {
			t.Fatal(err)
		}
		if usage, closed := account.Snapshot(); usage != (quota.Usage{}) || closed {
			t.Fatalf("close quota = %+v, closed=%v", usage, closed)
		}
		common.Lock()
		leases := common.UDPPortLeaseCountLocked()
		common.Unlock()
		if leases != 0 {
			t.Fatalf("close retained %d UDP port leases", leases)
		}
	})
}

func TestSocketTrySendRejectsNonWireDestinationsWithoutQueueMutation(t *testing.T) {
	config := Config{MaxSockets: 1, ReceiveBytes: 32, TransmitBytes: 128, ReceiveDatagrams: 1, TransmitDatagrams: 4, MaxPayloadBytes: 32}
	policyConfig := policy.Config{
		Rules: []policy.Rule{{
			Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP},
			Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		}},
		LoopbackTransports:  []policy.Transport{policy.TransportUDP},
		MulticastTransports: []policy.Transport{policy.TransportUDP},
		BroadcastTransports: []policy.Transport{policy.TransportUDP},
	}
	_, adapter, account := newTestAdapterWithConfigAndPolicy(t, 63, config, policyConfig)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.63"), Port: 4063}
	socket := bindTestSocket(t, adapter, local).(*udpSocket)
	usageBefore, closedBefore := account.Snapshot()
	readyBefore := socket.Readiness()
	for _, remote := range []nscore.Endpoint{
		{Address: netip.IPv4Unspecified(), Port: 53},
		{Address: netip.MustParseAddr("127.0.0.1"), Port: 53},
	} {
		if progress, err := socket.TrySend([]byte("invalid"), remote); progress != 0 || udpFailureOf(t, err) != nscore.FailureInvalidArgument {
			t.Fatalf("non-wire send to %v = %v, %v", remote, progress, err)
		}
		if socket.tx.count != 0 || socket.tx.bytes != 0 || socket.tx.head != 0 || socket.Readiness() != readyBefore {
			t.Fatalf("rejected destination %v mutated queue: count=%d bytes=%d head=%d readiness=%v/%v", remote, socket.tx.count, socket.tx.bytes, socket.tx.head, socket.Readiness(), readyBefore)
		}
		if usage, closed := account.Snapshot(); usage != usageBefore || closed != closedBefore {
			t.Fatalf("rejected destination %v changed quota = %+v, closed=%v; want %+v, closed=%v", remote, usage, closed, usageBefore, closedBefore)
		}
	}

	for _, remote := range []nscore.Endpoint{
		{Address: netip.MustParseAddr("192.0.2.64"), Port: 53},
		{Address: netip.MustParseAddr("192.0.2.255"), Port: 53},
		{Address: netip.MustParseAddr("224.0.0.1"), Port: 53},
		{Address: netip.AddrFrom4([4]byte{255, 255, 255, 255}), Port: 53},
	} {
		if progress, err := socket.TrySend([]byte("wire"), remote); err != nil || progress != nscore.ProgressDone {
			t.Fatalf("wire send to %v = %v, %v", remote, progress, err)
		}
	}
	if socket.tx.count != 4 {
		t.Fatalf("wire destinations queued = %d, want 4", socket.tx.count)
	}
}

func TestSocketEgressUsesDestinationClassHardwareAddress(t *testing.T) {
	policyConfig := policy.Config{
		Rules: []policy.Rule{{
			Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP},
			Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		}},
		MulticastTransports: []policy.Transport{policy.TransportUDP},
		BroadcastTransports: []policy.Transport{policy.TransportUDP},
	}
	for index, test := range []struct {
		name        string
		address     netip.Addr
		destination [6]byte
	}{
		{name: "unicast via gateway", address: netip.MustParseAddr("198.51.100.9")},
		{name: "multicast mapping", address: netip.MustParseAddr("239.255.0.1"), destination: [6]byte{0x01, 0x00, 0x5e, 0x7f, 0x00, 0x01}},
		{name: "limited broadcast", address: netip.AddrFrom4([4]byte{255, 255, 255, 255}), destination: ethernet.BroadcastAddr()},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := byte(64 + index)
			common, adapter, _ := newTestAdapterWithConfigAndPolicy(t, id, Config{
				MaxSockets: 1, ReceiveBytes: 32, TransmitBytes: 32,
				ReceiveDatagrams: 1, TransmitDatagrams: 1, MaxPayloadBytes: 32,
			}, policyConfig)
			local := nscore.Endpoint{Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), Port: uint16(4064 + index)}
			socket := bindTestSocket(t, adapter, local)
			if progress, err := socket.TrySend([]byte("wire"), nscore.Endpoint{Address: test.address, Port: 53}); err != nil || progress != nscore.ProgressDone {
				t.Fatalf("send = %v, %v", progress, err)
			}
			frame := serviceUDPFrame(t, common)
			eth, err := ethernet.NewFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			want := test.destination
			if want == ([6]byte{}) {
				want = adapter.gatewayHardwareAddress
			}
			if got := *eth.DestinationHardwareAddr(); got != want {
				t.Fatalf("destination hardware address = %x, want %x", got, want)
			}
			ipFrame, _ := decodeUDPFrame(t, frame)
			if got := netip.AddrFrom4(*ipFrame.DestinationAddr()); got != test.address {
				t.Fatalf("destination IP address = %v, want %v", got, test.address)
			}
		})
	}
}

func TestSocketCloseDropsQueuedDatagramsAndReusesBackingWithoutStaleRevival(t *testing.T) {
	_, adapter, account := newTestAdapter(t, 89)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.89"), Port: 4089}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.90"), Port: 4090}
	socket := bindTestSocket(t, adapter, local).(*udpSocket)
	if progress, err := socket.TrySend([]byte("queued transmit"), remote); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("queue transmit = %v, %v", progress, err)
	}
	adapter.core.Lock()
	if !socket.rx.push([]byte("queued receive"), remote) {
		adapter.core.Unlock()
		t.Fatal("queue receive failed")
	}
	rxStart, txStart := &socket.rx.storage[0], &socket.tx.storage[0]
	adapter.core.Unlock()
	if ready := socket.Readiness(); ready != nscore.ReadyReadable|nscore.ReadyWritable {
		t.Fatalf("queued readiness = %v", ready)
	}

	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if endpoint := socket.LocalEndpoint(); endpoint != (nscore.Endpoint{}) {
		t.Fatalf("stale local endpoint = %+v", endpoint)
	}
	if ready := socket.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("stale readiness = %v", ready)
	}
	dst := []byte{0xa5, 0xa5}
	if result, err := socket.TryReceive(dst); result != (udpns.DatagramResult{}) || udpFailureOf(t, err) != nscore.FailureClosed || dst[0] != 0xa5 || dst[1] != 0xa5 {
		t.Fatalf("stale receive = %+v, %v, dst=%x", result, err, dst)
	}
	if progress, err := socket.TrySend([]byte("stale"), remote); progress != 0 || udpFailureOf(t, err) != nscore.FailureClosed {
		t.Fatalf("stale send = %v, %v", progress, err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed socket retained quota = %+v", usage)
	}
	if len(adapter.freeBackings) != 1 || !allZeroBytes(adapter.freeBackings[0].rxStorage) || !allZeroBytes(adapter.freeBackings[0].txStorage) {
		t.Fatalf("recycled backing retained payloads: %+v", adapter.freeBackings)
	}

	fresh := bindTestSocket(t, adapter, local).(*udpSocket)
	if fresh == socket || &fresh.rx.storage[0] != rxStart || &fresh.tx.storage[0] != txStart {
		t.Fatalf("backing reuse = stale:%p fresh:%p rx:%p/%p tx:%p/%p", socket, fresh, rxStart, &fresh.rx.storage[0], txStart, &fresh.tx.storage[0])
	}
	if ready := fresh.Readiness(); ready != nscore.ReadyWritable || fresh.rx.count != 0 || fresh.tx.count != 0 {
		t.Fatalf("fresh socket inherited queue state: readiness=%v rx=%d tx=%d", ready, fresh.rx.count, fresh.tx.count)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage.Resources != 1 || usage.UDPResources != 1 {
		t.Fatalf("stale close released fresh quota = %+v", usage)
	}
	if progress, err := fresh.TrySend([]byte("fresh"), remote); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("fresh send after stale close = %v, %v", progress, err)
	}
}

func TestSocketNamespaceCloseRacesQueuedIOAndEndpointSnapshots(t *testing.T) {
	common, adapter, account := newTestAdapter(t, 88)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.88"), Port: 4088}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.87"), Port: 4087}
	socket := bindTestSocket(t, adapter, local).(*udpSocket)
	if progress, err := socket.TrySend([]byte("queued transmit"), remote); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("queue transmit = %v, %v", progress, err)
	}
	common.Lock()
	if !socket.rx.push([]byte("queued receive"), remote) {
		common.Unlock()
		t.Fatal("queue receive failed")
	}
	common.Unlock()

	start := make(chan struct{})
	unexpected := make(chan error, 1)
	record := func(err error) {
		select {
		case unexpected <- err:
		default:
		}
	}
	var workers sync.WaitGroup
	workers.Add(4)
	go func() {
		defer workers.Done()
		<-start
		for range 1000 {
			_ = socket.LocalEndpoint()
			if ready := socket.Readiness(); !ready.Valid() {
				record(errors.New("invalid UDP readiness"))
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		dst := make([]byte, 32)
		for range 1000 {
			result, err := socket.TryReceive(dst)
			if err != nil {
				if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureClosed {
					record(err)
				}
				return
			}
			if !result.Valid(len(dst)) {
				record(errors.New("invalid UDP receive result"))
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for range 1000 {
			if _, err := socket.TrySend([]byte("pressure"), remote); err != nil {
				if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureClosed {
					record(err)
				}
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		if err := socket.Close(); err != nil {
			record(err)
			return
		}
		if err := common.Close(); err != nil {
			record(err)
		}
	}()
	close(start)
	workers.Wait()
	select {
	case err := <-unexpected:
		t.Fatal(err)
	default:
	}
	if endpoint := socket.LocalEndpoint(); endpoint != (nscore.Endpoint{}) {
		t.Fatalf("terminal endpoint = %+v", endpoint)
	}
	if ready := socket.Readiness(); ready != nscore.ReadyClosed {
		t.Fatalf("terminal readiness = %v", ready)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("close race retained quota = %+v", usage)
	}
	common.Lock()
	leases := common.UDPPortLeaseCountLocked()
	common.Unlock()
	if leases != 0 {
		t.Fatalf("close race retained %d UDP port leases", leases)
	}
}

func TestAdapterTryBindCloseReusesDatagramBacking(t *testing.T) {
	_, adapter, _ := newTestAdapter(t, 90)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.90"), Port: 4090}
	allocs := testing.AllocsPerRun(1000, func() {
		value, progress, err := adapter.TryBind(local)
		if err != nil || progress != nscore.ProgressDone {
			panic(err)
		}
		if err := value.Close(); err != nil {
			panic(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("bind/close allocations = %v, want <= 1", allocs)
	}
}

func TestEphemeralBindChecksFinalAllocatedPortAgainstPolicy(t *testing.T) {
	config := Config{MaxSockets: 1, ReceiveBytes: 32, TransmitBytes: 32, ReceiveDatagrams: 1, TransmitDatagrams: 1, MaxPayloadBytes: 32}
	policyConfig := policy.Config{
		Rules: []policy.Rule{
			{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionInbound}, Ports: []policy.PortRange{{First: firstEphemeralUDPPort, Last: firstEphemeralUDPPort}}},
			{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP}, Directions: []policy.Direction{policy.DirectionInbound}, Ports: []policy.PortRange{{First: 0, Last: 0}}},
		},
		WildcardBindTransports: []policy.Transport{policy.TransportUDP},
	}
	common, adapter, account := newTestAdapterWithConfigAndPolicy(t, 35, config, policyConfig)
	local := nscore.Endpoint{Address: netip.IPv4Unspecified()}
	if resource, progress, err := adapter.TryBind(local); err == nil || resource != nil || progress != 0 {
		t.Fatalf("denied first ephemeral bind = %T, %v, %v", resource, progress, err)
	} else if failure, ok := nscore.FailureOf(err); !ok || failure != nscore.FailureAccessDenied {
		t.Fatalf("denied first ephemeral bind failure = %v", err)
	}
	common.Lock()
	if leases := common.UDPPortLeaseCountLocked(); leases != 0 {
		common.Unlock()
		t.Fatalf("denied ephemeral bind retained %d leases", leases)
	}
	common.Unlock()
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("denied ephemeral bind retained quota = %+v", usage)
	}
	resource, progress, err := adapter.TryBind(local)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("second ephemeral bind = %T, %v, %v", resource, progress, err)
	}
	socket := resource.(udpns.Socket)
	if got := socket.LocalEndpoint().Port; got != firstEphemeralUDPPort+1 {
		t.Fatalf("second ephemeral port = %d, want %d", got, firstEphemeralUDPPort+1)
	}
}

func TestAdapterCloseReleasesAllSocketsDeterministically(t *testing.T) {
	common, adapter, account := newTestAdapter(t, 33)
	for _, port := range []uint16{4100, 4101} {
		bindTestSocket(t, adapter, nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.33"), Port: port})
	}
	if err := common.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("core close retained quota = %+v", usage)
	}
}

func TestSocketDatagramQueuesShareBackingStorage(t *testing.T) {
	config := Config{ReceiveBytes: 64, TransmitBytes: 96, ReceiveDatagrams: 2, TransmitDatagrams: 3, MaxPayloadBytes: 32}
	rx, tx := newSocketDatagramQueues(config)
	if len(rx.storage) != 64 || cap(rx.storage) != 64 || len(tx.storage) != 96 || cap(tx.storage) != 96 {
		t.Fatalf("payload layout = rx %d/%d tx %d/%d", len(rx.storage), cap(rx.storage), len(tx.storage), cap(tx.storage))
	}
	if len(rx.slots) != 2 || cap(rx.slots) != 2 || len(tx.slots) != 3 || cap(tx.slots) != 3 {
		t.Fatalf("slot layout = rx %d/%d tx %d/%d", len(rx.slots), cap(rx.slots), len(tx.slots), cap(tx.slots))
	}
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 53}
	if !rx.push([]byte("receive"), endpoint) || !tx.push([]byte("transmit"), endpoint) {
		t.Fatal("shared queues rejected independent payloads")
	}
	rxPayload, _, _ := rx.peek()
	txPayload, _, _ := tx.peek()
	if string(rxPayload) != "receive" || string(txPayload) != "transmit" {
		t.Fatalf("shared queue payloads = %q, %q", rxPayload, txPayload)
	}
}

func TestZeroPayloadDatagramRoundTripPreservesReadyEvent(t *testing.T) {
	config := Config{MaxSockets: 1, ReceiveDatagrams: 1, TransmitDatagrams: 1}
	sourceCore, sourceAdapter, sourceAccount := newTestAdapterWithConfig(t, 34, config)
	_, destinationAdapter, destinationAccount := newTestAdapterWithConfig(t, 35, config)
	sourceEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.34"), Port: 4034}
	destinationEndpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.35"), Port: 4035}
	source := bindTestSocket(t, sourceAdapter, sourceEndpoint)
	destination := bindTestSocket(t, destinationAdapter, destinationEndpoint).(*udpSocket)

	if progress, err := source.TrySend(nil, destinationEndpoint); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("empty datagram send = %v, %v", progress, err)
	}
	if ready := source.Readiness(); ready&nscore.ReadyWritable != 0 {
		t.Fatalf("full zero-payload transmit queue remained writable: %v", ready)
	}
	frame := serviceUDPFrame(t, sourceCore)
	if len(frame) != 14+20+8 {
		t.Fatalf("empty datagram frame bytes = %d", len(frame))
	}
	ipFrame, udpFrame := decodeUDPFrame(t, frame)
	if ipFrame.TotalLength() != 20+8 || udpFrame.Length() != 8 || len(udpFrame.Payload()) != 0 {
		t.Fatalf("empty datagram wire lengths = IPv4 %d UDP %d payload %d", ipFrame.TotalLength(), udpFrame.Length(), len(udpFrame.Payload()))
	}
	ethernetFrame, err := ethernet.NewFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	*ethernetFrame.DestinationHardwareAddr() = destinationAdapter.hardwareAddress
	destinationAdapter.core.Lock()
	handled, err := destinationAdapter.ingressLocked(frame)
	queued := destination.rx.count
	destinationAdapter.core.Unlock()
	if err != nil || !handled || queued != 1 || destination.Readiness()&nscore.ReadyReadable == 0 {
		t.Fatalf("empty datagram ingress = handled %v, err %v, queued %d, readiness %v", handled, err, queued, destination.Readiness())
	}

	dst := []byte{0xa5}
	result, err := destination.TryReceive(dst)
	if err != nil || result != (udpns.DatagramResult{Source: sourceEndpoint, Ready: true}) || dst[0] != 0xa5 {
		t.Fatalf("empty datagram receive = %+v, %v, dst=%x", result, err, dst)
	}
	if ready := destination.Readiness(); ready&nscore.ReadyReadable != 0 {
		t.Fatalf("drained empty datagram remained readable: %v", ready)
	}
	wantUsage := quota.Usage{Resources: 1, UDPResources: 1}
	if usage, _ := sourceAccount.Snapshot(); usage != wantUsage {
		t.Fatalf("source metadata-only quota = %+v, want %+v", usage, wantUsage)
	}
	if usage, _ := destinationAccount.Snapshot(); usage != wantUsage {
		t.Fatalf("destination metadata-only quota = %+v, want %+v", usage, wantUsage)
	}
}

func TestZeroPayloadSocketCreationUsesMetadataOnlyQuota(t *testing.T) {
	config := Config{MaxSockets: 1, ReceiveDatagrams: 1, TransmitDatagrams: 1}
	_, adapter, account := newTestAdapterWithConfig(t, 34, config)
	local := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.34"), Port: 4034}
	socket := bindTestSocket(t, adapter, local)
	if usage, closed := account.Snapshot(); closed || usage != (quota.Usage{Resources: 1, UDPResources: 1}) {
		t.Fatalf("metadata-only socket quota = %+v, closed=%v", usage, closed)
	}
	remote := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.35"), Port: 53}
	if progress, err := socket.TrySend(nil, remote); err != nil || progress != nscore.ProgressDone {
		t.Fatalf("empty datagram send = %v, %v", progress, err)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := account.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("metadata-only socket close retained quota = %+v", usage)
	}
}

func TestValidConfigRejectsCombinedQueueSizeOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, test := range []struct {
		name   string
		config Config
	}{
		{
			name: "zero-payload slot count",
			config: Config{
				MaxSockets: 1, ReceiveDatagrams: maxInt, TransmitDatagrams: 1,
			},
		},
		{
			name: "shared payload backing",
			config: Config{
				MaxSockets: 1, ReceiveBytes: maxInt - 1, TransmitBytes: maxInt - 1,
				ReceiveDatagrams: maxInt / 2, TransmitDatagrams: maxInt / 2, MaxPayloadBytes: 2,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if ValidConfig(test.config, ethernet.MaxMTU, nil, nil, false) {
				t.Fatalf("overflowing config accepted: %+v", test.config)
			}
		})
	}
}

func udpFailureOf(t testing.TB, err error) nscore.Failure {
	t.Helper()
	if err == nil {
		t.Fatal("missing error")
	}
	failure, ok := nscore.FailureOf(err)
	if !ok {
		t.Fatalf("missing semantic failure: %v", err)
	}
	return failure
}

func allZeroBytes(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func BenchmarkUDPDatagramQueueRoundTrip(b *testing.B) {
	queue := newDatagramQueue(8, 64, 512)
	endpoint := nscore.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 53}
	payload := make([]byte, 64)
	buffer := make([]byte, 64)
	b.ReportAllocs()
	for b.Loop() {
		if !queue.push(payload, endpoint) {
			b.Fatal("queue push blocked")
		}
		result, ok := queue.pop(buffer)
		if !ok || !result.Ready || result.Copied != len(payload) {
			b.Fatalf("queue pop = %+v, %v", result, ok)
		}
	}
}

func decodeUDPFrame(t testing.TB, frame []byte) (ipv4.Frame, lnetoudp.Frame) {
	t.Helper()
	ipFrame, err := ipv4.NewFrame(frame[14:])
	if err != nil {
		t.Fatal(err)
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	return ipFrame, udpFrame
}

func rechecksumUDPFrame(ipFrame ipv4.Frame, udpFrame lnetoudp.Frame) {
	udpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
	udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
}

func serviceUDPFrame(t testing.TB, common *lnetocore.Namespace) []byte {
	t.Helper()
	common.Lock()
	common.SetNextIngressLocked(false)
	common.Unlock()
	budget := nscore.ServiceBudget{Packets: 1, Bytes: uint32(common.Link().MaxFrameBytes()), Operations: 1}
	report, progress, err := common.TryService(budget)
	if err != nil || progress != nscore.ProgressDone || report.Packets != 1 || report.Operations != 1 {
		t.Fatalf("egress = %+v, %v, %v", report, progress, err)
	}
	frame := make([]byte, common.Link().MaxFrameBytes())
	result, err := common.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready || result.Truncated {
		t.Fatalf("dequeue = %+v, %v", result, err)
	}
	return frame[:result.FrameBytes]
}

func bindTestSocket(t testing.TB, adapter *Adapter, local nscore.Endpoint) udpns.Socket {
	t.Helper()
	resource, progress, err := adapter.TryBind(local)
	if err != nil || progress != nscore.ProgressDone {
		t.Fatalf("bind = %T, %v, %v", resource, progress, err)
	}
	return resource.(udpns.Socket)
}

func newGatewayConfigTestCore(t testing.TB, gateway [6]byte) *lnetocore.Namespace {
	t.Helper()
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	mtu := uint16(ethernet.MaxMTU)
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "udp-config", RandSeed: 101,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, 101}, GatewayHardwareAddress: gateway,
		IPv4Address: netip.MustParseAddr("192.0.2.101"), MTU: mtu,
		Link:   packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 1, EgressFrames: 1},
		Policy: compiled, Quotas: quota.NewAccount(quota.DefaultLimits()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return common
}

func newTestAdapter(t testing.TB, id byte) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	return newTestAdapterWithConfig(t, id, Config{MaxSockets: 4, ReceiveBytes: 64, TransmitBytes: 64, ReceiveDatagrams: 2, TransmitDatagrams: 2, MaxPayloadBytes: 32})
}

func newTestAdapterWithConfig(t testing.TB, id byte, config Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	return newTestAdapterWithConfigAndPolicy(t, id, config, policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportUDP},
		Directions: []policy.Direction{policy.DirectionInbound, policy.DirectionOutbound},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}})
}

func newTestAdapterWithConfigAndPolicy(t testing.TB, id byte, config Config, policyConfig policy.Config) (*lnetocore.Namespace, *Adapter, *quota.Account) {
	t.Helper()
	compiled, err := policy.Compile(policyConfig)
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.Limits{Resources: 4, UDPResources: 4, QueuedBytes: 512})
	mtu := uint16(ethernet.MaxMTU)
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: "udp", RandSeed: int64(id) + 1,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 3},
		IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), MTU: mtu,
		Link:   packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
		Policy: compiled, Quotas: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(common, config)
	if err != nil {
		_ = common.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = common.Close() })
	return common, adapter, account
}
