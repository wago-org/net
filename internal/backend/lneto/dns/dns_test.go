package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	lneto "github.com/soypat/lneto"
	lnetodns "github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	lnetoudp "github.com/soypat/lneto/udp"
	lnetocore "github.com/wago-org/net/internal/backend/lneto/core"
	tcpbackend "github.com/wago-org/net/internal/backend/lneto/tcp"
	"github.com/wago-org/net/internal/namespace"
	tcpns "github.com/wago-org/net/internal/namespace/tcp"
	"github.com/wago-org/net/internal/packetlink"
	"github.com/wago-org/net/internal/policy"
	"github.com/wago-org/net/internal/quota"
)

func TestConfigRejectsNonWireResolvers(t *testing.T) {
	compiled, err := policy.Compile(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	account := quota.NewAccount(quota.DefaultLimits())
	base := Config{Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 1, MaxRecords: 1, MaxResponseBytes: 512, MaxAttempts: 1, RetryServiceAttempts: 1}
	if !ValidConfig(base, 1500, compiled, account, true) {
		t.Fatal("valid unicast resolver rejected")
	}
	fallback := base
	fallback.MaxTCPResponseBytes = 16 << 10
	fallback.MaxTCPServiceAttempts = 128
	if !ValidConfig(fallback, 1500, compiled, account, true) {
		t.Fatal("valid bounded TCP fallback rejected")
	}
	for name, mutate := range map[string]func(*Config){
		"bytes without attempts": func(config *Config) { config.MaxTCPResponseBytes = 512 },
		"attempts without bytes": func(config *Config) { config.MaxTCPServiceAttempts = 1 },
		"response too short": func(config *Config) {
			config.MaxTCPResponseBytes, config.MaxTCPServiceAttempts = 11, 1
		},
		"too many attempts": func(config *Config) {
			config.MaxTCPResponseBytes, config.MaxTCPServiceAttempts = 512, MaximumTCPServiceAttempts+1
		},
		"aggregate response retention": func(config *Config) {
			config.MaxQueries, config.MaxTCPResponseBytes, config.MaxTCPServiceAttempts = 1025, MaximumTCPResponseBytes, 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := base
			mutate(&invalid)
			if ValidConfig(invalid, 1500, compiled, account, true) {
				t.Fatalf("invalid TCP fallback accepted: %+v", invalid)
			}
		})
	}
	for name, server := range map[string]netip.Addr{
		"loopback":          netip.MustParseAddr("127.0.0.1"),
		"multicast":         netip.MustParseAddr("224.0.0.251"),
		"limited broadcast": netip.AddrFrom4([4]byte{255, 255, 255, 255}),
	} {
		t.Run(name, func(t *testing.T) {
			invalid := base
			invalid.Server = server
			if ValidConfig(invalid, 1500, compiled, account, true) {
				t.Fatalf("accepted invalid resolver %v", server)
			}
		})
	}
}

func TestAdapterRejectsLoopbackResolverBeforeInstallingState(t *testing.T) {
	config := dnsTestConfig(t, 105)
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: config.Hostname, RandSeed: config.RandSeed,
		HardwareAddress: config.HardwareAddress, GatewayHardwareAddress: config.GatewayHardwareAddress,
		IPv4Address: config.IPv4Address, MTU: config.MTU, Link: config.Link,
		Policy: config.Policy, Quotas: config.Quotas,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer common.Close()
	invalid := config.DNS
	invalid.Server = netip.MustParseAddr("127.0.0.53")
	usageBefore, closedBefore := config.Quotas.Snapshot()
	if adapter, err := New(common, invalid); err == nil || adapter != nil || requireFailure(t, err) != namespace.FailureInvalidArgument {
		t.Fatalf("loopback resolver adapter = %T, %v", adapter, err)
	}
	common.Lock()
	leases := common.UDPPortLeaseCountLocked()
	common.Unlock()
	if leases != 0 {
		t.Fatalf("rejected resolver retained %d UDP port leases", leases)
	}
	if usage, closed := config.Quotas.Snapshot(); usage != usageBefore || closed != closedBefore {
		t.Fatalf("rejected resolver changed quota = %+v, closed=%v; want %+v, closed=%v", usage, closed, usageBefore, closedBefore)
	}
	if adapter, err := New(common, config.DNS); err != nil || adapter == nil {
		t.Fatalf("valid adapter after rejected resolver = %T, %v", adapter, err)
	}
}

func TestAdapterRequiresUnicastGatewayHardwareAddressWhenEnabled(t *testing.T) {
	for name, gateway := range map[string][6]byte{
		"zero":      {},
		"multicast": {0x01, 0, 0, 0, 0, 1},
		"broadcast": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			config := dnsTestConfig(t, 104)
			config.GatewayHardwareAddress = gateway
			common, err := lnetocore.New(lnetocore.Config{
				Hostname: config.Hostname, RandSeed: config.RandSeed,
				HardwareAddress: config.HardwareAddress, GatewayHardwareAddress: config.GatewayHardwareAddress,
				IPv4Address: config.IPv4Address, MTU: config.MTU, Link: config.Link,
				Policy: config.Policy, Quotas: config.Quotas,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer common.Close()
			if _, err := New(common, config.DNS); err == nil {
				t.Fatalf("enabled DNS accepted gateway hardware address %v", gateway)
			}
			if _, err := New(common, Config{}); err != nil {
				t.Fatalf("disabled DNS rejected irrelevant gateway hardware address %v: %v", gateway, err)
			}
		})
	}
}

func TestBuildDNSQueryPacketDirectEncoding(t *testing.T) {
	request := namespace.DNSRequest{Name: "service.api.example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	packet, err := buildDNSQueryPacket(request, 0x1234, 1232)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := lnetodns.NewFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if frame.TxID() != 0x1234 || frame.Flags().IsResponse() || frame.QDCount() != 2 || frame.ANCount() != 0 || frame.NSCount() != 0 || frame.ARCount() != 1 {
		t.Fatalf("query header = txid=%x flags=%x counts=%d/%d/%d/%d", frame.TxID(), frame.Flags(), frame.QDCount(), frame.ANCount(), frame.NSCount(), frame.ARCount())
	}
	offset, err := validateDNSQuestions(packet, lnetodns.SizeHeader, frame.QDCount(), request)
	if err != nil {
		t.Fatal(err)
	}
	if offset+11 != len(packet) || packet[offset] != 0 || binary.BigEndian.Uint16(packet[offset+1:offset+3]) != 41 || binary.BigEndian.Uint16(packet[offset+3:offset+5]) != 1232 {
		t.Fatalf("EDNS resource = %x", packet[offset:])
	}
	for _, value := range packet[offset+5:] {
		if value != 0 {
			t.Fatalf("nonzero EDNS tail: %x", packet[offset:])
		}
	}
}

func TestDNSTruncatedUDPUsesBoundedPrivateTCPFallback(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.61")
	serverAddress := netip.MustParseAddr("192.0.2.53")
	clientMAC := [6]byte{0x02, 0, 0, 0, 0, 61}
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 53}
	clientPolicy, err := policy.Compile(policy.Config{Rules: []policy.Rule{{
		Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDNS},
		Directions: []policy.Direction{policy.DirectionOutbound}, DNSSuffixes: []string{"example.com"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	serverPolicy, err := policy.Compile(policy.Config{
		Rules: []policy.Rule{{
			Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportTCP},
			Directions: []policy.Direction{policy.DirectionInbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)},
			Ports: []policy.PortRange{{First: lnetodns.ServerPort, Last: lnetodns.ServerPort}},
		}},
		PrivilegedBindTransports: []policy.Transport{policy.TransportTCP},
	})
	if err != nil {
		t.Fatal(err)
	}
	limits := quota.Limits{Resources: 16, TCPResources: 8, DNSResources: 4, QueuedBytes: 1 << 20, DNSWork: 8}
	clientAccount := quota.NewAccount(limits)
	serverAccount := quota.NewAccount(limits)
	mtu := uint16(ethernet.MaxMTU)
	newCore := func(hostname string, seed int64, address netip.Addr, hardware, gateway [6]byte, compiled *policy.Policy, account *quota.Account) *lnetocore.Namespace {
		core, err := lnetocore.New(lnetocore.Config{
			Hostname: hostname, RandSeed: seed, HardwareAddress: hardware, GatewayHardwareAddress: gateway,
			IPv4Address: address, MTU: mtu, MaxActiveTCPPorts: 4, Policy: compiled, Quotas: account,
			Link: packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 32, EgressFrames: 32},
		})
		if err != nil {
			t.Fatal(err)
		}
		return core
	}
	clientCore := newCore("dns-tcp-client", 61, clientAddress, clientMAC, serverMAC, clientPolicy, clientAccount)
	serverCore := newCore("dns-tcp-server", 53, serverAddress, serverMAC, clientMAC, serverPolicy, serverAccount)
	t.Cleanup(func() {
		_ = clientCore.Close()
		_ = serverCore.Close()
	})
	dnsConfig := Config{
		Server: serverAddress, MaxQueries: 2, MaxRecords: 4, MaxResponseBytes: 512,
		MaxAttempts: 1, RetryServiceAttempts: 2, MaxTCPResponseBytes: 2048, MaxTCPServiceAttempts: 512,
	}
	clientDNS, err := New(clientCore, dnsConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverTCP, err := tcpbackend.New(serverCore, tcpbackend.Config{
		MaxListeners: 1, AcceptBacklog: 1, ReceiveBytes: 4 << 10, TransmitBytes: 4 << 10, TransmitPackets: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	listenerValue, progress, err := serverTCP.TryListen(namespace.Endpoint{Address: serverAddress, Port: lnetodns.ServerPort})
	if err != nil || progress != namespace.ProgressDone {
		t.Fatalf("TCP DNS listen = %T, %v, %v", listenerValue, progress, err)
	}
	listener := listenerValue.(tcpns.Listener)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	queryValue, progress, err := clientDNS.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("DNS query = %T, %v, %v", queryValue, progress, err)
	}
	query := queryValue.(*dnsQuery)
	clientNS := &testNamespace{core: clientCore, adapter: clientDNS, requiredFrameBytes: int(mtu) + 14}
	udpQuery := serviceDNSPacket(t, clientNS)
	txid, localPort := dnsPacketIdentity(t, udpQuery)
	questionName := lnetodns.MustNewName(request.Name)
	truncatedMessage := lnetodns.Message{Questions: []lnetodns.Question{
		{Name: questionName, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: questionName, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}}
	responseConfig := namespaceTestConfig{
		HardwareAddress: clientMAC, GatewayHardwareAddress: serverMAC, IPv4Address: clientAddress, DNS: dnsConfig,
	}
	truncated := buildDNSFrame(t, responseConfig, txid, localPort, truncatedMessage, lnetodns.HeaderFlags(1<<15|1<<9|1<<8|1<<7))
	serviceDNSIngressFrame(t, clientNS, truncated)
	if query.state != dnsQueryTCPConnecting || query.localPort != 0 || query.tcpStream == nil {
		t.Fatalf("fallback transition = state:%v port:%d stream:%T", query.state, query.localPort, query.tcpStream)
	}

	var serverStream tcpns.Stream
	var requestWire, responseWire []byte
	responseOffset := 0
	for attempt := 0; attempt < 20000 && query.state != dnsQueryDone; attempt++ {
		relayDNSCore(t, clientCore, serverCore)
		relayDNSCore(t, serverCore, clientCore)
		if serverStream == nil && listener.Readiness()&namespace.ReadyAccept != 0 {
			accepted, acceptProgress, acceptErr := listener.TryAccept()
			if acceptErr != nil || acceptProgress != namespace.ProgressDone {
				t.Fatalf("TCP DNS accept = %T, %v, %v", accepted, acceptProgress, acceptErr)
			}
			serverStream = accepted.(tcpns.Stream)
		}
		if serverStream != nil {
			buffer := make([]byte, 257)
			result, readErr := serverStream.TryRead(buffer)
			if readErr != nil {
				t.Fatal(readErr)
			}
			requestWire = append(requestWire, buffer[:result.Bytes]...)
			if responseWire == nil && len(requestWire) >= 2 {
				requestBytes := int(binary.BigEndian.Uint16(requestWire[:2]))
				if len(requestWire) >= 2+requestBytes {
					if got := binary.BigEndian.Uint16(requestWire[2:4]); got != txid {
						t.Fatalf("TCP query txid = %d, want %d", got, txid)
					}
					udpResponse := buildDNSResponseFrame(t, responseConfig, txid, localPort, request.Name)
					ethernetFrame, _ := ethernet.NewFrame(udpResponse)
					ipFrame, _ := ipv4.NewFrame(ethernetFrame.Payload())
					udpFrame, _ := lnetoudp.NewFrame(ipFrame.Payload())
					payload := append([]byte(nil), udpFrame.RawData()[8:udpFrame.Length()]...)
					responseWire = make([]byte, 2+len(payload))
					binary.BigEndian.PutUint16(responseWire[:2], uint16(len(payload)))
					copy(responseWire[2:], payload)
				}
			}
			if responseOffset < len(responseWire) {
				result, writeErr := serverStream.TryWrite(responseWire[responseOffset:])
				if writeErr != nil {
					t.Fatal(writeErr)
				}
				responseOffset += result.Bytes
			}
		}
		runtime.Gosched()
	}
	if query.state != dnsQueryDone || query.tcpStream != nil || query.tcpResponse != nil || query.txid != 0 {
		t.Fatalf("TCP fallback completion = state:%v stream:%T response:%d txid:%d failure:%v", query.state, query.tcpStream, len(query.tcpResponse), query.txid, query.failure)
	}
	var records []namespace.DNSRecord
	for {
		record, next, err := query.TryNext()
		if err != nil {
			t.Fatal(err)
		}
		if next == namespace.DNSNextEOF {
			break
		}
		if next != namespace.DNSNextReady {
			t.Fatalf("TCP DNS next = %v", next)
		}
		records = append(records, record)
	}
	if len(records) != 3 {
		t.Fatalf("TCP fallback records = %+v", records)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if serverStream != nil {
		_ = serverStream.Close()
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := clientAccount.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("client fallback quota = %+v", usage)
	}
	if usage, _ := serverAccount.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("server fallback quota = %+v", usage)
	}
}

func TestDNSQueryReusesClearedPacketAndInlineRecordStorage(t *testing.T) {
	config := dnsTestConfig(t, 60)
	config.DNS.MaxQueries = 2
	config.DNS.MaxRecords = inlineDNSRecordCapacity
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	value, _, err := ns.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	first := value.(*dnsQuery)
	packetStorage := first.packetStorage
	recordStorage := first.recordStorage
	first.records = first.recordStorage[:1]
	first.records[0] = namespace.DNSRecord{Name: request.Name, Type: namespace.DNSRecordA, TTLSeconds: 60, Address: netip.MustParseAddr("192.0.2.60")}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if first.packetStorage != nil || first.recordStorage != nil || ns.adapter.freePacket == nil || ns.adapter.freeRecordInline == nil {
		t.Fatalf("closed query storage = packet:%p records:%p free-packet:%p free-records:%p", first.packetStorage, first.recordStorage, ns.adapter.freePacket, ns.adapter.freeRecordInline)
	}
	if ns.adapter.freePacket != packetStorage || ns.adapter.freePacket[0] != 0 {
		t.Fatalf("cleared packet storage = stored:%p want:%p first:%d", ns.adapter.freePacket, packetStorage, ns.adapter.freePacket[0])
	}
	if ns.adapter.freeRecordInline != recordStorage || ns.adapter.freeRecordInline[0] != (namespace.DNSRecord{}) {
		t.Fatalf("cleared inline storage = stored:%p want:%p record:%+v", ns.adapter.freeRecordInline, recordStorage, ns.adapter.freeRecordInline[0])
	}
	value, _, err = ns.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	second := value.(*dnsQuery)
	if second.packetStorage != packetStorage || second.recordStorage != recordStorage || ns.adapter.freePacket != nil || ns.adapter.freeRecordInline != nil {
		t.Fatalf("reused query storage = packet:%p want:%p records:%p want:%p free-packet:%p free-records:%p", second.packetStorage, packetStorage, second.recordStorage, recordStorage, ns.adapter.freePacket, ns.adapter.freeRecordInline)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	ns.core.Lock()
	ns.adapter.CloseLocked()
	ns.core.Unlock()
	if ns.adapter.freePacket != nil || ns.adapter.freeRecordInline != nil {
		t.Fatalf("namespace close retained query storage packet=%p records=%p", ns.adapter.freePacket, ns.adapter.freeRecordInline)
	}
}

func TestDNSRecordOverflowCacheHasOneFiniteCeiling(t *testing.T) {
	for index, maxRecords := range []uint16{maximumCachedDNSRecordOverflow, maximumCachedDNSRecordOverflow + 1} {
		t.Run(fmt.Sprintf("records=%d", maxRecords), func(t *testing.T) {
			config := dnsTestConfig(t, byte(90+index))
			config.DNS.MaxQueries = 2
			config.DNS.MaxRecords = maxRecords
			config.Quotas = quota.NewAccount(quota.Limits{Resources: 4, DNSResources: 4, QueuedBytes: 1 << 20, DNSWork: 4})
			ns := newTestNamespace(t, config)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
			for range 2 {
				value, _, err := ns.TryResolve(request)
				if err != nil {
					t.Fatal(err)
				}
				if err := value.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if maxRecords <= maximumCachedDNSRecordOverflow {
				if cap(ns.adapter.freeRecordOverflow) != int(maxRecords) {
					t.Fatalf("cached overflow capacity = %d, want %d", cap(ns.adapter.freeRecordOverflow), maxRecords)
				}
			} else if ns.adapter.freeRecordOverflow != nil {
				t.Fatalf("oversized overflow capacity %d was retained", cap(ns.adapter.freeRecordOverflow))
			}
		})
	}
}

func TestDNSTCPFallbackDefersResponseStorageUntilCorrelatedTruncation(t *testing.T) {
	config := dnsTestConfig(t, 61)
	config.MaxActiveTCPPorts = 1
	config.DNS.MaxTCPResponseBytes = 16 << 10
	config.DNS.MaxTCPServiceAttempts = 32
	baseRetained := dnsRetainedBytes(config.DNS)
	tcpStorage := uint64(dnsTCPReceiveBytes + dnsTCPTransmitBytes)
	config.Quotas = quota.NewAccount(quota.Limits{
		Resources: 4, TCPResources: 2, DNSResources: 2,
		QueuedBytes: baseRetained + tcpStorage, DNSWork: 4,
	})
	ns := newTestNamespace(t, config)
	if got, want := len(ns.adapter.candidates), config.DNS.MaxResponseBytes/11; got != want {
		t.Fatalf("eager parser candidate storage = %d, want UDP-only bound %d", got, want)
	}
	if got, want := len(ns.adapter.names), 2*(config.DNS.MaxResponseBytes/11); got != want {
		t.Fatalf("eager parser name storage = %d, want UDP-only bound %d", got, want)
	}
	largeTCPResponse := make([]byte, 2048)
	binary.BigEndian.PutUint16(largeTCPResponse[6:8], 60)
	candidates, names := ns.adapter.parserScratchLocked(largeTCPResponse)
	if len(candidates) != 60 || len(names) != 120 || len(ns.adapter.candidates) != config.DNS.MaxResponseBytes/11 {
		t.Fatalf("temporary TCP parser scratch = candidates:%d names:%d eager:%d", len(candidates), len(names), len(ns.adapter.candidates))
	}
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	value, _, err := ns.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	query := value.(*dnsQuery)
	if query.tcpResponse != nil {
		t.Fatal("resolve eagerly allocated TCP fallback response storage")
	}
	if usage, _ := config.Quotas.Snapshot(); usage.QueuedBytes != baseRetained || usage.DNSWork != 2 {
		t.Fatalf("pre-fallback quota = %+v, want queued=%d work=2", usage, baseRetained)
	}
	outgoing := serviceDNSPacket(t, ns)
	txid, localPort := dnsPacketIdentity(t, outgoing)
	name := lnetodns.MustNewName(request.Name)
	truncated := buildDNSFrame(t, config, txid, localPort, lnetodns.Message{Questions: []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}}, lnetodns.HeaderFlags(1<<15|1<<9|1<<8|1<<7))
	serviceDNSIngressFrame(t, ns, truncated)
	if query.state != dnsQueryTCPConnecting || len(query.tcpResponse) != config.DNS.MaxTCPResponseBytes || query.tcpStream == nil {
		t.Fatalf("started fallback = state:%v response:%d stream:%T", query.state, len(query.tcpResponse), query.tcpStream)
	}
	if usage, _ := config.Quotas.Snapshot(); usage.QueuedBytes != baseRetained+tcpStorage || usage.DNSWork != 2 || usage.TCPResources != 1 {
		t.Fatalf("active fallback quota = %+v", usage)
	}
	if err := query.Cancel(); err != nil {
		t.Fatal(err)
	}
	if query.tcpResponse != nil || query.tcpStream != nil {
		t.Fatalf("canceled fallback retained response=%d stream=%T", len(query.tcpResponse), query.tcpStream)
	}
	if usage, _ := config.Quotas.Snapshot(); usage.QueuedBytes != baseRetained || usage.DNSWork != 0 || usage.TCPResources != 0 {
		t.Fatalf("canceled fallback quota = %+v, want only query retention", usage)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed fallback retained quota = %+v", usage)
	}
}

func TestDNSTCPFallbackHonorsRawTCPDenyWithoutLeakingTransport(t *testing.T) {
	config := dnsTestConfig(t, 62)
	config.MaxActiveTCPPorts = 2
	config.DNS.MaxTCPResponseBytes = 2048
	config.DNS.MaxTCPServiceAttempts = 32
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 8, TCPResources: 4, DNSResources: 4, QueuedBytes: 1 << 20, DNSWork: 8})
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDNS}, Directions: []policy.Direction{policy.DirectionOutbound}, DNSSuffixes: []string{"example.com"}},
		{Action: policy.ActionDeny, Transports: []policy.Transport{policy.TransportTCP}, Directions: []policy.Direction{policy.DirectionOutbound}, Prefixes: []netip.Prefix{netip.PrefixFrom(config.DNS.Server, 32)}, Ports: []policy.PortRange{{First: lnetodns.ServerPort, Last: lnetodns.ServerPort}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	config.Policy = compiled
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	value, _, err := ns.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	query := value.(*dnsQuery)
	outgoing := serviceDNSPacket(t, ns)
	txid, localPort := dnsPacketIdentity(t, outgoing)
	questionName := lnetodns.MustNewName(request.Name)
	truncatedMessage := lnetodns.Message{Questions: []lnetodns.Question{
		{Name: questionName, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: questionName, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}}
	truncated := buildDNSFrame(t, config, txid, localPort, truncatedMessage, lnetodns.HeaderFlags(1<<15|1<<9|1<<8|1<<7))
	serviceDNSIngressFrame(t, ns, truncated)
	if query.state != dnsQueryFailed || requireFailure(t, query.failure) != namespace.FailureAccessDenied || query.localPort != 0 || query.tcpStream != nil {
		t.Fatalf("denied fallback = state:%v failure:%v port:%d stream:%T", query.state, query.failure, query.localPort, query.tcpStream)
	}
	ns.core.Lock()
	leases := ns.core.TCPPortLeaseCountLocked()
	ns.core.Unlock()
	if leases != 0 {
		t.Fatalf("denied fallback retained %d TCP leases", leases)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("denied fallback retained quota = %+v", usage)
	}
}

func TestDNSTCPFallbackCancellationClosesPrivateStreamAndClearsRetention(t *testing.T) {
	config := dnsTestConfig(t, 63)
	config.MaxActiveTCPPorts = 2
	config.DNS.MaxTCPResponseBytes = 2048
	config.DNS.MaxTCPServiceAttempts = 32
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 8, TCPResources: 4, DNSResources: 4, QueuedBytes: 1 << 20, DNSWork: 8})
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	value, _, err := ns.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	query := value.(*dnsQuery)
	outgoing := serviceDNSPacket(t, ns)
	txid, localPort := dnsPacketIdentity(t, outgoing)
	name := lnetodns.MustNewName(request.Name)
	truncated := buildDNSFrame(t, config, txid, localPort, lnetodns.Message{Questions: []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}}, lnetodns.HeaderFlags(1<<15|1<<9|1<<8|1<<7))
	serviceDNSIngressFrame(t, ns, truncated)
	if query.state != dnsQueryTCPConnecting || query.tcpStream == nil {
		t.Fatalf("fallback before cancel = state:%v stream:%T", query.state, query.tcpStream)
	}
	if err := query.Cancel(); err != nil {
		t.Fatal(err)
	}
	if query.state != dnsQueryFailed || requireFailure(t, query.failure) != namespace.FailureCanceled || query.tcpStream != nil || query.txid != 0 {
		t.Fatalf("canceled fallback = state:%v failure:%v stream:%T txid:%d", query.state, query.failure, query.tcpStream, query.txid)
	}
	if !bytes.Equal(query.tcpResponse, make([]byte, len(query.tcpResponse))) {
		t.Fatal("canceled fallback retained response bytes")
	}
	ns.core.Lock()
	leases := ns.core.TCPPortLeaseCountLocked()
	ns.core.Unlock()
	if leases != 0 {
		t.Fatalf("canceled fallback retained %d TCP leases", leases)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("canceled fallback retained quota = %+v", usage)
	}
}

func TestDNSTCPFallbackBoundsLengthTimeoutAndEOFCleanup(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*dnsQuery, *scriptedLockedTCPStream)
		want    namespace.Failure
	}{
		{
			name: "oversized response",
			prepare: func(query *dnsQuery, stream *scriptedLockedTCPStream) {
				query.state = dnsQueryTCPReadingLength
				stream.reads = [][]byte{{0x08, 0x01}}
			},
			want: namespace.FailureMessageTooLarge,
		},
		{
			name: "service timeout",
			prepare: func(query *dnsQuery, _ *scriptedLockedTCPStream) {
				query.state = dnsQueryTCPConnecting
				query.tcpServiceAttempts = query.owner.config.MaxTCPServiceAttempts
			},
			want: namespace.FailureTimedOut,
		},
		{
			name: "premature EOF",
			prepare: func(query *dnsQuery, stream *scriptedLockedTCPStream) {
				query.state = dnsQueryTCPReadingLength
				stream.eof = true
			},
			want: namespace.FailureTemporary,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &scriptedLockedTCPStream{}
			query := &dnsQuery{
				owner:     &Adapter{config: Config{MaxTCPResponseBytes: 2048, MaxTCPServiceAttempts: 4}},
				tcpStream: stream, tcpResponse: make([]byte, 2048), txid: 1,
			}
			test.prepare(query, stream)
			if err := query.serviceTCPFallbackLocked(); err != nil {
				t.Fatal(err)
			}
			if query.state != dnsQueryFailed || requireFailure(t, query.failure) != test.want || query.tcpStream != nil || stream.closeCalls != 1 {
				t.Fatalf("bounded fallback = state:%v failure:%v stream:%T closes:%d", query.state, query.failure, query.tcpStream, stream.closeCalls)
			}
			if !bytes.Equal(query.tcpResponse, make([]byte, len(query.tcpResponse))) {
				t.Fatal("failed fallback retained response bytes")
			}
		})
	}
}

type scriptedLockedTCPStream struct {
	reads      [][]byte
	eof        bool
	closeCalls int
}

func (stream *scriptedLockedTCPStream) TryFinishConnectLocked() (namespace.Progress, error) {
	return namespace.ProgressInProgress, nil
}

func (stream *scriptedLockedTCPStream) TryReadLocked(dst []byte) (namespace.IOResult, error) {
	if len(stream.reads) != 0 {
		value := stream.reads[0]
		stream.reads = stream.reads[1:]
		count := copy(dst, value)
		return namespace.IOResult{Bytes: count, State: namespace.IOReady}, nil
	}
	if stream.eof {
		return namespace.IOResult{State: namespace.IOEOF}, nil
	}
	return namespace.IOResult{State: namespace.IOWouldBlock}, nil
}

func (stream *scriptedLockedTCPStream) TryWriteLocked([]byte) (namespace.IOResult, error) {
	return namespace.IOResult{State: namespace.IOWouldBlock}, nil
}

func (stream *scriptedLockedTCPStream) CloseLocked() error {
	stream.closeCalls++
	return nil
}

func TestBuildDNSQueryPacketIntoUsesCallerStorage(t *testing.T) {
	request := namespace.DNSRequest{Name: "service.api.example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	var storage [dnsQueryPacketCapacity]byte
	for i := range storage {
		storage[i] = 0xff
	}
	packet, err := buildDNSQueryPacketInto(storage[:], request, 0x5678, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) == 0 || &packet[0] != &storage[0] {
		t.Fatal("query packet did not retain caller-owned storage")
	}
	frame, err := lnetodns.NewFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if frame.TxID() != 0x5678 || frame.QDCount() != 2 || frame.ARCount() != 1 {
		t.Fatalf("query header = txid=%x counts=%d/%d", frame.TxID(), frame.QDCount(), frame.ARCount())
	}
	if _, err := buildDNSQueryPacketInto(storage[:len(packet)-1], request, 1, 512); !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short storage error = %v", err)
	}
}

func TestBuildDNSQueryPacketIntoFitsMaximumCanonicalName(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	request := namespace.DNSRequest{Name: name, Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	if !request.Valid() || len(name) != 253 {
		t.Fatalf("maximum request validity = %v, length=%d", request.Valid(), len(name))
	}
	var storage [dnsQueryPacketCapacity]byte
	packet, err := buildDNSQueryPacketInto(storage[:], request, 0xabcd, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != len(storage) || &packet[0] != &storage[0] {
		t.Fatalf("maximum packet length = %d, capacity=%d", len(packet), len(storage))
	}
	frame, err := lnetodns.NewFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateDNSQuestions(packet, lnetodns.SizeHeader, frame.QDCount(), request); err != nil {
		t.Fatal(err)
	}
}

func TestDNSNameInterningReusesRequestAndBoundedScratch(t *testing.T) {
	storage := make([]string, 1)
	count := 0
	request := "example.com"
	name, err := internDNSName([]byte(request), request, storage, &count)
	if err != nil || name != request || count != 0 {
		t.Fatalf("request intern = %q, count=%d, err=%v", name, count, err)
	}
	first, err := internDNSName([]byte("alias.example.com"), request, storage, &count)
	if err != nil || count != 1 {
		t.Fatalf("first alias intern = %q, count=%d, err=%v", first, count, err)
	}
	second, err := internDNSName([]byte("alias.example.com"), request, storage, &count)
	if err != nil || second != first || count != 1 {
		t.Fatalf("reused alias intern = %q, count=%d, err=%v", second, count, err)
	}
	if _, err := internDNSName([]byte("other.example.com"), request, storage, &count); err == nil {
		t.Fatal("bounded name scratch accepted a second unique name")
	}
}

func TestEgressShortBufferPreservesRoundRobinStateAndPendingQueries(t *testing.T) {
	config := dnsTestConfig(t, 74)
	ns := newTestNamespace(t, config)
	firstRequest := namespace.DNSRequest{Name: "first.example.com", Types: namespace.DNSRecordsA}
	secondRequest := namespace.DNSRequest{Name: "second.example.com", Types: namespace.DNSRecordsAAAA}
	firstResource, _, err := ns.TryResolve(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondResource, _, err := ns.TryResolve(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	first := firstResource.(*dnsQuery)
	second := secondResource.(*dnsQuery)
	firstPacket := append([]byte(nil), first.packet...)
	secondPacket := append([]byte(nil), second.packet...)
	usageBefore, _ := config.Quotas.Snapshot()
	firstReady, secondReady := first.Readiness(), second.Readiness()
	short := bytes.Repeat([]byte{0xa5}, 14+20+8+len(first.packet)-1)

	ns.core.Lock()
	written, worked, err := ns.adapter.egressLocked(short)
	cursor := ns.adapter.cursor
	ns.core.Unlock()
	if written != 0 || worked || !errors.Is(err, lneto.ErrShortBuffer) {
		t.Fatalf("short egress = %d, %v, %v", written, worked, err)
	}
	if !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, len(short))) {
		t.Fatalf("short egress mutated destination = %x", short)
	}
	if cursor != 0 || first.state != dnsQueryPending || second.state != dnsQueryPending || first.attempts != 0 || second.attempts != 0 || first.retry != 0 || second.retry != 0 || !bytes.Equal(first.packet, firstPacket) || !bytes.Equal(second.packet, secondPacket) {
		t.Fatalf("short egress mutated scheduler or queries: cursor=%d first=%v/%d/%d second=%v/%d/%d", cursor, first.state, first.attempts, first.retry, second.state, second.attempts, second.retry)
	}
	if first.Readiness() != firstReady || second.Readiness() != secondReady {
		t.Fatalf("short egress changed readiness: first=%v/%v second=%v/%v", first.Readiness(), firstReady, second.Readiness(), secondReady)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != usageBefore {
		t.Fatalf("short egress changed quota = %+v, want %+v", usage, usageBefore)
	}

	frame := make([]byte, ns.Link().MaxFrameBytes())
	ns.core.Lock()
	firstBytes, firstWorked, err := ns.adapter.egressLocked(frame)
	cursorAfterFirst := ns.adapter.cursor
	ns.core.Unlock()
	if err != nil || !firstWorked || firstBytes == 0 || cursorAfterFirst != 1 {
		t.Fatalf("first retry = %d, %v, %v, cursor=%d", firstBytes, firstWorked, err, cursorAfterFirst)
	}
	firstIP, err := ipv4.NewFrame(frame[14:firstBytes])
	if err != nil {
		t.Fatal(err)
	}
	firstTxID, firstPort := dnsPacketIdentity(t, frame[:firstBytes])
	if firstIP.ID() != 75 || firstTxID != first.txid || firstPort != first.localPort {
		t.Fatalf("first retry frame = id=%d txid=%d port=%d", firstIP.ID(), firstTxID, firstPort)
	}

	ns.core.Lock()
	secondBytes, secondWorked, err := ns.adapter.egressLocked(frame)
	cursorAfterSecond := ns.adapter.cursor
	ns.core.Unlock()
	if err != nil || !secondWorked || secondBytes == 0 || cursorAfterSecond != 0 {
		t.Fatalf("second egress = %d, %v, %v, cursor=%d", secondBytes, secondWorked, err, cursorAfterSecond)
	}
	secondIP, err := ipv4.NewFrame(frame[14:secondBytes])
	if err != nil {
		t.Fatal(err)
	}
	secondTxID, secondPort := dnsPacketIdentity(t, frame[:secondBytes])
	if secondIP.ID() != 76 || secondTxID != second.txid || secondPort != second.localPort {
		t.Fatalf("second frame = id=%d txid=%d port=%d", secondIP.ID(), secondTxID, secondPort)
	}
}

func TestDNSBoundedQueryRecordsAndQuotaLifecycle(t *testing.T) {
	config := dnsTestConfig(t, 41)
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	resource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress || resource == nil {
		t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
	}
	query := resource.(*dnsQuery)
	if len(query.packet) == 0 || &query.packet[0] != &query.packetStorage[0] {
		t.Fatal("live query packet does not use embedded storage")
	}
	if cap(query.records) != int(config.DNS.MaxRecords) || cap(query.records) > len(query.recordStorage) {
		t.Fatalf("live query records capacity = %d", cap(query.records))
	}
	if got := query.Readiness(); got != 0 {
		t.Fatalf("initial readiness = %v", got)
	}
	if _, next, err := query.TryNext(); err != nil || next != namespace.DNSNextWouldBlock {
		t.Fatalf("initial next = %v, %v", next, err)
	}
	usage, closed := config.Quotas.Snapshot()
	if closed || usage.Resources != 1 || usage.DNSResources != 1 || usage.DNSWork != 2 || usage.QueuedBytes != dnsRetainedBytes(config.DNS) {
		t.Fatalf("in-flight quota = %+v, closed=%v", usage, closed)
	}

	outgoing := serviceDNSPacket(t, ns)
	txid, localPort := dnsPacketIdentity(t, outgoing)
	response := buildDNSResponseFrame(t, config, txid, localPort, request.Name)
	if err := ns.Link().TryEnqueue(packetlink.Ingress, response); err != nil {
		t.Fatal(err)
	}
	setNextIngress(ns, true)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report != (namespace.ServiceReport{Packets: 1, Bytes: uint32(len(response)), Operations: 1}) {
		t.Fatalf("response service = %+v, %v, %v", report, progress, err)
	}
	if got := query.Readiness(); got != namespace.ReadyDNSResult {
		t.Fatalf("completed readiness = %v", got)
	}

	want := []namespace.DNSRecord{
		{Name: "example.com", Type: namespace.DNSRecordCNAME, TTLSeconds: 60, CanonicalName: "canonical.example.com"},
		{Name: "canonical.example.com", Type: namespace.DNSRecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.99")},
		{Name: "canonical.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 180, Address: netip.MustParseAddr("2001:db8::99")},
	}
	for i, expected := range want {
		record, next, err := query.TryNext()
		if err != nil || next != namespace.DNSNextReady || record != expected {
			t.Fatalf("record %d = %+v, %v, %v; want %+v", i, record, next, err, expected)
		}
	}
	if _, next, err := query.TryNext(); err != nil || next != namespace.DNSNextEOF {
		t.Fatalf("EOF = %v, %v", next, err)
	}
	usage, _ = config.Quotas.Snapshot()
	if usage.DNSWork != 0 || usage.Resources != 1 || usage.DNSResources != 1 || usage.QueuedBytes == 0 {
		t.Fatalf("completed quota = %+v", usage)
	}
	workReset := query.work.ResetReleased()
	if workReset {
		t.Fatalf("completed query retained work graph state: reset=%v", workReset)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("closed query retained quota = %+v", usage)
	}
	retainedReset := query.retained.ResetReleased()
	workReset = query.work.ResetReleased()
	if retainedReset || workReset || query.request != (namespace.DNSRequest{}) || query.packet != nil || query.records != nil || query.failure != nil || query.cursor != 0 {
		t.Fatalf("closed query retained graph state: retained_reset=%v work_reset=%v request=%+v packet=%v records=%v failure=%v cursor=%d", retainedReset, workReset, query.request, query.packet != nil, query.records != nil, query.failure, query.cursor)
	}
	if got := query.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed readiness = %v", got)
	}
}

func TestResolveCloseReusesOverflowRecordBacking(t *testing.T) {
	config := dnsTestConfig(t, 41)
	config.DNS.MaxQueries = 1
	config.DNS.MaxRecords = inlineDNSRecordCapacity + 1
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	allocs := testing.AllocsPerRun(1000, func() {
		value, progress, err := ns.TryResolve(request)
		if err != nil || progress != namespace.ProgressInProgress {
			panic(err)
		}
		if err := value.Close(); err != nil {
			panic(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("resolve/close allocations = %v, want <= 1", allocs)
	}
}

func TestDNSRetryTimeoutPolicyLimitsAndReuse(t *testing.T) {
	config := dnsTestConfig(t, 42)
	config.DNS.MaxQueries = 1
	config.DNS.MaxAttempts = 2
	config.DNS.RetryServiceAttempts = 1
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	resource, _, err := ns.TryResolve(request)
	if err != nil {
		t.Fatal(err)
	}
	query := resource.(*dnsQuery)
	if _, _, err := ns.TryResolve(request); requireFailure(t, err) != namespace.FailureResourceLimit {
		t.Fatalf("second query error = %v", err)
	}
	if _, _, err := ns.TryResolve(namespace.DNSRequest{Name: "denied.example", Types: namespace.DNSRecordsA}); requireFailure(t, err) != namespace.FailureAccessDenied {
		t.Fatalf("denied query error = %v", err)
	}

	_ = serviceDNSPacket(t, ns)
	maintenance := serviceDNSMaintenance(t, ns)
	if maintenance != (namespace.ServiceReport{Operations: 1}) {
		t.Fatalf("retry maintenance = %+v", maintenance)
	}
	_ = serviceDNSPacket(t, ns)
	maintenance = serviceDNSMaintenance(t, ns)
	if maintenance != (namespace.ServiceReport{Operations: 1}) {
		t.Fatalf("timeout maintenance = %+v", maintenance)
	}
	if got := query.Readiness(); got != namespace.ReadyError {
		t.Fatalf("timeout readiness = %v", got)
	}
	if _, _, err := query.TryNext(); requireFailure(t, err) != namespace.FailureTimedOut {
		t.Fatalf("timeout result error = %v", err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage.DNSWork != 0 || usage.DNSResources != 1 {
		t.Fatalf("timeout quota = %+v", usage)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	reusedResource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress || reusedResource == query {
		t.Fatalf("query reuse = %T, %v, %v", reusedResource, progress, err)
	}
	reused := reusedResource.(*dnsQuery)
	if err := reused.Cancel(); err != nil {
		t.Fatal(err)
	}
	if got := reused.Readiness(); got != namespace.ReadyError {
		t.Fatalf("canceled readiness = %v", got)
	}
	if _, _, err := reused.TryNext(); requireFailure(t, err) != namespace.FailureCanceled {
		t.Fatalf("canceled result error = %v", err)
	}
	if usage, _ := config.Quotas.Snapshot(); usage.DNSWork != 0 || usage.DNSResources != 1 {
		t.Fatalf("canceled quota = %+v", usage)
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSIngressRequiresLocalEthernetDestinationAndValidSource(t *testing.T) {
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
			config := dnsTestConfig(t, 46)
			ns := newTestNamespace(t, config)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
			resource, progress, err := ns.TryResolve(request)
			if err != nil || progress != namespace.ProgressInProgress {
				t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
			}
			query := resource.(*dnsQuery)
			outgoing := serviceDNSPacket(t, ns)
			txid, localPort := dnsPacketIdentity(t, outgoing)
			response := buildDNSResponseFrame(t, config, txid, localPort, request.Name)
			ethernetFrame, err := ethernet.NewFrame(response)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&ethernetFrame)

			ns.core.Lock()
			handled, err := ns.adapter.ingressLocked(response)
			ns.core.Unlock()
			if err != nil || handled != test.wantHandled {
				t.Fatalf("ingress = handled %v, err %v; want handled %v", handled, err, test.wantHandled)
			}
			if query.state != dnsQueryWaiting || query.Readiness() != 0 || len(query.records) != 0 || ns.adapter.byPort[localPort] != query {
				t.Fatalf("foreign L2 frame mutated query: state=%v readiness=%v records=%d mapped=%v", query.state, query.Readiness(), len(query.records), ns.adapter.byPort[localPort] == query)
			}
		})
	}
}

func TestDNSIngressDropsInvalidIPv4LengthsWithoutMutatingQuery(t *testing.T) {
	for _, test := range []struct {
		name        string
		totalLength uint16
		headerWords uint8
	}{
		{name: "shorter than header", totalLength: 19},
		{name: "beyond frame", totalLength: 1501},
		{name: "header beyond total length", totalLength: 59, headerWords: 15},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := dnsTestConfig(t, 47)
			ns := newTestNamespace(t, config)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
			resource, progress, err := ns.TryResolve(request)
			if err != nil || progress != namespace.ProgressInProgress {
				t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
			}
			query := resource.(*dnsQuery)
			outgoing := serviceDNSPacket(t, ns)
			txid, localPort := dnsPacketIdentity(t, outgoing)
			valid := buildDNSResponseFrame(t, config, txid, localPort, request.Name)
			malformed := append([]byte(nil), valid...)
			ethernetFrame, err := ethernet.NewFrame(malformed)
			if err != nil {
				t.Fatal(err)
			}
			ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
			if err != nil {
				t.Fatal(err)
			}
			if test.headerWords != 0 {
				ipFrame.SetVersionAndIHL(4, test.headerWords)
			}
			ipFrame.SetTotalLength(test.totalLength)
			ipFrame.SetCRC(0)
			ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())

			var handled bool
			var ingressErr error
			var state dnsQueryState
			var mapped *dnsQuery
			func() {
				ns.core.Lock()
				defer ns.core.Unlock()
				handled, ingressErr = ns.adapter.ingressLocked(malformed)
				state = query.state
				mapped = ns.adapter.byPort[localPort]
			}()
			if ingressErr != nil || handled || state != dnsQueryWaiting || mapped != query || query.Readiness() != 0 {
				t.Fatalf("malformed response = handled:%v err:%v state:%v mapped:%p readiness:%v", handled, ingressErr, state, mapped, query.Readiness())
			}

			ns.core.Lock()
			handled, ingressErr = ns.adapter.ingressLocked(valid)
			ns.core.Unlock()
			if ingressErr != nil || !handled || query.state != dnsQueryDone || query.Readiness() != namespace.ReadyDNSResult {
				t.Fatalf("valid ingress after malformed length = handled:%v err:%v state:%v readiness:%v", handled, ingressErr, query.state, query.Readiness())
			}
		})
	}
}

func TestDNSIngressDropsMalformedCorrelatedTransportAndAcceptsFollowingValidResponse(t *testing.T) {
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
			name: "fragmented IPv4",
			mutate: func(t *testing.T, frame []byte) {
				ethernetFrame, err := ethernet.NewFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				ipFrame.SetFlags(ipv4.FlagMoreFragments)
				ipFrame.SetCRC(0)
				ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
			},
		},
		{
			name: "bad UDP checksum",
			mutate: func(t *testing.T, frame []byte) {
				ethernetFrame, err := ethernet.NewFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				udpFrame.Payload()[len(udpFrame.Payload())-1] ^= 1
			},
		},
		{
			name: "short UDP length",
			mutate: func(t *testing.T, frame []byte) {
				ethernetFrame, err := ethernet.NewFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				udpFrame.SetLength(7)
			},
		},
		{
			name: "trailing IPv4 payload outside UDP datagram",
			mutate: func(t *testing.T, frame []byte) {
				ethernetFrame, err := ethernet.NewFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				ipFrame, err := ipv4.NewFrame(ethernetFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
				if err != nil {
					t.Fatal(err)
				}
				udpFrame.SetLength(udpFrame.Length() - 1)
				udpFrame.SetCRC(0)
				var checksum lneto.CRC791
				ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
				udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := dnsTestConfig(t, 47)
			ns := newTestNamespace(t, config)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
			resource, progress, err := ns.TryResolve(request)
			if err != nil || progress != namespace.ProgressInProgress {
				t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
			}
			query := resource.(*dnsQuery)
			outgoing := serviceDNSPacket(t, ns)
			txid, localPort := dnsPacketIdentity(t, outgoing)
			valid := buildDNSResponseFrame(t, config, txid, localPort, request.Name)
			malformed := append([]byte(nil), valid...)
			test.mutate(t, malformed)

			ns.core.Lock()
			handled, err := ns.adapter.ingressLocked(malformed)
			ns.core.Unlock()
			if err != nil || !handled {
				t.Fatalf("malformed ingress = handled %v, err %v", handled, err)
			}
			if query.state != dnsQueryWaiting || query.Readiness() != 0 || len(query.records) != 0 || ns.adapter.byPort[localPort] != query {
				t.Fatalf("malformed transport terminalized query: state=%v readiness=%v records=%d mapped=%v", query.state, query.Readiness(), len(query.records), ns.adapter.byPort[localPort] == query)
			}

			ns.core.Lock()
			handled, err = ns.adapter.ingressLocked(valid)
			ns.core.Unlock()
			if err != nil || !handled || query.state != dnsQueryDone || query.Readiness() != namespace.ReadyDNSResult {
				t.Fatalf("valid ingress after malformed = handled %v, err %v, state=%v readiness=%v", handled, err, query.state, query.Readiness())
			}
		})
	}
}

func TestDNSTerminalCompletionRetiresTransportAndIgnoresLateResponses(t *testing.T) {
	config := dnsTestConfig(t, 44)
	ns := newTestNamespace(t, config)
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	resource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
	}
	query := resource.(*dnsQuery)
	outgoing := serviceDNSPacket(t, ns)
	txid, localPort := dnsPacketIdentity(t, outgoing)
	serviceDNSIngressFrame(t, ns, buildDNSResponseFrame(t, config, txid, localPort, request.Name))
	if query.state != dnsQueryDone || query.Readiness() != namespace.ReadyDNSResult {
		t.Fatalf("completion state = %v, readiness=%v", query.state, query.Readiness())
	}
	ns.core.Lock()
	leaseCount := ns.core.UDPPortLeaseCountLocked()
	stillMapped := ns.adapter.byPort[localPort] != nil
	ns.core.Unlock()
	if leaseCount != 0 || stillMapped || query.localPort != 0 || query.portLease.UDPPort() != 0 {
		t.Fatalf("completion transport retained lease=%d mapped=%v local_port=%d lease_port=%d", leaseCount, stillMapped, query.localPort, query.portLease.UDPPort())
	}
	before := append([]namespace.DNSRecord(nil), query.records...)
	serviceDNSIngressFrame(t, ns, buildDNSResponseFrameWithRecords(t, config, txid, localPort, request.Name, []namespace.DNSRecord{{
		Name: "example.com", Type: namespace.DNSRecordA, TTLSeconds: 1, Address: netip.MustParseAddr("192.0.2.1"),
	}}))
	if !reflect.DeepEqual(query.records, before) {
		t.Fatalf("late response mutated committed records: got %+v want %+v", query.records, before)
	}
	first, next, err := query.TryNext()
	if err != nil || next != namespace.DNSNextReady || first != before[0] {
		t.Fatalf("first record = %+v, %v, %v; want %+v", first, next, err, before[0])
	}
	serviceDNSIngressFrame(t, ns, buildDNSResponseFrameWithRecords(t, config, txid, localPort, request.Name, []namespace.DNSRecord{{
		Name: "example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 1, Address: netip.MustParseAddr("2001:db8::1"),
	}}))
	for i, want := range before[1:] {
		record, next, err := query.TryNext()
		if err != nil || next != namespace.DNSNextReady || record != want {
			t.Fatalf("remaining record %d = %+v, %v, %v; want %+v", i, record, next, err, want)
		}
	}
	if _, next, err := query.TryNext(); err != nil || next != namespace.DNSNextEOF {
		t.Fatalf("EOF = %v, %v", next, err)
	}
	ns.adapter.nextPort = localPort
	reusedResource, progress, err := ns.TryResolve(request)
	if err != nil || progress != namespace.ProgressInProgress {
		t.Fatalf("reused resolve = %T, %v, %v", reusedResource, progress, err)
	}
	reused := reusedResource.(*dnsQuery)
	if reused.localPort != localPort {
		t.Fatalf("reused local port = %d, want %d", reused.localPort, localPort)
	}
	serviceDNSIngressFrame(t, ns, buildDNSResponseFrameWithRecords(t, config, txid, localPort, request.Name, []namespace.DNSRecord{{
		Name: "example.com", Type: namespace.DNSRecordA, TTLSeconds: 1, Address: netip.MustParseAddr("192.0.2.7"),
	}}))
	if reused.state != dnsQueryPending || reused.Readiness() != 0 || len(reused.records) != 0 || ns.adapter.byPort[localPort] != reused {
		t.Fatalf("late reused-port response mutated fresh query: state=%v readiness=%v records=%d mapped=%v", reused.state, reused.Readiness(), len(reused.records), ns.adapter.byPort[localPort] == reused)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	if err := query.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
	if ns.adapter.byPort[localPort] != reused {
		t.Fatalf("stale close disturbed fresh query: mapped=%p", ns.adapter.byPort[localPort])
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSTerminalFailuresRetireTransportImmediately(t *testing.T) {
	for _, test := range []struct {
		name        string
		expected    namespace.Failure
		prepare     func(*testing.T, *testNamespace, *dnsQuery, namespaceTestConfig)
		terminalize func(*testing.T, *testNamespace, *dnsQuery, namespaceTestConfig)
	}{
		{
			name:     "canceled",
			expected: namespace.FailureCanceled,
			terminalize: func(t *testing.T, _ *testNamespace, query *dnsQuery, _ namespaceTestConfig) {
				if err := query.Cancel(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:     "timed out",
			expected: namespace.FailureTimedOut,
			prepare: func(t *testing.T, ns *testNamespace, _ *dnsQuery, _ namespaceTestConfig) {
				_ = serviceDNSPacket(t, ns)
				if report := serviceDNSMaintenance(t, ns); report != (namespace.ServiceReport{Operations: 1}) {
					t.Fatalf("retry maintenance = %+v", report)
				}
				_ = serviceDNSPacket(t, ns)
			},
			terminalize: func(t *testing.T, ns *testNamespace, _ *dnsQuery, _ namespaceTestConfig) {
				if report := serviceDNSMaintenance(t, ns); report != (namespace.ServiceReport{Operations: 1}) {
					t.Fatalf("timeout maintenance = %+v", report)
				}
			},
		},
		{
			name:     "parser failure",
			expected: namespace.FailureIO,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := dnsTestConfig(t, 45)
			config.DNS.MaxQueries = 1
			config.DNS.MaxAttempts = 2
			config.DNS.RetryServiceAttempts = 1
			ns := newTestNamespace(t, config)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
			resource, progress, err := ns.TryResolve(request)
			if err != nil || progress != namespace.ProgressInProgress {
				t.Fatalf("resolve = %T, %v, %v", resource, progress, err)
			}
			query := resource.(*dnsQuery)
			localPort := query.localPort
			if test.prepare != nil {
				test.prepare(t, ns, query, config)
			}
			if test.name == "parser failure" {
				outgoing := serviceDNSPacket(t, ns)
				txid, destinationPort := dnsPacketIdentity(t, outgoing)
				message := lnetodns.Message{Questions: []lnetodns.Question{{Name: lnetodns.MustNewName(request.Name), Type: lnetodns.TypeA, Class: lnetodns.ClassINET}}}
				serviceDNSIngressFrame(t, ns, buildDNSFrame(t, config, txid, destinationPort, message, lnetodns.HeaderFlags(1<<15)))
			} else {
				test.terminalize(t, ns, query, config)
			}
			if got := query.Readiness(); got != namespace.ReadyError {
				t.Fatalf("terminal readiness = %v", got)
			}
			ns.core.Lock()
			leaseCount := ns.core.UDPPortLeaseCountLocked()
			stillMapped := ns.adapter.byPort[localPort] != nil
			ns.core.Unlock()
			if leaseCount != 0 || stillMapped || query.localPort != 0 || query.portLease.UDPPort() != 0 {
				t.Fatalf("terminal transport retained lease=%d mapped=%v local_port=%d lease_port=%d", leaseCount, stillMapped, query.localPort, query.portLease.UDPPort())
			}
			if _, _, err := query.TryNext(); requireFailure(t, err) != test.expected {
				t.Fatalf("terminal failure = %v, want %v", err, test.expected)
			}
			if err := query.Close(); err != nil {
				t.Fatal(err)
			}
			if err := query.Close(); err != nil {
				t.Fatalf("second close = %v", err)
			}
		})
	}
}

func TestDNSTerminalFailuresIsolateForcedPortReuseAndStaleClose(t *testing.T) {
	for _, test := range []struct {
		name        string
		terminalize func(*testing.T, *testNamespace, *dnsQuery, namespaceTestConfig, []byte)
	}{
		{
			name: "cancel",
			terminalize: func(t *testing.T, _ *testNamespace, query *dnsQuery, _ namespaceTestConfig, _ []byte) {
				if err := query.Cancel(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "timeout",
			terminalize: func(t *testing.T, ns *testNamespace, _ *dnsQuery, _ namespaceTestConfig, _ []byte) {
				if report := serviceDNSMaintenance(t, ns); report != (namespace.ServiceReport{Operations: 1}) {
					t.Fatalf("timeout maintenance = %+v", report)
				}
			},
		},
		{
			name: "parser failure",
			terminalize: func(t *testing.T, ns *testNamespace, _ *dnsQuery, config namespaceTestConfig, outgoing []byte) {
				txid, localPort := dnsPacketIdentity(t, outgoing)
				requestName := lnetodns.MustNewName("example.com")
				message := lnetodns.Message{Questions: []lnetodns.Question{{Name: requestName, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}}}
				serviceDNSIngressFrame(t, ns, buildDNSFrame(t, config, txid, localPort, message, lnetodns.HeaderFlags(1<<15)))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := dnsTestConfig(t, 48)
			config.DNS.MaxQueries = 2
			config.DNS.MaxAttempts = 1
			config.DNS.RetryServiceAttempts = 1
			ns := newTestNamespace(t, config)
			request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
			resource, _, err := ns.TryResolve(request)
			if err != nil {
				t.Fatal(err)
			}
			stale := resource.(*dnsQuery)
			outgoing := serviceDNSPacket(t, ns)
			staleTxID, stalePort := dnsPacketIdentity(t, outgoing)
			staleResponse := buildDNSResponseFrame(t, config, staleTxID, stalePort, request.Name)
			test.terminalize(t, ns, stale, config, outgoing)
			if stale.state != dnsQueryFailed || stale.Readiness() != namespace.ReadyError || stale.localPort != 0 || stale.portLease.UDPPort() != 0 || ns.adapter.byPort[stalePort] != nil {
				t.Fatalf("terminal transport = state:%v readiness:%v local:%d lease:%d mapped:%p", stale.state, stale.Readiness(), stale.localPort, stale.portLease.UDPPort(), ns.adapter.byPort[stalePort])
			}

			ns.adapter.nextPort = stalePort
			resource, _, err = ns.TryResolve(request)
			if err != nil {
				t.Fatal(err)
			}
			fresh := resource.(*dnsQuery)
			if fresh.localPort != stalePort || fresh.txid == staleTxID || ns.adapter.byPort[stalePort] != fresh {
				t.Fatalf("forced port reuse = port:%d txid:%d/%d mapped:%p", fresh.localPort, staleTxID, fresh.txid, ns.adapter.byPort[stalePort])
			}
			ns.core.Lock()
			handled, ingressErr := ns.adapter.ingressLocked(staleResponse)
			ns.core.Unlock()
			if ingressErr != nil || !handled || fresh.state != dnsQueryPending || fresh.Readiness() != 0 || len(fresh.records) != 0 || ns.adapter.byPort[stalePort] != fresh {
				t.Fatalf("stale response on reused port = handled:%v err:%v state:%v readiness:%v records:%d mapped:%p", handled, ingressErr, fresh.state, fresh.Readiness(), len(fresh.records), ns.adapter.byPort[stalePort])
			}
			if err := stale.Close(); err != nil {
				t.Fatal(err)
			}
			if ns.adapter.byPort[stalePort] != fresh || fresh.localPort != stalePort {
				t.Fatalf("stale close affected fresh transport: mapped=%p port=%d", ns.adapter.byPort[stalePort], fresh.localPort)
			}
			if usage, closed := config.Quotas.Snapshot(); closed || usage.Resources != 1 || usage.DNSResources != 1 || usage.DNSWork != 2 || usage.QueuedBytes != dnsRetainedBytes(config.DNS) {
				t.Fatalf("fresh quota after stale close = %+v, closed=%v", usage, closed)
			}

			freshOutgoing := serviceDNSPacket(t, ns)
			freshTxID, freshPort := dnsPacketIdentity(t, freshOutgoing)
			serviceDNSIngressFrame(t, ns, buildDNSResponseFrame(t, config, freshTxID, freshPort, request.Name))
			if fresh.state != dnsQueryDone || fresh.Readiness() != namespace.ReadyDNSResult {
				t.Fatalf("fresh completion = state:%v readiness:%v", fresh.state, fresh.Readiness())
			}
			if err := fresh.Close(); err != nil {
				t.Fatal(err)
			}
			if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
				t.Fatalf("closed quota = %+v", usage)
			}
		})
	}
}

func TestDNSResponseFailureMappingAndRecordBound(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	name := lnetodns.MustNewName(request.Name)
	for _, test := range []struct {
		name    string
		flags   lnetodns.HeaderFlags
		answers []lnetodns.Resource
		limit   int
		want    namespace.Failure
	}{
		{name: "not found", flags: lnetodns.HeaderFlags(1<<15) | lnetodns.HeaderFlags(lnetodns.RCodeNameError), limit: 1, want: namespace.FailureNameNotFound},
		{name: "truncated", flags: lnetodns.HeaderFlags(1<<15 | 1<<9), limit: 1, want: namespace.FailureTemporary},
		{name: "record limit", flags: lnetodns.HeaderFlags(1 << 15), answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
			lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 2}),
		}, limit: 1, want: namespace.FailureResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := lnetodns.Message{Questions: []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}}, Answers: test.answers}
			payload, err := message.AppendTo(nil, 7, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			_, response, failure, err := parseDNSResponse(payload, 7, request, test.limit)
			if !response || err == nil || failure != test.want {
				t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
			}
		})
	}
}

func TestDNSResponseRequiresExactEchoedQuestions(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	name := lnetodns.MustNewName(request.Name)
	valid := []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}
	other := lnetodns.MustNewName("other.example.com")
	for _, test := range []struct {
		name      string
		questions []lnetodns.Question
		flags     lnetodns.HeaderFlags
	}{
		{name: "missing type", questions: valid[:1], flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "extra type", questions: append(append([]lnetodns.Question(nil), valid...), valid[0]), flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong name", questions: []lnetodns.Question{{Name: other, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}, valid[1]}, flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong order", questions: []lnetodns.Question{valid[1], valid[0]}, flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong class", questions: []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassCHAOS}, valid[1]}, flags: lnetodns.HeaderFlags(1 << 15)},
		{name: "wrong opcode", questions: valid, flags: lnetodns.HeaderFlags(1<<15) | lnetodns.HeaderFlags(lnetodns.OpCodeStatus<<11)},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := (&lnetodns.Message{Questions: test.questions}).AppendTo(nil, 11, test.flags)
			if err != nil {
				t.Fatal(err)
			}
			_, response, failure, err := parseDNSResponse(payload, 11, request, 8)
			if !response || failure != namespace.FailureIO || err == nil {
				t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
			}
		})
	}
}

func TestDNSResponseSelectsUniqueReachableChainAndRequestedTypes(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	name := lnetodns.MustNewName(request.Name)
	alias := lnetodns.MustNewName("alias.example.com")
	terminal := lnetodns.MustNewName("terminal.example.com")
	unrelated := lnetodns.MustNewName("unrelated.example.com")
	aliasData, _ := alias.AppendTo(nil)
	terminalData, _ := terminal.AppendTo(nil)
	message := lnetodns.Message{
		Questions: []lnetodns.Question{
			{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
			{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
		},
		Answers: []lnetodns.Resource{
			lnetodns.NewResource(unrelated, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 10, aliasData),
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 99, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeCNAME, lnetodns.ClassINET, 20, terminalData),
			lnetodns.NewResource(alias, lnetodns.TypeA, lnetodns.ClassINET, 30, []byte{192, 0, 2, 30}),
			lnetodns.NewResource(terminal, lnetodns.TypeA, lnetodns.ClassINET, 40, []byte{192, 0, 2, 40}),
			lnetodns.NewResource(terminal, lnetodns.TypeA, lnetodns.ClassINET, 41, []byte{192, 0, 2, 40}),
			lnetodns.NewResource(terminal, lnetodns.TypeAAAA, lnetodns.ClassINET, 50, netip.MustParseAddr("2001:db8::40").AsSlice()),
		},
	}
	payload, err := message.AppendTo(nil, 12, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		t.Fatal(err)
	}
	records, response, failure, err := parseDNSResponse(payload, 12, request, 4)
	if err != nil || !response || failure != 0 {
		t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
	}
	want := []namespace.DNSRecord{
		{Name: request.Name, Type: namespace.DNSRecordCNAME, TTLSeconds: 10, CanonicalName: "alias.example.com"},
		{Name: "alias.example.com", Type: namespace.DNSRecordCNAME, TTLSeconds: 20, CanonicalName: "terminal.example.com"},
		{Name: "terminal.example.com", Type: namespace.DNSRecordA, TTLSeconds: 40, Address: netip.MustParseAddr("192.0.2.40")},
		{Name: "terminal.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 50, Address: netip.MustParseAddr("2001:db8::40")},
	}
	if len(records) != len(want) {
		t.Fatalf("records = %+v", records)
	}
	for i := range want {
		if records[i] != want[i] {
			t.Fatalf("record %d = %+v, want %+v", i, records[i], want[i])
		}
	}

	aOnly := namespace.DNSRequest{Name: request.Name, Types: namespace.DNSRecordsA}
	unrequested, err := (&lnetodns.Message{
		Questions: []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}},
		Answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeAAAA, lnetodns.ClassINET, 1, netip.MustParseAddr("2001:db8::1").AsSlice()),
			lnetodns.NewResource(unrelated, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
		},
	}).AppendTo(nil, 16, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		t.Fatal(err)
	}
	if records, _, failure, err := parseDNSResponse(unrequested, 16, aOnly, 4); err != nil || failure != 0 || len(records) != 0 {
		t.Fatalf("unrequested/irrelevant records = %+v, failure %v, err %v", records, failure, err)
	}
}

func TestDNSResponseRejectsForwardCompressionPointer(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	name := lnetodns.MustNewName(request.Name)
	payload := make([]byte, lnetodns.SizeHeader+6)
	binary.BigEndian.PutUint16(payload[0:2], 17)
	binary.BigEndian.PutUint16(payload[2:4], 1<<15)
	binary.BigEndian.PutUint16(payload[4:6], 1)
	binary.BigEndian.PutUint16(payload[6:8], 1)
	payload[12], payload[13] = 0xc0, byte(lnetodns.SizeHeader+6)
	binary.BigEndian.PutUint16(payload[14:16], uint16(lnetodns.TypeA))
	binary.BigEndian.PutUint16(payload[16:18], uint16(lnetodns.ClassINET))
	var err error
	payload, err = name.AppendTo(payload)
	if err != nil {
		t.Fatal(err)
	}
	answer := len(payload)
	payload = append(payload, make([]byte, 14)...)
	binary.BigEndian.PutUint16(payload[answer:answer+2], uint16(lnetodns.TypeA))
	binary.BigEndian.PutUint16(payload[answer+2:answer+4], uint16(lnetodns.ClassINET))
	binary.BigEndian.PutUint32(payload[answer+4:answer+8], 1)
	binary.BigEndian.PutUint16(payload[answer+8:answer+10], 4)
	copy(payload[answer+10:], []byte{192, 0, 2, 17})

	if records, response, failure, err := parseDNSResponse(payload, 17, request, 4); !response || failure != namespace.FailureIO || err == nil || len(records) != 0 {
		t.Fatalf("forward pointer = records %+v, response %v, failure %v, err %v", records, response, failure, err)
	}
}

func TestDNSResponseRejectsCNAMEConflictLoopAndMalformedWire(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	name := lnetodns.MustNewName(request.Name)
	alias := lnetodns.MustNewName("alias.example.com")
	other := lnetodns.MustNewName("other.example.com")
	aliasData, _ := alias.AppendTo(nil)
	otherData, _ := other.AppendTo(nil)
	nameData, _ := name.AppendTo(nil)
	question := []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}}
	for _, test := range []struct {
		name    string
		answers []lnetodns.Resource
		limit   int
		want    namespace.Failure
	}{
		{name: "conflicting cname", answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, aliasData),
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, otherData),
		}, limit: 4, want: namespace.FailureIO},
		{name: "cname loop", answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, nameData),
		}, limit: 4, want: namespace.FailureIO},
		{name: "chain exceeds record limit", answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 1, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
		}, limit: 1, want: namespace.FailureResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := (&lnetodns.Message{Questions: question, Answers: test.answers}).AppendTo(nil, 13, lnetodns.HeaderFlags(1<<15))
			if err != nil {
				t.Fatal(err)
			}
			_, response, failure, err := parseDNSResponse(payload, 13, request, test.limit)
			if !response || failure != test.want || err == nil {
				t.Fatalf("parse = response %v, failure %v, err %v", response, failure, err)
			}
		})
	}

	selfPointer := make([]byte, lnetodns.SizeHeader+6)
	binary.BigEndian.PutUint16(selfPointer[0:2], 14)
	binary.BigEndian.PutUint16(selfPointer[2:4], 1<<15)
	binary.BigEndian.PutUint16(selfPointer[4:6], 1)
	selfPointer[12], selfPointer[13] = 0xc0, 0x0c
	binary.BigEndian.PutUint16(selfPointer[14:16], uint16(lnetodns.TypeA))
	binary.BigEndian.PutUint16(selfPointer[16:18], uint16(lnetodns.ClassINET))
	if _, response, failure, err := parseDNSResponse(selfPointer, 14, request, 4); !response || failure != namespace.FailureIO || err == nil {
		t.Fatalf("self pointer = response %v, failure %v, err %v", response, failure, err)
	}

	valid, err := (&lnetodns.Message{Questions: question, Answers: []lnetodns.Resource{
		lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
	}}).AppendTo(nil, 15, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{valid[:len(valid)-1], append(append([]byte(nil), valid...), 0)} {
		if _, response, failure, err := parseDNSResponse(malformed, 15, request, 4); !response || failure != namespace.FailureIO || err == nil {
			t.Fatalf("malformed resource = response %v, failure %v, err %v", response, failure, err)
		}
	}
}

func TestDNSParserClearsSharedScratchAfterEnvelopeFailureAndSuccess(t *testing.T) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA}
	name := lnetodns.MustNewName(request.Name)
	alias := lnetodns.MustNewName("alias.example.com")
	aliasData, err := alias.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := (&lnetodns.Message{
		Questions: []lnetodns.Question{{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET}},
		Answers: []lnetodns.Resource{
			lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, 60, aliasData),
			lnetodns.NewResource(alias, lnetodns.TypeA, lnetodns.ClassINET, 60, []byte{192, 0, 2, 44}),
		},
	}).AppendTo(nil, 31, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		t.Fatal(err)
	}

	recordStorage := []namespace.DNSRecord{
		{Name: "sentinel-0.example", Type: namespace.DNSRecordA, TTLSeconds: 1, Address: netip.MustParseAddr("192.0.2.1")},
		{Name: "sentinel-1.example", Type: namespace.DNSRecordA, TTLSeconds: 1, Address: netip.MustParseAddr("192.0.2.2")},
		{},
		{},
	}
	recordsBefore := append([]namespace.DNSRecord(nil), recordStorage...)
	candidates := make([]namespace.DNSRecord, len(payload)/11)
	names := make([]string, 2*len(candidates))
	malformed := append(append([]byte(nil), payload...), 0)

	if records, response, failure, err := parseDNSResponseInto(recordStorage[:0], candidates, names, malformed, 31, request, len(recordStorage)); !response || failure != namespace.FailureIO || err == nil || len(records) != 0 {
		t.Fatalf("malformed parse = records:%+v response:%v failure:%v err:%v", records, response, failure, err)
	}
	if !reflect.DeepEqual(recordStorage, recordsBefore) {
		t.Fatalf("malformed parse staged partial output: got %+v want %+v", recordStorage, recordsBefore)
	}
	if !reflect.DeepEqual(candidates, make([]namespace.DNSRecord, len(candidates))) {
		t.Fatalf("malformed parse retained candidate scratch: %+v", candidates)
	}
	if !reflect.DeepEqual(names, make([]string, len(names))) {
		t.Fatalf("malformed parse retained name scratch: %+v", names)
	}

	records, response, failure, err := parseDNSResponseInto(recordStorage[:0], candidates, names, payload, 31, request, len(recordStorage))
	if err != nil || !response || failure != 0 || len(records) != 2 || records[0].Type != namespace.DNSRecordCNAME || records[0].CanonicalName != "alias.example.com" || records[1].Address != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("valid parse = records:%+v response:%v failure:%v err:%v", records, response, failure, err)
	}
	if !reflect.DeepEqual(candidates, make([]namespace.DNSRecord, len(candidates))) {
		t.Fatalf("valid parse retained candidate scratch: %+v", candidates)
	}
	if !reflect.DeepEqual(names, make([]string, len(names))) {
		t.Fatalf("valid parse retained name scratch: %+v", names)
	}
}

func FuzzDNSWireResponse(f *testing.F) {
	request := namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA | namespace.DNSRecordsAAAA}
	name := lnetodns.MustNewName(request.Name)
	seed, err := (&lnetodns.Message{Questions: []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}, Answers: []lnetodns.Resource{
		lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, 1, []byte{192, 0, 2, 1}),
	}}).AppendTo(nil, 77, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		f.Fatal(err)
	}
	compressed, err := (&lnetodns.Message{Questions: []lnetodns.Question{
		{Name: name, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
		{Name: name, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
	}}).AppendTo(nil, 77, lnetodns.HeaderFlags(1<<15))
	if err != nil {
		f.Fatal(err)
	}
	binary.BigEndian.PutUint16(compressed[6:8], 1)
	compressed = append(compressed, 0xc0, 0x0c, 0, byte(lnetodns.TypeA), 0, byte(lnetodns.ClassINET), 0, 0, 0, 1, 0, 4, 192, 0, 2, 1)
	f.Add(seed)
	f.Add(compressed)
	f.Add([]byte{0, 77, 0x80})
	f.Add(make([]byte, lnetodns.SizeHeader))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 2048 {
			payload = payload[:2048]
		}
		records, _, _, _ := parseDNSResponse(payload, 77, request, 8)
		if len(records) > 8 {
			t.Fatalf("returned %d records", len(records))
		}
		current := request.Name
		seen := make(map[namespace.DNSRecord]struct{}, len(records))
		for _, record := range records {
			if !record.Valid() || record.Name != current {
				t.Fatalf("invalid or unreachable record %+v after %q", record, current)
			}
			key := record
			key.TTLSeconds = 0
			if _, exists := seen[key]; exists {
				t.Fatalf("duplicate record %+v", record)
			}
			seen[key] = struct{}{}
			if record.Type == namespace.DNSRecordCNAME {
				current = record.CanonicalName
			}
		}
	})
}

func TestDNSConcurrentOperationsAndNamespaceClose(t *testing.T) {
	config := dnsTestConfig(t, 43)
	ns := newTestNamespace(t, config)
	resource, _, err := ns.TryResolve(namespace.DNSRequest{Name: "example.com", Types: namespace.DNSRecordsA})
	if err != nil {
		t.Fatal(err)
	}
	query := resource.(*dnsQuery)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 200 {
				_, _, _ = query.TryNext()
				if !query.Readiness().Valid() {
					t.Error("invalid concurrent DNS readiness")
					return
				}
			}
		}()
	}
	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if got := query.Readiness(); got != namespace.ReadyClosed {
		t.Fatalf("closed query readiness = %v", got)
	}
	if usage, _ := config.Quotas.Snapshot(); usage != (quota.Usage{}) {
		t.Fatalf("namespace close retained DNS quota = %+v", usage)
	}
}

type namespaceTestConfig struct {
	Hostname               string
	RandSeed               int64
	MaxActiveTCPPorts      uint16
	HardwareAddress        [6]byte
	GatewayHardwareAddress [6]byte
	IPv4Address            netip.Addr
	MTU                    uint16
	Link                   packetlink.Config
	DNS                    Config
	Policy                 *policy.Policy
	Quotas                 *quota.Account
}

type testNamespace struct {
	core               *lnetocore.Namespace
	adapter            *Adapter
	requiredFrameBytes int
}

func newTestNamespace(t testing.TB, config namespaceTestConfig) *testNamespace {
	t.Helper()
	common, err := lnetocore.New(lnetocore.Config{
		Hostname: config.Hostname, RandSeed: config.RandSeed,
		HardwareAddress: config.HardwareAddress, GatewayHardwareAddress: config.GatewayHardwareAddress,
		IPv4Address: config.IPv4Address, MTU: config.MTU, MaxActiveTCPPorts: config.MaxActiveTCPPorts, Link: config.Link,
		Policy: config.Policy, Quotas: config.Quotas,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(common, config.DNS)
	if err != nil {
		_ = common.Close()
		t.Fatal(err)
	}
	ns := &testNamespace{core: common, adapter: adapter, requiredFrameBytes: int(config.MTU) + 14}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func (n *testNamespace) TryResolve(request namespace.DNSRequest) (namespace.Resource, namespace.Progress, error) {
	return n.adapter.TryResolve(request)
}

func (n *testNamespace) TryService(budget namespace.ServiceBudget) (namespace.ServiceReport, namespace.Progress, error) {
	return n.core.TryService(budget)
}

func (n *testNamespace) Link() *packetlink.Link { return n.core.Link() }
func (n *testNamespace) Close() error           { return n.core.Close() }

func setNextIngress(n *testNamespace, next bool) {
	n.core.Lock()
	n.core.SetNextIngressLocked(next)
	n.core.Unlock()
}

func requireFailure(t testing.TB, err error) namespace.Failure {
	t.Helper()
	failure, ok := namespace.FailureOf(err)
	if !ok {
		t.Fatalf("missing semantic failure: %v", err)
	}
	return failure
}

func testConfig(id byte) namespaceTestConfig {
	mtu := uint16(ethernet.MaxMTU)
	return namespaceTestConfig{
		Hostname: "dns", RandSeed: int64(id) + 1,
		HardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id}, GatewayHardwareAddress: [6]byte{0x02, 0, 0, 0, 0, id ^ 3},
		IPv4Address: netip.AddrFrom4([4]byte{192, 0, 2, id}), MTU: mtu,
		Link: packetlink.Config{MaxFrameBytes: int(mtu) + 14, IngressFrames: 4, EgressFrames: 4},
	}
}

func dnsTestConfig(t testing.TB, id byte) namespaceTestConfig {
	t.Helper()
	config := testConfig(id)
	compiled, err := policy.Compile(policy.Config{Rules: []policy.Rule{
		{Action: policy.ActionAllow, Transports: []policy.Transport{policy.TransportDNS}, Directions: []policy.Direction{policy.DirectionOutbound}, DNSSuffixes: []string{"example.com"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	config.Policy = compiled
	config.Quotas = quota.NewAccount(quota.Limits{Resources: 4, DNSResources: 4, QueuedBytes: 16 << 10, DNSWork: 8})
	config.DNS = Config{
		Server: netip.MustParseAddr("192.0.2.53"), MaxQueries: 2, MaxRecords: 4,
		MaxResponseBytes: 512, MaxAttempts: 2, RetryServiceAttempts: 2,
	}
	config.GatewayHardwareAddress = [6]byte{0x02, 0, 0, 0, 0, 53}
	return config
}

func relayDNSCore(t testing.TB, from, to *lnetocore.Namespace) bool {
	t.Helper()
	from.Lock()
	from.SetNextIngressLocked(false)
	required := from.RequiredFrameBytesLocked()
	from.Unlock()
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1}
	report, progress, err := from.TryService(budget)
	if err != nil || !report.ValidResult(budget, progress) {
		t.Fatalf("DNS TCP egress service = %+v, %v, %v", report, progress, err)
	}
	if report.Packets == 0 {
		return false
	}
	frame := make([]byte, from.Link().MaxFrameBytes())
	result, err := from.Link().TryDequeue(packetlink.Egress, frame)
	if err != nil || !result.Ready || result.Truncated || result.FrameBytes == 0 {
		t.Fatalf("DNS TCP egress dequeue = %+v, %v", result, err)
	}
	if err := to.Link().TryEnqueue(packetlink.Ingress, frame[:result.FrameBytes]); err != nil {
		t.Fatal(err)
	}
	to.Lock()
	to.SetNextIngressLocked(true)
	required = to.RequiredFrameBytesLocked()
	to.Unlock()
	budget = namespace.ServiceBudget{Packets: 1, Bytes: uint32(required), Operations: 1}
	report, progress, err = to.TryService(budget)
	if err != nil || report.Packets != 1 || !report.ValidResult(budget, progress) {
		t.Fatalf("DNS TCP ingress service = %+v, %v, %v", report, progress, err)
	}
	return true
}

func serviceDNSPacket(t testing.TB, ns *testNamespace) []byte {
	t.Helper()
	setNextIngress(ns, false)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || report.Packets != 1 || report.Operations != 1 || report.Bytes == 0 {
		t.Fatalf("DNS packet service = %+v, %v, %v", report, progress, err)
	}
	buffer := make([]byte, ns.Link().MaxFrameBytes())
	result, err := ns.Link().TryDequeue(packetlink.Egress, buffer)
	if err != nil || !result.Ready || result.Truncated {
		t.Fatalf("DNS packet dequeue = %+v, %v", result, err)
	}
	return append([]byte(nil), buffer[:result.FrameBytes]...)
}

func serviceDNSIngressFrame(t testing.TB, ns *testNamespace, frame []byte) namespace.ServiceReport {
	t.Helper()
	if err := ns.Link().TryEnqueue(packetlink.Ingress, frame); err != nil {
		t.Fatal(err)
	}
	setNextIngress(ns, true)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidResult(budget, progress) {
		t.Fatalf("DNS ingress service = %+v, %v, %v", report, progress, err)
	}
	return report
}

func serviceDNSMaintenance(t testing.TB, ns *testNamespace) namespace.ServiceReport {
	t.Helper()
	setNextIngress(ns, false)
	budget := namespace.ServiceBudget{Packets: 1, Bytes: uint32(ns.requiredFrameBytes), Operations: 1}
	report, progress, err := ns.TryService(budget)
	if err != nil || progress != namespace.ProgressDone || !report.ValidResult(budget, progress) {
		t.Fatalf("DNS maintenance = %+v, %v, %v", report, progress, err)
	}
	return report
}

func dnsPacketIdentity(t testing.TB, packet []byte) (uint16, uint16) {
	t.Helper()
	ipFrame, err := ipv4.NewFrame(packet[14:])
	if err != nil {
		t.Fatal(err)
	}
	udpFrame, err := lnetoudp.NewFrame(ipFrame.Payload())
	if err != nil {
		t.Fatal(err)
	}
	dnsFrame, err := lnetodns.NewFrame(udpFrame.RawData()[8:udpFrame.Length()])
	if err != nil {
		t.Fatal(err)
	}
	return dnsFrame.TxID(), udpFrame.SourcePort()
}

func buildDNSResponseFrame(t testing.TB, config namespaceTestConfig, txid, destinationPort uint16, question string) []byte {
	t.Helper()
	return buildDNSResponseFrameWithRecords(t, config, txid, destinationPort, question, []namespace.DNSRecord{
		{Name: "example.com", Type: namespace.DNSRecordCNAME, TTLSeconds: 60, CanonicalName: "canonical.example.com"},
		{Name: "canonical.example.com", Type: namespace.DNSRecordA, TTLSeconds: 120, Address: netip.MustParseAddr("192.0.2.99")},
		{Name: "canonical.example.com", Type: namespace.DNSRecordAAAA, TTLSeconds: 180, Address: netip.MustParseAddr("2001:db8::99")},
	})
}

func buildDNSResponseFrameWithRecords(t testing.TB, config namespaceTestConfig, txid, destinationPort uint16, question string, records []namespace.DNSRecord) []byte {
	t.Helper()
	questionName := lnetodns.MustNewName(question)
	answers := make([]lnetodns.Resource, 0, len(records))
	for _, record := range records {
		name := lnetodns.MustNewName(record.Name)
		switch record.Type {
		case namespace.DNSRecordA:
			answers = append(answers, lnetodns.NewResource(name, lnetodns.TypeA, lnetodns.ClassINET, record.TTLSeconds, record.Address.AsSlice()))
		case namespace.DNSRecordAAAA:
			answers = append(answers, lnetodns.NewResource(name, lnetodns.TypeAAAA, lnetodns.ClassINET, record.TTLSeconds, record.Address.AsSlice()))
		case namespace.DNSRecordCNAME:
			canonical := lnetodns.MustNewName(record.CanonicalName)
			canonicalData, err := canonical.AppendTo(nil)
			if err != nil {
				t.Fatal(err)
			}
			answers = append(answers, lnetodns.NewResource(name, lnetodns.TypeCNAME, lnetodns.ClassINET, record.TTLSeconds, canonicalData))
		default:
			t.Fatalf("unsupported DNS record type %v", record.Type)
		}
	}
	message := lnetodns.Message{
		Questions: []lnetodns.Question{
			{Name: questionName, Type: lnetodns.TypeA, Class: lnetodns.ClassINET},
			{Name: questionName, Type: lnetodns.TypeAAAA, Class: lnetodns.ClassINET},
		},
		Answers: answers,
	}
	return buildDNSFrame(t, config, txid, destinationPort, message, lnetodns.HeaderFlags(1<<15|1<<8|1<<7))
}

func buildDNSFrame(t testing.TB, config namespaceTestConfig, txid, destinationPort uint16, message lnetodns.Message, flags lnetodns.HeaderFlags) []byte {
	t.Helper()
	payload, err := message.AppendTo(nil, txid, flags)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 14+20+8+len(payload))
	ethernetFrame, _ := ethernet.NewFrame(frame)
	*ethernetFrame.DestinationHardwareAddr() = config.HardwareAddress
	*ethernetFrame.SourceHardwareAddr() = config.GatewayHardwareAddress
	ethernetFrame.SetEtherType(ethernet.TypeIPv4)
	ipFrame, _ := ipv4.NewFrame(frame[14:])
	ipFrame.SetVersionAndIHL(4, 5)
	ipFrame.SetTotalLength(uint16(20 + 8 + len(payload)))
	ipFrame.SetTTL(64)
	ipFrame.SetProtocol(lneto.IPProtoUDP)
	*ipFrame.SourceAddr() = config.DNS.Server.As4()
	*ipFrame.DestinationAddr() = config.IPv4Address.As4()
	ipFrame.SetCRC(0)
	ipFrame.SetCRC(ipFrame.CalculateHeaderCRC())
	udpFrame, _ := lnetoudp.NewFrame(frame[14+20:])
	udpFrame.SetSourcePort(lnetodns.ServerPort)
	udpFrame.SetDestinationPort(destinationPort)
	udpFrame.SetLength(uint16(8 + len(payload)))
	copy(frame[14+20+8:], payload)
	udpFrame.SetCRC(0)
	var checksum lneto.CRC791
	ipFrame.CRCWriteUDPPseudo(&checksum, udpFrame.Length())
	udpFrame.SetCRC(lneto.NeverZeroSum(checksum.PayloadSum16(udpFrame.RawData()[:udpFrame.Length()])))
	return frame
}
