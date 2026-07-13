package dependencytest

import (
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	allfixture "github.com/wago-org/net/internal/dependencytest/testdata/all"
	dnsfixture "github.com/wago-org/net/internal/dependencytest/testdata/dns"
	icmpfixture "github.com/wago-org/net/internal/dependencytest/testdata/icmpv4"
	rootfixture "github.com/wago-org/net/internal/dependencytest/testdata/root"
	tcpfixture "github.com/wago-org/net/internal/dependencytest/testdata/tcp"
	tcpdnsfixture "github.com/wago-org/net/internal/dependencytest/testdata/tcpdns"
	tcpudpfixture "github.com/wago-org/net/internal/dependencytest/testdata/tcpudp"
	udpfixture "github.com/wago-org/net/internal/dependencytest/testdata/udp"
	udpdnsfixture "github.com/wago-org/net/internal/dependencytest/testdata/udpdns"
	wago "github.com/wago-org/wago"
)

type networkFactory func() (*wagonet.Network, error)

func TestFixtureRuntimeInspection(t *testing.T) {
	tests := []struct {
		name         string
		newNetwork   networkFactory
		capabilities []wago.Capability
		imports      map[string]int
	}{
		{name: "root", newNetwork: rootfixture.Network, imports: map[string]int{}},
		{name: "tcp", newNetwork: tcpfixture.Network, capabilities: []wago.Capability{wagonet.CapInfo, wagonet.CapTCP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11}},
		{name: "udp", newNetwork: udpfixture.Network, capabilities: []wago.Capability{wagonet.CapInfo, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.UDPModule: 6}},
		{name: "dns", newNetwork: dnsfixture.Network, capabilities: []wago.Capability{wagonet.CapDNS, wagonet.CapInfo}, imports: map[string]int{wagonet.Module: 1, wagonet.DNSModule: 6}},
		{name: "icmpv4", newNetwork: icmpfixture.Network, capabilities: []wago.Capability{wagonet.CapICMPv4, wagonet.CapInfo}, imports: map[string]int{wagonet.Module: 1, wagonet.ICMPv4Module: 6}},
		{name: "tcp_udp", newNetwork: tcpudpfixture.Network, capabilities: []wago.Capability{wagonet.CapInfo, wagonet.CapTCP, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.UDPModule: 6}},
		{name: "tcp_dns", newNetwork: tcpdnsfixture.Network, capabilities: []wago.Capability{wagonet.CapDNS, wagonet.CapInfo, wagonet.CapTCP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.DNSModule: 6}},
		{name: "udp_dns", newNetwork: udpdnsfixture.Network, capabilities: []wago.Capability{wagonet.CapDNS, wagonet.CapInfo, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.UDPModule: 6, wagonet.DNSModule: 6}},
		{name: "all", newNetwork: allfixture.Network, capabilities: []wago.Capability{wagonet.CapDNS, wagonet.CapICMPv4, wagonet.CapInfo, wagonet.CapTCP, wagonet.CapUDP}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.UDPModule: 6, wagonet.DNSModule: 6, wagonet.ICMPv4Module: 6}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network, err := test.newNetwork()
			if err != nil {
				t.Fatalf("compose fixture: %v", err)
			}
			runtime := wago.NewRuntime()
			if err := runtime.Use(network); err != nil {
				t.Fatalf("Use: %v", err)
			}
			if got := runtime.Capabilities(); !reflect.DeepEqual(got, test.capabilities) {
				t.Fatalf("Capabilities = %v, want %v", got, test.capabilities)
			}
			gotImports := make(map[string]int)
			for _, spec := range runtime.ProvidedImports() {
				gotImports[spec.Module]++
			}
			if !reflect.DeepEqual(gotImports, test.imports) {
				t.Fatalf("import modules = %v, want %v", gotImports, test.imports)
			}
		})
	}
}
