// Package register exposes every networking catalog entry published by this
// module, including the explicit all-protocol composition.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dhcpv4"
	dhcpv4register "github.com/wago-org/net/dhcpv4/register"
	"github.com/wago-org/net/dhcpv6"
	dhcpv6register "github.com/wago-org/net/dhcpv6/register"
	"github.com/wago-org/net/dns"
	dnsregister "github.com/wago-org/net/dns/register"
	"github.com/wago-org/net/icmpv4"
	icmpv4register "github.com/wago-org/net/icmpv4/register"
	"github.com/wago-org/net/icmpv6"
	icmpv6register "github.com/wago-org/net/icmpv6/register"
	"github.com/wago-org/net/ipv6"
	ipv6register "github.com/wago-org/net/ipv6/register"
	"github.com/wago-org/net/linklocal4"
	linklocal4register "github.com/wago-org/net/linklocal4/register"
	"github.com/wago-org/net/mdns"
	mdnsregister "github.com/wago-org/net/mdns/register"
	"github.com/wago-org/net/ntp"
	ntpregister "github.com/wago-org/net/ntp/register"
	"github.com/wago-org/net/tcp"
	tcpregister "github.com/wago-org/net/tcp/register"
	"github.com/wago-org/net/udp"
	udpregister "github.com/wago-org/net/udp/register"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: wagonet.PluginID, Name: "Wago Networking",
		Description: "Bounded capability-gated TCP, UDP, DNS, and network protocol plugins for Wago.",
		Modules: []string{wagonet.Module, wagonet.TCPModule, wagonet.UDPModule, wagonet.DNSModule,
			wagonet.ICMPv4Module, wagonet.NTPModule, wagonet.MDNSModule, wagonet.DHCPv4Module,
			wagonet.LinkLocal4Module, wagonet.IPv6Module, wagonet.ICMPv6Module, wagonet.DHCPv6Module},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			for _, register := range []func() error{
				func() error { return tcp.Register(network) }, func() error { return udp.Register(network) },
				func() error { return dns.Register(network) }, func() error { return icmpv4.Register(network) },
				func() error { return ntp.Register(network) }, func() error { return mdns.Register(network) },
				func() error { return dhcpv4.Register(network) }, func() error { return linklocal4.Register(network) },
				func() error { return ipv6.Register(network) }, func() error { return icmpv6.Register(network) },
				func() error { return dhcpv6.Register(network) },
			} {
				if err := register(); err != nil {
					return nil, err
				}
			}
			return network, nil
		},
	})
}

// Providers returns every catalog entry published by this module. Each call
// returns fresh providers without process-global state.
func Providers() []wago.PluginProvider {
	return []wago.PluginProvider{
		Provider(),
		dhcpv4register.Provider(),
		dhcpv6register.Provider(),
		dnsregister.Provider(),
		icmpv4register.Provider(),
		icmpv6register.Provider(),
		ipv6register.Provider(),
		linklocal4register.Provider(),
		mdnsregister.Provider(),
		ntpregister.Provider(),
		tcpregister.Provider(),
		udpregister.Provider(),
	}
}
