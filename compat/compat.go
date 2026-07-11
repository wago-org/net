// Package compat provides the explicit aggregate UDP, TCP, and DNS networking
// extension for callers migrating from the former root Init constructor.
//
// New selective callers should compose github.com/wago-org/net.New with the
// individual tcp.Register, udp.Register, and dns.Register functions instead.
package compat

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	"github.com/wago-org/net/tcp"
	"github.com/wago-org/net/udp"
)

// Init constructs one shared network with UDP, TCP, and DNS all selected. The
// supplied root Config retains the advanced aggregate configuration surface.
func Init(config wagonet.Config) *wagonet.Extension {
	network := wagonet.New(wagonet.WithConfig(config))
	var udpConfig udp.Config
	var tcpConfig tcp.Config
	var dnsConfig dns.Config
	if config.StaticIPv4 != nil {
		udpConfig = udp.Config(config.StaticIPv4.UDP)
		tcpConfig = tcp.Config(config.StaticIPv4.TCP)
		dnsConfig = dns.Config(config.StaticIPv4.DNS)
	}
	mustRegister(udp.Register(network, udp.WithConfig(udpConfig)))
	mustRegister(tcp.Register(network, tcp.WithConfig(tcpConfig)))
	mustRegister(dns.Register(network, dns.WithConfig(dnsConfig)))
	return network
}

func mustRegister(err error) {
	if err != nil {
		panic("wagonet/compat: registering built-in protocol: " + err.Error())
	}
}
