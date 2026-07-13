// Package register self-registers the explicit all-protocol Wago networking
// bundle for custom binaries built by `wago pkg build`.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	"github.com/wago-org/net/icmpv4"
	"github.com/wago-org/net/ntp"
	"github.com/wago-org/net/tcp"
	"github.com/wago-org/net/udp"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net", func() wago.Extension {
		network := wagonet.New()
		mustRegister(tcp.Register(network))
		mustRegister(udp.Register(network))
		mustRegister(dns.Register(network))
		mustRegister(icmpv4.Register(network))
		mustRegister(ntp.Register(network))
		return network
	})
}

func mustRegister(err error) {
	if err != nil {
		panic("wagonet/register: " + err.Error())
	}
}
