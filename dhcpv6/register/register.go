// Package register self-registers the selective DHCPv6-only extension.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dhcpv6"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-dhcpv6", func() wago.Extension {
		network := wagonet.New()
		if err := dhcpv6.Register(network); err != nil {
			panic("wagonet/dhcpv6/register: " + err.Error())
		}
		return network
	})
}
