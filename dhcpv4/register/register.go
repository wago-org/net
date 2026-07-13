// Package register self-registers the selective DHCPv4-only Wago networking extension.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dhcpv4"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-dhcpv4", func() wago.Extension {
		network := wagonet.New()
		if err := dhcpv4.Register(network); err != nil {
			panic("wagonet/dhcpv4/register: " + err.Error())
		}
		return network
	})
}
