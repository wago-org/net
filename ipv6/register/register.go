// Package register self-registers the selective IPv6 namespace extension.
// Deployment identity remains disabled until explicit composition supplies it.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/ipv6"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-ipv6", func() wago.Extension {
		network := wagonet.New()
		if err := ipv6.Register(network); err != nil {
			panic("wagonet/ipv6/register: " + err.Error())
		}
		return network
	})
}
