// Package register self-registers the selective ICMPv6/NDP extension.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/icmpv6"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-icmpv6", func() wago.Extension {
		network := wagonet.New()
		if err := icmpv6.Register(network); err != nil {
			panic("wagonet/icmpv6/register: " + err.Error())
		}
		return network
	})
}
