// Package register self-registers the selective ICMPv4-only Wago networking
// extension for custom binaries built by `wago pkg build`.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/icmpv4"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-icmpv4", func() wago.Extension {
		network := wagonet.New()
		if err := icmpv4.Register(network); err != nil {
			panic("wagonet/icmpv4/register: " + err.Error())
		}
		return network
	})
}
