// Package register self-registers the selective UDP-only Wago networking
// extension for custom binaries built by `wago pkg build`.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/udp"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-udp", func() wago.Extension {
		network := wagonet.New()
		if err := udp.Register(network); err != nil {
			panic("wagonet/udp/register: " + err.Error())
		}
		return network
	})
}
