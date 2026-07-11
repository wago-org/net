// Package register self-registers the selective TCP-only Wago networking
// extension for custom binaries built by `wago pkg build`.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/tcp"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-tcp", func() wago.Extension {
		network := wagonet.New()
		if err := tcp.Register(network); err != nil {
			panic("wagonet/tcp/register: " + err.Error())
		}
		return network
	})
}
