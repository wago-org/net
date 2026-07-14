// Package register self-registers the selective IPv4 link-local-only Wago networking extension.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/linklocal4"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-linklocal4", func() wago.Extension {
		network := wagonet.New()
		if err := linklocal4.Register(network); err != nil {
			panic("wagonet/linklocal4/register: " + err.Error())
		}
		return network
	})
}
