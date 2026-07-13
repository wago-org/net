// Package register self-registers the selective mDNS-only Wago networking extension.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/mdns"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-mdns", func() wago.Extension {
		network := wagonet.New()
		if err := mdns.Register(network); err != nil {
			panic("wagonet/mdns/register: " + err.Error())
		}
		return network
	})
}
