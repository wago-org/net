// Package register self-registers the selective DNS-only Wago networking
// extension for custom binaries built by `wago pkg build`. Resolver/storage
// remain disabled until an explicitly configured composition is used.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-dns", func() wago.Extension {
		network := wagonet.New()
		if err := dns.Register(network); err != nil {
			panic("wagonet/dns/register: " + err.Error())
		}
		return network
	})
}
