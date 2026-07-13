// Package register self-registers the selective NTP-only Wago networking
// extension for custom binaries built by `wago pkg build`. The default
// self-registration exposes a truthful disabled NTP module until an embedding
// application uses ntp.Register with an explicit server and clock.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/ntp"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-ntp", func() wago.Extension {
		network := wagonet.New()
		if err := ntp.Register(network); err != nil {
			panic("wagonet/ntp/register: " + err.Error())
		}
		return network
	})
}
