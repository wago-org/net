// Package register self-registers the selective TLS-only Wago networking
// extension for custom binaries built by `wago pkg build`.
package register

import (
	cryptotls "crypto/tls"

	wagonet "github.com/wago-org/net"
	wagonettls "github.com/wago-org/net/tls"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net-tls", func() wago.Extension {
		network := wagonet.New()
		profile, err := wagonettls.NewClientProfile(1, &cryptotls.Config{}, wagonettls.AllowServerNames("localhost"))
		if err != nil {
			panic("wagonet/tls/register: " + err.Error())
		}
		if err := wagonettls.Register(network, wagonettls.WithClientProfile(profile)); err != nil {
			panic("wagonet/tls/register: " + err.Error())
		}
		return network
	})
}
