package tls

import (
	cryptotls "crypto/tls"

	wagonet "github.com/wago-org/net"
	wagonettls "github.com/wago-org/net/tls"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	profile, err := wagonettls.NewClientProfile(1, &cryptotls.Config{}, wagonettls.AllowServerNames("api.example.com"))
	if err != nil {
		return nil, err
	}
	return network, wagonettls.Register(network, wagonettls.WithClientProfile(profile))
}
