package dns

import (
	wagonet "github.com/wago-org/net"
	wagdns "github.com/wago-org/net/dns"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, wagdns.Register(network)
}
