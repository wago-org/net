package dhcpv6

import (
	wagonet "github.com/wago-org/net"
	protocol "github.com/wago-org/net/dhcpv6"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, protocol.Register(network)
}
