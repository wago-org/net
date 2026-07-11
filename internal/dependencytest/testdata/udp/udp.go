package udp

import (
	wagonet "github.com/wago-org/net"
	wagudp "github.com/wago-org/net/udp"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, wagudp.Register(network)
}
