package tcp

import (
	wagonet "github.com/wago-org/net"
	wagtcp "github.com/wago-org/net/tcp"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, wagtcp.Register(network)
}
