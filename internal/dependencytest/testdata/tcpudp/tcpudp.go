package tcpudp

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/tcp"
	"github.com/wago-org/net/udp"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	if err := tcp.Register(network); err != nil {
		return network, err
	}
	return network, udp.Register(network)
}
