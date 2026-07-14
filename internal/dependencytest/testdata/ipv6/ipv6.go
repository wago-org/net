package ipv6fixture

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/ipv6"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, ipv6.Register(network)
}
