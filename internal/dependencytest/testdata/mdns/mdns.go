package mdns

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/mdns"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, mdns.Register(network)
}
