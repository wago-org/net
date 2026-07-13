package ntp

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/ntp"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, ntp.Register(network)
}
