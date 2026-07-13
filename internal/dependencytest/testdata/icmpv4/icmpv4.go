package icmpv4

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/icmpv4"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, icmpv4.Register(network)
}
