package icmpv6fixture

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/icmpv6"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	return network, icmpv6.Register(network)
}
