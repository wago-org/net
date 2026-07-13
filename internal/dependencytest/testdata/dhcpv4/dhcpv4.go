package dhcpv4fixture

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dhcpv4"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	if err := dhcpv4.Register(network); err != nil {
		return network, err
	}
	return network, nil
}
