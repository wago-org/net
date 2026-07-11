package udpdns

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	"github.com/wago-org/net/udp"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	if err := udp.Register(network); err != nil {
		return network, err
	}
	return network, dns.Register(network)
}
