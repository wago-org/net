package all

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	"github.com/wago-org/net/tcp"
	"github.com/wago-org/net/udp"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	if err := tcp.Register(network); err != nil {
		return network, err
	}
	if err := udp.Register(network); err != nil {
		return network, err
	}
	if err := dns.Register(network); err != nil {
		return network, err
	}
	return network, nil
}
