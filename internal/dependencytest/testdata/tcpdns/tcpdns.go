package tcpdns

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	"github.com/wago-org/net/tcp"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	if err := tcp.Register(network); err != nil {
		return network, err
	}
	return network, dns.Register(network)
}
