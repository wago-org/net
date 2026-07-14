package linklocal4fixture

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/linklocal4"
)

func Network() (*wagonet.Network, error) {
	network := wagonet.New()
	if err := linklocal4.Register(network); err != nil {
		return network, err
	}
	return network, nil
}
