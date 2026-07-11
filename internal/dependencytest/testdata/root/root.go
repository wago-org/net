package root

import wagonet "github.com/wago-org/net"

func Network() (*wagonet.Network, error) {
	return wagonet.New(), nil
}
