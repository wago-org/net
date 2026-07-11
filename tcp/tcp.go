// Package tcp selectively registers Wago's checked nonblocking TCP guest
// capability and import module on a shared networking extension.
//
// The public facade constructs its own opaque TCP descriptor and installs the
// TCP-only binding package. Compile-time isolation is still incomplete until
// shared instance operations and the lneto adapter are split by protocol.
package tcp

import (
	"errors"

	wagonet "github.com/wago-org/net"
	tcpbinding "github.com/wago-org/net/internal/binding/tcp"
)

var ErrInvalidOption = errors.New("wagonet/tcp: invalid option")

// Option configures TCP-local authority and finite resource defaults. The
// initial selective-registration slice reserves this surface; concrete client,
// listener, policy, and limit options are added as TCP implementation ownership
// moves out of the aggregate root configuration.
type Option interface {
	applyTCP(*registration) error
}

type registration struct{}

// Register selects only the TCP capability and wago_net_tcp import table on
// network. Shared wago_net.abi_version registration is added by the root when
// the first protocol is selected. Duplicate or post-freeze registration returns
// the root package's stable composition errors.
func Register(network *wagonet.Network, options ...Option) error {
	var config registration
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyTCP(&config); err != nil {
			return err
		}
	}
	return network.RegisterModule(tcpbinding.Descriptor())
}
