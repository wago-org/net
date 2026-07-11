// Package udp selectively registers Wago's checked nonblocking UDP guest
// capability and import module on a shared networking extension.
//
// The public facade constructs its own opaque UDP descriptor and installs the
// UDP-only binding and instance-operation packages. Compile-time isolation is
// still incomplete until namespace/ABI contracts and the lneto adapter split.
package udp

import (
	"errors"

	wagonet "github.com/wago-org/net"
	udpbinding "github.com/wago-org/net/internal/binding/udp"
)

var ErrInvalidOption = errors.New("wagonet/udp: invalid option")

// Option configures UDP-local authority and finite resource defaults. The
// initial selective-registration slice reserves this surface; concrete client,
// server, policy, and limit options are added as UDP implementation ownership
// moves out of the aggregate root configuration.
type Option interface {
	applyUDP(*registration) error
}

type registration struct{}

// Register selects only the UDP capability and wago_net_udp import table on
// network. Shared wago_net.abi_version registration is added by the root when
// the first protocol is selected. Duplicate or post-freeze registration returns
// the root package's stable composition errors.
func Register(network *wagonet.Network, options ...Option) error {
	var config registration
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyUDP(&config); err != nil {
			return err
		}
	}
	return network.RegisterModule(udpbinding.Descriptor())
}
