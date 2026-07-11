// Package dns selectively registers Wago's checked bounded DNS guest capability
// and import module on a shared networking extension.
//
// The public facade constructs its own opaque DNS descriptor and installs the
// DNS-only binding and instance-operation packages. Compile-time isolation is
// still incomplete until namespace/ABI contracts and the lneto adapter split.
package dns

import (
	"errors"

	wagonet "github.com/wago-org/net"
	dnsbinding "github.com/wago-org/net/internal/binding/dns"
)

var ErrInvalidOption = errors.New("wagonet/dns: invalid option")

// Option configures DNS-local resolver authority and finite resource defaults.
// The initial selective-registration slice reserves this surface; concrete
// resolver, policy, and limit options are added as DNS implementation ownership
// moves out of the aggregate root configuration.
type Option interface {
	applyDNS(*registration) error
}

type registration struct{}

// Register selects only the DNS capability and wago_net_dns import table on
// network. Shared wago_net.abi_version registration is added by the root when
// the first protocol is selected. Duplicate or post-freeze registration returns
// the root package's stable composition errors.
func Register(network *wagonet.Network, options ...Option) error {
	var config registration
	for _, option := range options {
		if option == nil {
			return ErrInvalidOption
		}
		if err := option.applyDNS(&config); err != nil {
			return err
		}
	}
	return network.RegisterModule(dnsbinding.Descriptor())
}
