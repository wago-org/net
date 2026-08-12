// Package register exposes the explicit DHCPv6 networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dhcpv6"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/dhcpv6", Name: "Wago DHCPv6", Description: "Bounded checked initial DHCPv6 acquisition.",
		Modules: []string{wagonet.Module, wagonet.DHCPv6Module},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, dhcpv6.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
