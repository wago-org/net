// Package register exposes the explicit DHCPv4-only networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dhcpv4"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/dhcpv4", Name: "Wago DHCPv4", Description: "Bounded checked DHCPv4 networking.",
		Modules: []string{wagonet.Module, wagonet.DHCPv4Module},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, dhcpv4.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
