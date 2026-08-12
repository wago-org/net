// Package register exposes the explicit IPv6 networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/ipv6"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/ipv6", Name: "Wago IPv6", Description: "Bounded checked IPv6 networking.",
		Modules: []string{wagonet.Module, wagonet.IPv6Module},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, ipv6.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
