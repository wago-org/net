// Package register exposes the explicit UDP-only networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/udp"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/udp", Name: "Wago UDP", Description: "Bounded checked UDP networking.",
		Modules: []string{wagonet.Module, wagonet.UDPModule},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, udp.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
