// Package register exposes the explicit TCP-only networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/tcp"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/tcp", Name: "Wago TCP", Description: "Bounded checked TCP networking.",
		Modules: []string{wagonet.Module, wagonet.TCPModule},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, tcp.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
