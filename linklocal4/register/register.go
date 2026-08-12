// Package register exposes the explicit IPv4 link-local networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/linklocal4"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/linklocal4", Name: "Wago IPv4 Link-Local", Description: "Bounded checked IPv4 link-local networking.",
		Modules: []string{wagonet.Module, wagonet.LinkLocal4Module},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, linklocal4.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
