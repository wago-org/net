// Package register exposes the explicit mDNS-only networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/mdns"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/mdns", Name: "Wago mDNS", Description: "Bounded checked multicast DNS networking.",
		Modules: []string{wagonet.Module, wagonet.MDNSModule},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, mdns.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
