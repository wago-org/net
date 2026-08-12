// Package register exposes the explicit ICMPv4-only networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/icmpv4"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/icmpv4", Name: "Wago ICMPv4", Description: "Bounded checked ICMPv4 networking.",
		Modules: []string{wagonet.Module, wagonet.ICMPv4Module},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, icmpv4.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
