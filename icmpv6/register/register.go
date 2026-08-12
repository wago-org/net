// Package register exposes the explicit ICMPv6 networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/icmpv6"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/icmpv6", Name: "Wago ICMPv6", Description: "Bounded checked ICMPv6 and neighbor discovery.",
		Modules: []string{wagonet.Module, wagonet.ICMPv6Module},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, icmpv6.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
