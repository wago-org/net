// Package register exposes the explicit NTP-only networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/ntp"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/ntp", Name: "Wago NTP", Description: "Bounded checked NTP networking.",
		Modules: []string{wagonet.Module, wagonet.NTPModule},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, ntp.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
