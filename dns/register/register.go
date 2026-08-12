// Package register exposes the explicit DNS-only networking catalog entry.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/dns"
	wago "github.com/wago-org/wago"
)

func Provider() wago.PluginProvider {
	return wagonet.Provider(wagonet.ProviderSpec{
		ID: "github.com/wago-org/net/dns", Name: "Wago DNS", Description: "Bounded checked DNS networking.",
		Modules: []string{wagonet.Module, wagonet.DNSModule},
		Factory: func() (*wagonet.Network, error) {
			network := wagonet.New()
			return network, dns.Register(network)
		},
	})
}

func Providers() []wago.PluginProvider { return []wago.PluginProvider{Provider()} }
