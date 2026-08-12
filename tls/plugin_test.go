package tls_test

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/plugintest"
	wago "github.com/wago-org/wago"
)

func loadNetwork(runtime *wago.Runtime, network *wagonet.Network) error {
	return plugintest.LoadNetwork(runtime, network)
}

func compileImportHarness(runtime *wago.Runtime) (*wago.Module, error) {
	return plugintest.CompileImportHarness(runtime, wagonet.TLSModule)
}
