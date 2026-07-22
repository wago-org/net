//go:build !tinygo

package dependencytest

import (
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	tcptlsfixture "github.com/wago-org/net/internal/dependencytest/testdata/tcptls"
	tlsfixture "github.com/wago-org/net/internal/dependencytest/testdata/tls"
	wago "github.com/wago-org/wago"
)

func TestTLSFixtureRuntimeInspection(t *testing.T) {
	for _, test := range []struct {
		name         string
		newNetwork   networkFactory
		capabilities []wago.Capability
		imports      map[string]int
	}{
		{name: "tls", newNetwork: tlsfixture.Network, capabilities: []wago.Capability{wagonet.CapInfo, wagonet.CapTLS}, imports: map[string]int{wagonet.Module: 1, wagonet.TLSModule: 13}},
		{name: "tcp_tls", newNetwork: tcptlsfixture.Network, capabilities: []wago.Capability{wagonet.CapInfo, wagonet.CapTCP, wagonet.CapTLS}, imports: map[string]int{wagonet.Module: 1, wagonet.TCPModule: 11, wagonet.TLSModule: 13}},
	} {
		t.Run(test.name, func(t *testing.T) {
			network, err := test.newNetwork()
			if err != nil {
				t.Fatalf("compose fixture: %v", err)
			}
			runtime := wago.NewRuntime()
			if err := runtime.Use(network); err != nil {
				t.Fatalf("Use: %v", err)
			}
			if got := runtime.Capabilities(); !reflect.DeepEqual(got, test.capabilities) {
				t.Fatalf("Capabilities = %v, want %v", got, test.capabilities)
			}
			gotImports := make(map[string]int)
			for _, spec := range runtime.ProvidedImports() {
				gotImports[spec.Module]++
			}
			if !reflect.DeepEqual(gotImports, test.imports) {
				t.Fatalf("import modules = %v, want %v", gotImports, test.imports)
			}
		})
	}
}
