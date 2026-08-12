package register_test

import (
	"context"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	netregister "github.com/wago-org/net/dhcpv4/register"
	"github.com/wago-org/net/internal/plugintest"
	wago "github.com/wago-org/wago"
)

func TestDHCPv4FactoryHasExactRuntimeSurface(t *testing.T) {
	providers := netregister.Providers()
	if len(providers) != 1 {
		t.Fatalf("Providers = %d, want 1", len(providers))
	}
	provider := providers[0]
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.LoadPlugins(context.Background(), plugintest.Set(provider)); err != nil {
		t.Fatal(err)
	}
	if got, want := runtime.Capabilities(), []wago.Capability{wagonet.CapDHCPv4, wagonet.CapInfo}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	imports := map[string]int{}
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	if want := map[string]int{wagonet.Module: 1, wagonet.DHCPv4Module: 7}; !reflect.DeepEqual(imports, want) {
		t.Fatalf("imports = %v, want %v", imports, want)
	}
}
