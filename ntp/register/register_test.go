package register_test

import (
	"context"
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/internal/plugintest"
	netregister "github.com/wago-org/net/ntp/register"
	wago "github.com/wago-org/wago"
)

func TestNTPFactoryHasExactDisabledRuntimeSurface(t *testing.T) {
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
	if got, want := runtime.Capabilities(), []wago.Capability{wagonet.CapInfo, wagonet.CapNTP}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	imports := map[string]int{}
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	if want := map[string]int{wagonet.Module: 1, wagonet.NTPModule: 6}; !reflect.DeepEqual(imports, want) {
		t.Fatalf("imports = %v, want %v", imports, want)
	}
}
