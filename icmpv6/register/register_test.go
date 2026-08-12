package register_test

import (
	"context"
	"testing"

	wagonet "github.com/wago-org/net"
	netregister "github.com/wago-org/net/icmpv6/register"
	"github.com/wago-org/net/internal/plugintest"
	wago "github.com/wago-org/wago"
)

func TestGranularFactory(t *testing.T) {
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
	imports := 0
	for _, spec := range runtime.ProvidedImports() {
		if spec.Module == wagonet.ICMPv6Module {
			imports++
		}
	}
	if imports != 14 {
		t.Fatalf("imports = %d", imports)
	}
}
