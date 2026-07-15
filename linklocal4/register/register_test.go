package register_test

import (
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	_ "github.com/wago-org/net/linklocal4/register"
	wago "github.com/wago-org/wago"
)

func TestLinkLocal4FactoryHasExactRuntimeSurface(t *testing.T) {
	extension, ok := wago.NewExtension("net-linklocal4")
	if !ok {
		t.Fatal("link-local-only extension was not registered")
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatal(err)
	}
	if got, want := runtime.Capabilities(), []wago.Capability{wagonet.CapInfo, wagonet.CapLinkLocal4}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	imports := map[string]int{}
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	if want := map[string]int{wagonet.Module: 1, wagonet.LinkLocal4Module: 7}; !reflect.DeepEqual(imports, want) {
		t.Fatalf("imports = %v, want %v", imports, want)
	}
}
