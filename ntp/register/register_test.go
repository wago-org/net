package register_test

import (
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	_ "github.com/wago-org/net/ntp/register"
	wago "github.com/wago-org/wago"
)

func TestNTPFactoryHasExactDisabledRuntimeSurface(t *testing.T) {
	extension, ok := wago.NewExtension("net-ntp")
	if !ok {
		t.Fatal("NTP-only extension was not registered")
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
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
