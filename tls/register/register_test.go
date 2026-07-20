package register_test

import (
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	_ "github.com/wago-org/net/tls/register"
	wago "github.com/wago-org/wago"
)

func TestTLSFactoryHasExactRuntimeSurface(t *testing.T) {
	extension, ok := wago.NewExtension("net-tls")
	if !ok {
		t.Fatal("TLS-only extension was not registered")
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatal(err)
	}
	wantCapabilities := []wago.Capability{wagonet.CapInfo, wagonet.CapTLS}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("capabilities = %v, want %v", got, wantCapabilities)
	}
	imports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		imports[spec.Module]++
	}
	wantImports := map[string]int{wagonet.Module: 1, wagonet.TLSModule: 9}
	if !reflect.DeepEqual(imports, wantImports) {
		t.Fatalf("imports = %v, want %v", imports, wantImports)
	}
	if imports[wagonet.TCPModule] != 0 {
		t.Fatal("TLS-only self-registration exposed TCP")
	}
}
