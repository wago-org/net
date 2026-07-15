package register_test

import (
	"reflect"
	"testing"

	"github.com/wago-org/net/internal/inspectionpolicy"
	_ "github.com/wago-org/net/register"
	wago "github.com/wago-org/wago"
)

func TestAllProtocolFactoryHasExactRuntimeSurface(t *testing.T) {
	extension, ok := wago.NewExtension("net")
	if !ok {
		t.Fatal("net plugin was not registered")
	}
	if got := extension.Info().ID; got != "github.com/wago-org/net" {
		t.Fatalf("registered extension ID = %q", got)
	}
	runtime := wago.NewRuntime()
	if err := runtime.Use(extension); err != nil {
		t.Fatalf("Use: %v", err)
	}
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	want, ok := inspectionpolicy.Aggregate(policy)
	if !ok {
		t.Fatal("aggregate inspection policy missing")
	}
	gotCapabilities := make([]string, len(runtime.Capabilities()))
	for index, capability := range runtime.Capabilities() {
		gotCapabilities[index] = string(capability)
	}
	if !reflect.DeepEqual(gotCapabilities, want.Capabilities) {
		t.Fatalf("capabilities = %v, want %v", gotCapabilities, want.Capabilities)
	}
	gotImports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		gotImports[spec.Module]++
	}
	if !reflect.DeepEqual(gotImports, want.Imports) {
		t.Fatalf("import modules = %v, want %v", gotImports, want.Imports)
	}
}
