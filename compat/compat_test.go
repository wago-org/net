package compat_test

import (
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/compat"
	wago "github.com/wago-org/wago"
)

func TestInitRegistersExplicitAggregateSurface(t *testing.T) {
	runtime := wago.NewRuntime()
	if err := runtime.Use(compat.Init(wagonet.Config{})); err != nil {
		t.Fatalf("Use: %v", err)
	}

	wantCapabilities := []wago.Capability{wagonet.CapDNS, wagonet.CapInfo, wagonet.CapTCP, wagonet.CapUDP}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("Capabilities = %v, want %v", got, wantCapabilities)
	}
	gotImports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		gotImports[spec.Module]++
	}
	wantImports := map[string]int{
		wagonet.Module:    1,
		wagonet.UDPModule: 6,
		wagonet.TCPModule: 11,
		wagonet.DNSModule: 6,
	}
	if !reflect.DeepEqual(gotImports, wantImports) {
		t.Fatalf("import modules = %v, want %v", gotImports, wantImports)
	}
}
