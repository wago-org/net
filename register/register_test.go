package register_test

import (
	"reflect"
	"testing"

	wagonet "github.com/wago-org/net"
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
	wantCapabilities := []wago.Capability{wagonet.CapDHCPv4, wagonet.CapDNS, wagonet.CapICMPv4, wagonet.CapICMPv6, wagonet.CapInfo, wagonet.CapIPv6, wagonet.CapLinkLocal4, wagonet.CapMDNS, wagonet.CapNTP, wagonet.CapTCP, wagonet.CapUDP}
	if got := runtime.Capabilities(); !reflect.DeepEqual(got, wantCapabilities) {
		t.Fatalf("capabilities = %v, want %v", got, wantCapabilities)
	}
	gotImports := make(map[string]int)
	for _, spec := range runtime.ProvidedImports() {
		gotImports[spec.Module]++
	}
	wantImports := map[string]int{wagonet.Module: 1, wagonet.DHCPv4Module: 7, wagonet.DNSModule: 6, wagonet.ICMPv4Module: 6, wagonet.ICMPv6Module: 14, wagonet.IPv6Module: 3, wagonet.LinkLocal4Module: 7, wagonet.MDNSModule: 10, wagonet.NTPModule: 6, wagonet.TCPModule: 11, wagonet.UDPModule: 6}
	if !reflect.DeepEqual(gotImports, wantImports) {
		t.Fatalf("import modules = %v, want %v", gotImports, wantImports)
	}
}
