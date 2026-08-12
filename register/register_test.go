package register_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/wago-org/net/internal/inspectionpolicy"
	"github.com/wago-org/net/internal/plugintest"
	netregister "github.com/wago-org/net/register"
	wago "github.com/wago-org/wago"
)

func TestAllProtocolFactoryHasExactRuntimeSurface(t *testing.T) {
	provider := netregister.Provider()
	if got := provider.Definition.ID; got != "github.com/wago-org/net" {
		t.Fatalf("provider ID = %q", got)
	}
	runtime := wago.NewRuntime()
	defer runtime.Close()
	if err := runtime.LoadPlugins(context.Background(), plugintest.Set(provider)); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
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

func TestProvidersContainsEveryPublishedCatalogEntry(t *testing.T) {
	providers := netregister.Providers()
	got := make([]string, len(providers))
	for index, provider := range providers {
		got[index] = provider.Definition.ID
	}
	want := []string{
		"github.com/wago-org/net",
		"github.com/wago-org/net/dhcpv4",
		"github.com/wago-org/net/dhcpv6",
		"github.com/wago-org/net/dns",
		"github.com/wago-org/net/icmpv4",
		"github.com/wago-org/net/icmpv6",
		"github.com/wago-org/net/ipv6",
		"github.com/wago-org/net/linklocal4",
		"github.com/wago-org/net/mdns",
		"github.com/wago-org/net/ntp",
		"github.com/wago-org/net/tcp",
		"github.com/wago-org/net/udp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Providers IDs = %v, want %v", got, want)
	}
}
