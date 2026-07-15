package dhcpv6

import (
	"testing"

	"github.com/wago-org/net/internal/guest"
	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/plugin"
	wago "github.com/wago-org/wago"
)

func TestDescriptorInstallsCompleteBindingsAndPreservesBackend(t *testing.T) {
	configured := false
	base := new(int)
	serviceValue := new(int)
	backend := plugin.NewBackend(plugin.BackendLnetoV1,
		func(target any) error {
			configured = target == base
			return nil
		},
		func(target any) (nscore.Service, error) {
			if target != base {
				t.Fatalf("backend base = %p, want %p", target, base)
			}
			return nscore.Service{Key: "test-dhcpv6", Value: serviceValue}, nil
		},
	)
	descriptor := Descriptor(backend)
	descriptor.Install(new(wago.Registry), plugin.Host{})
	if err := descriptor.ConfigureBackend(plugin.BackendLnetoV1, base); err != nil || !configured {
		t.Fatalf("ConfigureBackend = %v configured=%v", err, configured)
	}
	service, installed, err := descriptor.InstallBackend(plugin.BackendLnetoV1, base)
	if err != nil || !installed || service.Key != "test-dhcpv6" || service.Value != serviceValue {
		t.Fatalf("InstallBackend = %+v %v %v", service, installed, err)
	}
	assertDHCPv6Bindings(t, Bindings(plugin.Host{}), 7)
}

func assertDHCPv6Bindings(t testing.TB, bindings []plugin.Binding, want int) {
	t.Helper()
	if len(bindings) != want {
		t.Fatalf("bindings = %d, want %d", len(bindings), want)
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if binding.Name == "" || binding.Func == nil || binding.Capability != Capability || binding.Docs == "" {
			t.Fatalf("invalid binding: %+v", binding)
		}
		if _, duplicate := seen[binding.Name]; duplicate {
			t.Fatalf("duplicate binding %q", binding.Name)
		}
		seen[binding.Name] = struct{}{}
		if binding.Name == "poll" {
			results := []uint64{0}
			binding.Func(nil, nil, results)
			if got := guest.Status(int32(results[0])); got != guest.StatusInvalidArgument {
				t.Fatalf("poll invalid shape = %v", got)
			}
		}
	}
	if _, ok := seen["poll"]; !ok {
		t.Fatal("poll binding missing")
	}
}
