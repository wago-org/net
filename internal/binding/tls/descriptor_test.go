package tls

import (
	"errors"
	"testing"

	nscore "github.com/wago-org/net/internal/namespace/core"
	"github.com/wago-org/net/internal/plugin"
	wago "github.com/wago-org/wago"
)

func TestDescriptorInstallsExactTLSBindingsAndPreservesBackend(t *testing.T) {
	configured := false
	base := new(int)
	serviceValue := new(int)
	backend := plugin.NewBackend(plugin.BackendLnetoV1,
		func(target any) error { configured = target == base; return nil },
		func(target any) (nscore.Service, error) {
			if target != base {
				t.Fatalf("backend base = %p, want %p", target, base)
			}
			return nscore.Service{Key: "test-tls", Value: serviceValue}, nil
		},
	)
	descriptor := Descriptor(backend)
	descriptor.Install(new(wago.Registry), plugin.Host{})
	if err := descriptor.ConfigureBackend(plugin.BackendLnetoV1, base); err != nil || !configured {
		t.Fatalf("ConfigureBackend = %v configured=%v", err, configured)
	}
	service, installed, err := descriptor.InstallBackend(plugin.BackendLnetoV1, base)
	if err != nil || !installed || service.Key != "test-tls" || service.Value != serviceValue {
		t.Fatalf("InstallBackend = %+v %v %v", service, installed, err)
	}
	if err := descriptor.ConfigureBackend("other", base); !errors.Is(err, plugin.ErrIncompatibleBackend) {
		t.Fatalf("incompatible backend = %v", err)
	}
	bindings := Bindings(plugin.Host{})
	if len(bindings) != 9 {
		t.Fatalf("bindings = %d, want 9", len(bindings))
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if binding.Name == "" || binding.Func == nil || len(binding.Results) != 1 || binding.Capability != Capability || binding.Docs == "" {
			t.Fatalf("invalid binding: %+v", binding)
		}
		if _, duplicate := seen[binding.Name]; duplicate {
			t.Fatalf("duplicate binding %q", binding.Name)
		}
		seen[binding.Name] = struct{}{}
	}
	for _, required := range []string{"namespace_default", "connect", "finish_connect", "read", "write", "shutdown_write", "connection_info", "close", "poll"} {
		if _, ok := seen[required]; !ok {
			t.Fatalf("binding %q missing", required)
		}
	}
}
