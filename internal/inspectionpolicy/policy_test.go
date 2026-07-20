package inspectionpolicy_test

import (
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	_ "github.com/wago-org/net/dhcpv4/register"
	_ "github.com/wago-org/net/dhcpv6/register"
	_ "github.com/wago-org/net/dns/register"
	_ "github.com/wago-org/net/icmpv4/register"
	_ "github.com/wago-org/net/icmpv6/register"
	"github.com/wago-org/net/internal/inspectionpolicy"
	_ "github.com/wago-org/net/ipv6/register"
	_ "github.com/wago-org/net/linklocal4/register"
	_ "github.com/wago-org/net/mdns/register"
	_ "github.com/wago-org/net/ntp/register"
	_ "github.com/wago-org/net/register"
	_ "github.com/wago-org/net/tcp/register"
	_ "github.com/wago-org/net/tls/register"
	_ "github.com/wago-org/net/udp/register"
	wago "github.com/wago-org/wago"
)

func TestCanonicalPolicyMatchesEveryRegisteredBundle(t *testing.T) {
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Bundles) != 13 {
		t.Fatalf("bundle count = %d, want 13", len(policy.Bundles))
	}
	for _, bundle := range policy.Bundles {
		extension, ok := wago.NewExtension(bundle.Key)
		if !ok {
			t.Errorf("registered extension %q is missing", bundle.Key)
			continue
		}
		runtime := wago.NewRuntime()
		if err := runtime.Use(extension); err != nil {
			t.Errorf("Use %q: %v", bundle.Key, err)
			continue
		}
		capabilities := make([]string, len(runtime.Capabilities()))
		for index, capability := range runtime.Capabilities() {
			capabilities[index] = string(capability)
		}
		if !reflect.DeepEqual(capabilities, bundle.Capabilities) {
			t.Errorf("%s capabilities = %v, want %v", bundle.Key, capabilities, bundle.Capabilities)
		}
		imports := make(map[string]int)
		for _, spec := range runtime.ProvidedImports() {
			imports[spec.Module]++
		}
		if !reflect.DeepEqual(imports, bundle.Imports) {
			t.Errorf("%s imports = %v, want %v", bundle.Key, imports, bundle.Imports)
		}
		if got := len(runtime.ProvidedImports()); got != inspectionpolicy.ImportCount(bundle) {
			t.Errorf("%s import total = %d, want %d", bundle.Key, got, inspectionpolicy.ImportCount(bundle))
		}
	}
}

func TestEveryRegisterPackageHasCanonicalExpectation(t *testing.T) {
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	configured := make(map[string]struct{}, len(policy.Bundles))
	for _, bundle := range policy.Bundles {
		configured[bundle.Package] = struct{}{}
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "*", "register", "register.go"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join("..", "..", "register", "register.go"))
	for _, file := range files {
		relative, err := filepath.Rel(filepath.Join("..", ".."), filepath.Dir(file))
		if err != nil {
			t.Fatal(err)
		}
		packagePath := "github.com/wago-org/net/" + filepath.ToSlash(relative)
		if _, ok := configured[packagePath]; !ok {
			t.Errorf("register package %s has no inspection expectation", packagePath)
		}
		delete(configured, packagePath)
	}
	if len(configured) != 0 {
		t.Fatalf("inspection expectations without register packages: %v", configured)
	}
}

func TestPolicyRejectsDuplicateAndOmittedProtocols(t *testing.T) {
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}

	duplicate := clonePolicy(policy)
	duplicate.Bundles = append(duplicate.Bundles, duplicate.Bundles[len(duplicate.Bundles)-1])
	if err := inspectionpolicy.Validate(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate bundle key") {
		t.Fatalf("duplicate policy error = %v", err)
	}

	omitted := clonePolicy(policy)
	aggregate, ok := inspectionpolicy.Aggregate(omitted)
	if !ok {
		t.Fatal("aggregate missing")
	}
	removeCapability := "net.udp"
	removeModule := "wago_net_udp"
	for index := range omitted.Bundles {
		if omitted.Bundles[index].Key != aggregate.Key {
			continue
		}
		capabilities := omitted.Bundles[index].Capabilities[:0]
		for _, capability := range omitted.Bundles[index].Capabilities {
			if capability != removeCapability {
				capabilities = append(capabilities, capability)
			}
		}
		omitted.Bundles[index].Capabilities = capabilities
		delete(omitted.Bundles[index].Imports, removeModule)
	}
	if err := inspectionpolicy.Validate(omitted); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("omitted aggregate protocol error = %v", err)
	}
}

func TestAggregateTotalsAreCanonicalSums(t *testing.T) {
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	aggregate, ok := inspectionpolicy.Aggregate(policy)
	if !ok {
		t.Fatal("aggregate missing")
	}
	if got := inspectionpolicy.ImportCount(aggregate); got != 84 {
		t.Fatalf("aggregate import total = %d, want 84", got)
	}
	if got := len(aggregate.Capabilities); got != 12 {
		t.Fatalf("aggregate capability count = %d, want 12", got)
	}
	modules := make([]string, 0, len(aggregate.Imports))
	for module := range aggregate.Imports {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	if modules[0] != "wago_net" || len(modules) != 12 {
		t.Fatalf("aggregate modules = %v", modules)
	}
}

func clonePolicy(source inspectionpolicy.Policy) inspectionpolicy.Policy {
	clone := inspectionpolicy.Policy{Bundles: make([]inspectionpolicy.Bundle, len(source.Bundles))}
	for index, bundle := range source.Bundles {
		clone.Bundles[index] = inspectionpolicy.Bundle{
			Key:          bundle.Key,
			Package:      bundle.Package,
			Capabilities: append([]string(nil), bundle.Capabilities...),
			Imports:      make(map[string]int, len(bundle.Imports)),
			GranularOnly: bundle.GranularOnly,
		}
		for module, count := range bundle.Imports {
			clone.Bundles[index].Imports[module] = count
		}
	}
	return clone
}
