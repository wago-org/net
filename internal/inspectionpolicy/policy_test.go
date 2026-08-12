package inspectionpolicy_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/wago-org/net/internal/inspectionpolicy"
	"github.com/wago-org/net/internal/plugintest"
	allregister "github.com/wago-org/net/register"
	wago "github.com/wago-org/wago"
)

func catalogProviders() map[string]wago.PluginProvider {
	providers := allregister.Providers()
	catalog := make(map[string]wago.PluginProvider, len(providers))
	for _, provider := range providers {
		catalog[provider.Definition.ID] = provider
	}
	return catalog
}

type manifestAuthor struct {
	Name string `json:"name"`
}

type manifestPackage struct {
	Module      string            `json:"module"`
	Version     string            `json:"version"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Stability   wago.Stability    `json:"stability"`
	License     string            `json:"license"`
	Homepage    string            `json:"homepage"`
	Repository  string            `json:"repository"`
	Authors     []manifestAuthor  `json:"authors"`
	Engines     map[string]string `json:"engines"`
	Platforms   []string          `json:"platforms"`
	Subpackages []manifestPackage `json:"subpackages"`
}

func TestCanonicalPolicyMatchesEveryRegisteredBundle(t *testing.T) {
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Bundles) != 12 {
		t.Fatalf("bundle count = %d, want 12", len(policy.Bundles))
	}
	providers := catalogProviders()
	for _, bundle := range policy.Bundles {
		provider, ok := providers[bundle.Key]
		if !ok {
			t.Errorf("explicit provider %q is missing", bundle.Key)
			continue
		}
		runtime := wago.NewRuntime()
		if err := runtime.LoadPlugins(context.Background(), plugintest.Set(provider)); err != nil {
			t.Errorf("LoadPlugins %q: %v", bundle.Key, err)
			continue
		}
		defer runtime.Close()
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

func TestV1ManifestMatchesEveryExplicitProviderDefinition(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "wago.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema  string            `json:"$schema"`
		Package manifestPackage   `json:"package"`
		Plugins map[string]string `json:"plugins"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "https://wago.sh/v1/schema.json" {
		t.Fatalf("manifest schema = %q", manifest.Schema)
	}
	if len(manifest.Plugins) != 0 {
		t.Fatalf("leaf manifest dependencies = %v", manifest.Plugins)
	}
	metadata := map[string]manifestPackage{manifest.Package.Module: manifest.Package}
	for _, subpackage := range manifest.Package.Subpackages {
		if _, duplicate := metadata[subpackage.Module]; duplicate {
			t.Fatalf("duplicate manifest provider %q", subpackage.Module)
		}
		metadata[subpackage.Module] = inheritManifestMetadata(manifest.Package, subpackage)
	}
	providers := catalogProviders()
	if len(metadata) != len(providers) {
		t.Fatalf("manifest entries = %d, catalog providers = %d", len(metadata), len(providers))
	}
	for id, provider := range providers {
		entry, ok := metadata[id]
		if !ok {
			t.Fatalf("manifest omits catalog provider %q", id)
		}
		assertManifestMetadata(t, entry, provider.Definition)
	}
	catalog := allregister.Providers()
	want, err := wago.EncodeProviderCatalog("github.com/wago-org/net/register", catalog)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", wago.ProviderCatalogFile))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s is stale; run wago plugin catalog", wago.ProviderCatalogFile)
	}
	document, err := wago.DecodeProviderCatalog(got)
	if err != nil {
		t.Fatalf("%s: %v", wago.ProviderCatalogFile, err)
	}
	if len(document.Providers) != len(providers) {
		t.Fatalf("artifact providers = %d, want %d", len(document.Providers), len(providers))
	}
}

func inheritManifestMetadata(root, subpackage manifestPackage) manifestPackage {
	if subpackage.Version == "" {
		subpackage.Version = root.Version
	}
	if subpackage.License == "" {
		subpackage.License = root.License
	}
	if subpackage.Homepage == "" {
		subpackage.Homepage = root.Homepage
	}
	if subpackage.Repository == "" {
		subpackage.Repository = root.Repository
	}
	if subpackage.Authors == nil {
		subpackage.Authors = root.Authors
	}
	if subpackage.Engines == nil {
		subpackage.Engines = root.Engines
	}
	if subpackage.Platforms == nil {
		subpackage.Platforms = root.Platforms
	}
	return subpackage
}

func assertManifestMetadata(t *testing.T, manifest manifestPackage, definition wago.PluginDefinition) {
	t.Helper()
	authors := make([]string, len(manifest.Authors))
	for i := range manifest.Authors {
		authors[i] = manifest.Authors[i].Name
	}
	if manifest.Module != definition.ID ||
		manifest.Version != definition.Version ||
		manifest.Name != definition.Name ||
		manifest.Description != definition.Description ||
		manifest.Stability != definition.Stability ||
		manifest.License != definition.Provenance.License ||
		manifest.Homepage != definition.Provenance.Homepage ||
		manifest.Repository != definition.Provenance.Repository ||
		!reflect.DeepEqual(authors, definition.Provenance.Authors) ||
		!reflect.DeepEqual(manifest.Engines, definition.Compatibility.Engines) ||
		!reflect.DeepEqual(manifest.Platforms, definition.Compatibility.Platforms) {
		t.Fatalf("%s manifest metadata drifted\nmanifest=%#v\ndefinition=%#v", definition.ID, manifest, definition)
	}
}

func TestCatalogDefinitionsRequestExactAuthoritiesAndContract(t *testing.T) {
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	providers := catalogProviders()
	for _, bundle := range policy.Bundles {
		provider := providers[bundle.Key]
		definition := provider.Definition
		if len(definition.Authorities) != 4 {
			t.Fatalf("%s authorities = %d, want 4", bundle.Key, len(definition.Authorities))
		}
		wantModules := make([]string, 0, len(bundle.Imports))
		for module := range bundle.Imports {
			wantModules = append(wantModules, module)
		}
		sort.Strings(wantModules)
		wantAuthorities := []wago.Authority{
			wago.AuthorityHostImportDefine,
			wago.AuthorityHostCallerIdentify,
			wago.AuthorityInstanceInstantiateIntercept,
			wago.AuthorityInstanceCloseObserve,
		}
		for i, authority := range definition.Authorities {
			if authority.Name != wantAuthorities[i] || authority.Mode != wago.AuthorityRequired {
				t.Fatalf("%s authority[%d] = %q/%q", bundle.Key, i, authority.Name, authority.Mode)
			}
			if authority.Name == wago.AuthorityHostImportDefine {
				if !reflect.DeepEqual(authority.Scope.Modules, wantModules) {
					t.Fatalf("%s import authority = %v, want %v", bundle.Key, authority.Scope.Modules, wantModules)
				}
			} else if !reflect.DeepEqual(authority.Scope, wago.AuthorityScope{}) {
				t.Fatalf("%s authority %s has unexpected scope %+v", bundle.Key, authority.Name, authority.Scope)
			}
		}
		if got, want := definition.Provides, []wago.ContractSpec{{ID: "github.com/wago-org/net/service", Major: 1}}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s provides = %+v, want %+v", bundle.Key, got, want)
		}
		if len(definition.Requires) != 0 || len(definition.Consumes) != 0 {
			t.Fatalf("%s unexpected dependencies: requires=%v consumes=%v", bundle.Key, definition.Requires, definition.Consumes)
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
		}
		for module, count := range bundle.Imports {
			clone.Bundles[index].Imports[module] = count
		}
	}
	return clone
}
