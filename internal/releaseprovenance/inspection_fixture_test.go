package releaseprovenance

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/wago-org/net/internal/inspectionpolicy"
)

// writeCanonicalInspectionEvidence stays in the common test build so both Go
// and TinyGo compile and exercise the release-inspection fixture contract.
func writeCanonicalInspectionEvidence(t testing.TB, dir string) {
	t.Helper()
	policy, err := inspectionpolicy.Load()
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-policy.json"), string(inspectionpolicy.Data()))
	for _, bundle := range policy.Bundles {
		var imports []map[string]string
		for module, count := range bundle.Imports {
			for range count {
				imports = append(imports, map[string]string{"module": module})
			}
		}
		sortInspectionImports(imports)
		inspectionData, err := json.Marshal(struct {
			Capabilities []string            `json:"capabilities"`
			Imports      []map[string]string `json:"imports"`
		}{Capabilities: bundle.Capabilities, Imports: imports})
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-"+bundle.Key+"-go.json"), string(inspectionData))
		writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-"+bundle.Key+"-tinygo.json"), string(inspectionData))
		if bundle.Key == inspectionpolicy.AggregateKey {
			writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-go.json"), string(inspectionData))
			writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-tinygo.json"), string(inspectionData))
		}
	}
}

func sortInspectionImports(imports []map[string]string) {
	for i := 1; i < len(imports); i++ {
		for j := i; j > 0 && imports[j]["module"] < imports[j-1]["module"]; j-- {
			imports[j], imports[j-1] = imports[j-1], imports[j]
		}
	}
}
