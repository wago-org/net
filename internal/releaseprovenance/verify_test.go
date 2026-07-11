package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVerifyAndDeterministicBundleExport(t *testing.T) {
	dir, subject := validReviewFixture(t)
	verified, err := Verify(dir, VerifyOptions{ExpectedSubject: subject})
	if err != nil {
		t.Fatalf("Verify directory: %v", err)
	}
	if verified.Manifest.Subject.Revision != subject || len(verified.Manifest.Exceptions) != 2 || len(verified.Manifest.Limitations) != 1 {
		t.Fatalf("verification = %+v", verified)
	}

	first := filepath.Join(t.TempDir(), "first.tar.gz")
	second := filepath.Join(t.TempDir(), "second.tar.gz")
	_, firstHash, err := ExportBundle(dir, first, VerifyOptions{ExpectedSubject: subject})
	if err != nil {
		t.Fatalf("ExportBundle first: %v", err)
	}
	_, secondHash, err := ExportBundle(dir, second, VerifyOptions{ExpectedSubject: subject})
	if err != nil {
		t.Fatalf("ExportBundle second: %v", err)
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash || !reflect.DeepEqual(firstData, secondData) {
		t.Fatalf("deterministic exports differ: %s != %s", firstHash, secondHash)
	}
	if _, err := Verify(first, VerifyOptions{ExpectedSubject: subject}); err != nil {
		t.Fatalf("Verify archive: %v", err)
	}
}

func TestVerifyRejectsTamperedEvidenceAndWrongSubject(t *testing.T) {
	dir, subject := validReviewFixture(t)
	if _, err := Verify(dir, VerifyOptions{ExpectedSubject: strings.Repeat("f", 40)}); err == nil {
		t.Fatal("wrong expected subject unexpectedly accepted")
	}
	writeTestFile(t, filepath.Join(dir, "arm64", "runner.txt"), "runner=forged\n")
	if _, err := Verify(dir, VerifyOptions{ExpectedSubject: subject}); err == nil {
		t.Fatal("tampered evidence unexpectedly accepted")
	}
}

func TestVerifyRejectsNoncanonicalOrPolicyDriftedManifest(t *testing.T) {
	dir, subject := validReviewFixture(t)
	path := filepath.Join(dir, "provenance.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Inputs[0].Parents[0], manifest.Inputs[0].Parents[1] = manifest.Inputs[0].Parents[1], manifest.Inputs[0].Parents[0]
	writeManifestFixture(t, dir, &manifest)
	if _, err := Verify(dir, VerifyOptions{ExpectedSubject: subject}); err == nil {
		t.Fatal("reordered Wago parents unexpectedly accepted")
	}
}

func validReviewFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	subject := strings.Repeat("a", 40)
	checks := []Check{
		{Name: "pinned-revisions", Status: "pass"},
		{Name: "initial-clean-trees", Status: "pass"},
		{Name: "wago-plugin-plan-compat", Status: "pass"},
		{Name: "wasi-upstream-preview1-audit", Status: "accepted-exception", Detail: "reviewed docs/CI-only upstream retains crash"},
		{Name: "go-test-workspace", Status: "pass"},
		{Name: "go-test-module", Status: "pass"},
		{Name: "go-test-race", Status: "pass"},
		{Name: "go-vet", Status: "pass"},
		{Name: "go-list", Status: "pass"},
		{Name: "go-mod-tidy", Status: "pass"},
		{Name: "fuzz-dns-wire", Status: "pass"},
		{Name: "fuzz-dns-layout", Status: "pass"},
		{Name: "fuzz-dns-guest", Status: "pass"},
		{Name: "fuzz-shared-layout", Status: "pass"},
		{Name: "benchmark-guest-poll", Status: "pass"},
		{Name: "benchmark-udp-queue", Status: "pass"},
		{Name: "tinygo-test", Status: "pass"},
		{Name: "cross-build", Status: "pass"},
		{Name: "arm64-execution", Status: "skipped-no-runner"},
		{Name: "source-boundaries", Status: "pass"},
		{Name: "custom-cli-inspection", Status: "pass"},
		{Name: "wago-lifecycle-worker-tests", Status: "pass"},
		{Name: "lneto-test", Status: "pass"},
		{Name: "wasi-preview1-native-sigsegv", Status: "accepted-exception", Detail: "documented native preview-1 crash"},
		{Name: "final-clean-trees", Status: "pass"},
	}
	var checkText strings.Builder
	for _, check := range checks {
		checkText.WriteString(check.Name + "\t" + check.Status)
		if check.Detail != "" {
			checkText.WriteString("\t" + check.Detail)
		}
		checkText.WriteByte('\n')
	}
	writeTestFile(t, filepath.Join(dir, "checks.tsv"), checkText.String())
	writeTestFile(t, filepath.Join(dir, "toolchains.txt"), "go: go version go1.24.4 linux/amd64\ntinygo: tinygo version 0.41.1 linux/amd64\n")
	writeTestFile(t, filepath.Join(dir, "revisions.txt"), "plugin: "+subject+"\nWago: "+ExpectedWagoRevision+"\nlneto: "+ExpectedLnetoRevision+"\nWASI: "+ExpectedWASIRevision+"\n")
	writeTestFile(t, filepath.Join(dir, "arm64", "status.txt"), "status=skipped-no-runner\n")
	writeTestFile(t, filepath.Join(dir, "arm64", "runner.txt"), "runner=none\n")
	binaryHash := strings.Repeat("b", 64)
	writeTestFile(t, filepath.Join(dir, "arm64", "binary.sha256"), binaryHash+"  net-arm64.test\n")

	var imports []map[string]string
	for module, count := range map[string]int{"wago_net": 1, "wago_net_dns": 6, "wago_net_tcp": 11, "wago_net_udp": 6} {
		for i := 0; i < count; i++ {
			imports = append(imports, map[string]string{"module": module})
		}
	}
	sortInspectionImports(imports)
	inspectionData, err := json.Marshal(struct {
		Capabilities []string            `json:"capabilities"`
		Imports      []map[string]string `json:"imports"`
	}{Capabilities: []string{"net.dns", "net.info", "net.tcp", "net.udp"}, Imports: imports})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-go.json"), string(inspectionData))
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-tinygo.json"), string(inspectionData))

	var inspection Inspection
	if err := readInspection(dir, &inspection); err != nil {
		t.Fatal(err)
	}
	artifacts, err := scanArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &Manifest{
		Schema:  SchemaV1,
		Subject: Repository{Name: "net", Revision: subject, Tree: strings.Repeat("c", 40)},
		Inputs: []Repository{
			{Name: "wago", Revision: ExpectedWagoRevision, Tree: strings.Repeat("d", 40), Parents: []string{ExpectedWagoParent1, ExpectedWagoParent2}},
			{Name: "lneto", Revision: ExpectedLnetoRevision, Tree: strings.Repeat("e", 40)},
			{Name: "wasi", Revision: ExpectedWASIRevision, Tree: strings.Repeat("f", 40)},
		},
		Toolchains: Toolchains{Go: "go version go1.24.4 linux/amd64", TinyGo: "tinygo version 0.41.1 linux/amd64"},
		Inspection: inspection,
		Targets: Targets{
			CrossBuild:     TargetResult{GOOS: "linux", GOARCH: "arm64", Status: "pass"},
			Arm64Execution: TargetResult{GOOS: "linux", GOARCH: "arm64", Status: "skipped-no-runner", Runner: "none", BinarySHA256: binaryHash},
		},
		Checks:    checks,
		Artifacts: artifacts,
		Exceptions: []Exception{
			{ID: "wasi-upstream-preview1-audit", Status: "accepted-exception", Detail: "reviewed docs/CI-only upstream retains crash"},
			{ID: "wasi-preview1-native-sigsegv", Status: "accepted-exception", Detail: "documented native preview-1 crash"},
		},
		Limitations: []Limitation{{
			ID: "linux-arm64-execution", Status: "skipped-no-runner",
			Detail: "cross-build passed, but this release gate did not execute the arm64 smoke binary",
		}},
	}
	var evidence strings.Builder
	for _, artifact := range artifacts {
		evidence.WriteString(artifact.SHA256 + "  " + artifact.Path + "\n")
	}
	writeTestFile(t, filepath.Join(dir, "evidence.sha256"), evidence.String())
	writeManifestFixture(t, dir, manifest)
	return dir, subject
}

func sortInspectionImports(imports []map[string]string) {
	for i := 1; i < len(imports); i++ {
		for j := i; j > 0 && imports[j]["module"] < imports[j-1]["module"]; j-- {
			imports[j], imports[j-1] = imports[j-1], imports[j]
		}
	}
}

func writeManifestFixture(t *testing.T, dir string, manifest *Manifest) {
	t.Helper()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	writeTestFile(t, filepath.Join(dir, "provenance.sha256"), hex.EncodeToString(sum[:])+"  provenance.json\n")
}
