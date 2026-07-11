//go:build !tinygo

package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVerifyAndDeterministicBundleExport(t *testing.T) {
	dir, opts := validReviewFixture(t)
	verified, err := Verify(dir, opts)
	if err != nil {
		t.Fatalf("Verify directory: %v", err)
	}
	if verified.Manifest.Subject.Revision != opts.ExpectedSubject || len(verified.Manifest.Exceptions) != 2 || len(verified.Manifest.Limitations) != 1 {
		t.Fatalf("verification = %+v", verified)
	}

	first := filepath.Join(t.TempDir(), "first.tar.gz")
	second := filepath.Join(t.TempDir(), "second.tar.gz")
	_, firstHash, err := ExportBundle(dir, first, opts)
	if err != nil {
		t.Fatalf("ExportBundle first: %v", err)
	}
	_, secondHash, err := ExportBundle(dir, second, opts)
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
	if _, err := Verify(first, opts); err != nil {
		t.Fatalf("Verify archive: %v", err)
	}
}

func TestExportSourceObjectsIsDeterministic(t *testing.T) {
	repositories := newSourceObjectFixture(t)
	sets := []SourceObjectSet{
		{Name: "net", Directory: repositories.net.Directory, Revisions: []string{repositories.net.Revision}},
		{Name: "wago", Directory: repositories.wago.Directory, Revisions: append([]string{repositories.wago.Revision}, repositories.wago.Parents...)},
		{Name: "lneto", Directory: repositories.lneto.Directory, Revisions: []string{repositories.lneto.Revision}},
		{Name: "wasi", Directory: repositories.wasi.Directory, Revisions: []string{repositories.wasi.Revision}},
	}
	first, second := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	if err := ExportSourceObjects(first, sets); err != nil {
		t.Fatal(err)
	}
	if err := ExportSourceObjects(second, sets); err != nil {
		t.Fatal(err)
	}
	for _, set := range sets {
		for _, suffix := range []string{".objects", ".pack"} {
			left, err := os.ReadFile(filepath.Join(first, set.Name+suffix))
			if err != nil {
				t.Fatal(err)
			}
			right, err := os.ReadFile(filepath.Join(second, set.Name+suffix))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(left, right) {
				t.Fatalf("%s%s exports differ", set.Name, suffix)
			}
		}
	}
}

func TestVerifyRejectsTamperedEvidenceAndWrongSubject(t *testing.T) {
	dir, opts := validReviewFixture(t)
	wrong := opts
	wrong.ExpectedSubject = strings.Repeat("f", 40)
	if _, err := Verify(dir, wrong); err == nil {
		t.Fatal("wrong expected subject unexpectedly accepted")
	}
	writeTestFile(t, filepath.Join(dir, "arm64", "runner.txt"), "runner=forged\n")
	if _, err := Verify(dir, opts); err == nil {
		t.Fatal("tampered evidence unexpectedly accepted")
	}

	dir, opts = validReviewFixture(t)
	packPath := filepath.Join(dir, "source-objects", "wago.pack")
	pack, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	pack[len(pack)/2] ^= 0xff
	if err := os.WriteFile(packPath, pack, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, opts); err == nil {
		t.Fatal("tampered source-object pack unexpectedly accepted")
	}
}

func TestVerifyRejectsNoncanonicalOrPolicyDriftedManifest(t *testing.T) {
	dir, opts := validReviewFixture(t)
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
	if _, err := Verify(dir, opts); err == nil {
		t.Fatal("reordered Wago parents unexpectedly accepted")
	}
}

func validReviewFixture(t *testing.T) (string, VerifyOptions) {
	t.Helper()
	dir := t.TempDir()
	repositories := newSourceObjectFixture(t)
	subject := repositories.net.Revision
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
		{Name: "source-object-packs", Status: "pass"},
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
	writeTestFile(t, filepath.Join(dir, "revisions.txt"), "plugin: "+subject+"\nWago: "+repositories.wago.Revision+"\nlneto: "+repositories.lneto.Revision+"\nWASI: "+repositories.wasi.Revision+"\n")
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
	if err := ExportSourceObjects(filepath.Join(dir, "source-objects"), []SourceObjectSet{
		{Name: "net", Directory: repositories.net.Directory, Revisions: []string{repositories.net.Revision}},
		{Name: "wago", Directory: repositories.wago.Directory, Revisions: append([]string{repositories.wago.Revision}, repositories.wago.Parents...)},
		{Name: "lneto", Directory: repositories.lneto.Directory, Revisions: []string{repositories.lneto.Revision}},
		{Name: "wasi", Directory: repositories.wasi.Directory, Revisions: []string{repositories.wasi.Revision}},
	}); err != nil {
		t.Fatal(err)
	}
	artifacts, err := scanArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &Manifest{
		Schema:  SchemaV1,
		Subject: repositories.net.Repository,
		Inputs: []Repository{
			repositories.wago.Repository,
			repositories.lneto.Repository,
			repositories.wasi.Repository,
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
	return dir, VerifyOptions{
		ExpectedSubject: subject,
		expectedInputs: []Repository{
			repositories.wago.Repository,
			repositories.lneto.Repository,
			repositories.wasi.Repository,
		},
	}
}

type testSourceRepository struct {
	Repository
	Directory string
}

type testSourceRepositories struct {
	net, wago, lneto, wasi testSourceRepository
}

func newSourceObjectFixture(t *testing.T) testSourceRepositories {
	t.Helper()
	return testSourceRepositories{
		net:   newLinearSourceRepository(t, "net"),
		wago:  newMergeSourceRepository(t),
		lneto: newLinearSourceRepository(t, "lneto"),
		wasi:  newLinearSourceRepository(t, "wasi"),
	}
}

func newLinearSourceRepository(t *testing.T, name string) testSourceRepository {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
	runTestGit(t, "", "init", "--quiet", "--initial-branch=main", directory)
	writeTestFile(t, filepath.Join(directory, name+".txt"), name+" source\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", name+" source")
	return testRepositoryIdentity(t, directory, name, nil)
}

func newMergeSourceRepository(t *testing.T) testSourceRepository {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "wago")
	runTestGit(t, "", "init", "--quiet", "--initial-branch=main", directory)
	writeTestFile(t, filepath.Join(directory, "base.txt"), "base\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "base")
	base := testGitText(t, directory, "rev-parse", "HEAD")

	writeTestFile(t, filepath.Join(directory, "main.txt"), "main parent\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "main parent")
	parent1 := testGitText(t, directory, "rev-parse", "HEAD")

	runTestGit(t, directory, "checkout", "--quiet", "-b", "workers", base)
	writeTestFile(t, filepath.Join(directory, "workers.txt"), "worker parent\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "worker parent")
	parent2 := testGitText(t, directory, "rev-parse", "HEAD")

	runTestGit(t, directory, "checkout", "--quiet", "main")
	runTestGit(t, directory, "merge", "--quiet", "--no-ff", "-m", "merge parents", "workers")
	return testRepositoryIdentity(t, directory, "wago", []string{parent1, parent2})
}

func testRepositoryIdentity(t *testing.T, directory, name string, parents []string) testSourceRepository {
	t.Helper()
	return testSourceRepository{
		Repository: Repository{
			Name: name, Revision: testGitText(t, directory, "rev-parse", "HEAD"),
			Tree: testGitText(t, directory, "rev-parse", "HEAD^{tree}"), Parents: parents,
		},
		Directory: directory,
	}
}

func runTestGit(t *testing.T, directory string, args ...string) {
	t.Helper()
	commandArgs := append([]string{}, args...)
	if directory != "" {
		commandArgs = append([]string{"-C", directory}, commandArgs...)
	}
	command := exec.Command("git", commandArgs...)
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Release Test", "GIT_AUTHOR_EMAIL=release@example.com",
		"GIT_COMMITTER_NAME=Release Test", "GIT_COMMITTER_EMAIL=release@example.com",
		"GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z",
	)
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(commandArgs, " "), err, data)
	}
}

func testGitText(t *testing.T, directory string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", directory}, args...)
	data, err := exec.Command("git", commandArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(commandArgs, " "), err, data)
	}
	return strings.TrimSpace(string(data))
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
