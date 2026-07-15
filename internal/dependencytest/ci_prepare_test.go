//go:build !tinygo

package dependencytest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const lnetoModulePath = "github.com/soypat/" + "lneto"

func TestCIPrepareDependenciesSelectsExactWorktrees(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	scriptData, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "ci-prepare-dependencies.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []string{
		"97e6f91e6c822491577faa86f3c30aa5a8fff1e8",
		"ab1a0c735a8b534a1d6322a3e245bc11a09431e7",
	} {
		if !strings.Contains(string(scriptData), revision) {
			t.Fatalf("dependency preparation lost pinned revision %s", revision)
		}
	}

	temporary := t.TempDir()
	wagoRepository, wagoRevision := newFakeModuleRepository(t, filepath.Join(temporary, "repositories", "wago"), "github.com/wago-org/wago")
	lnetoRepository, lnetoRevision := newFakeModuleRepository(t, filepath.Join(temporary, "repositories", "lneto"), lnetoModulePath)
	checkout := filepath.Join(temporary, "checkout")
	if err := os.MkdirAll(filepath.Join(checkout, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, "scripts", "ci-prepare-dependencies.sh"), scriptData, 0o755); err != nil {
		t.Fatal(err)
	}
	goMod := "module example.com/ci-fixture\n\ngo 1.24\n\nrequire (\n\tgithub.com/wago-org/wago v0.1.0\n\t" + lnetoModulePath + " v0.0.0\n)\n\nreplace github.com/wago-org/wago => ../wago\n"
	if err := os.WriteFile(filepath.Join(checkout, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, "go.sum"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	githubEnv := filepath.Join(temporary, "github.env")

	command := exec.Command("bash", filepath.Join(checkout, "scripts", "ci-prepare-dependencies.sh"))
	command.Env = append(os.Environ(),
		"CI_WAGO_REPOSITORY="+wagoRepository,
		"CI_WAGO_REVISION="+wagoRevision,
		"CI_LNETO_REPOSITORY="+lnetoRepository,
		"CI_LNETO_REVISION="+lnetoRevision,
		"GITHUB_ENV="+githubEnv,
		"GOWORK=off",
		"GOPROXY=off",
		"GOTOOLCHAIN=local",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("dependency preparation: %v\n%s", err, output)
	}

	workspace := filepath.Join(checkout, ".audit", "ci.work")
	workspaceData, err := os.ReadFile(workspace)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"use ..",
		"github.com/wago-org/wago => ./wago",
		lnetoModulePath + " => ./lneto",
	} {
		if !strings.Contains(string(workspaceData), required) {
			t.Fatalf("generated workspace missing %q:\n%s", required, workspaceData)
		}
	}
	if data, err := os.ReadFile(githubEnv); err != nil || string(data) != "GOWORK="+workspace+"\n" {
		t.Fatalf("GITHUB_ENV = %q, %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(checkout, ".audit", "ci.env")); err != nil || string(data) != "export GOWORK="+workspace+"\n" {
		t.Fatalf("ci.env = %q, %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(checkout, "go.mod")); err != nil || string(data) != goMod {
		t.Fatalf("go.mod changed: %v\n%s", err, data)
	}
	if data, err := os.ReadFile(filepath.Join(checkout, "go.sum")); err != nil || len(data) != 0 {
		t.Fatalf("go.sum changed: %v\n%s", err, data)
	}
	if _, err := os.Stat(filepath.Join(temporary, "wago")); !os.IsNotExist(err) {
		t.Fatalf("fixture unexpectedly supplied sibling ../wago: %v", err)
	}

	assertWorkspaceModule(t, checkout, workspace, "github.com/wago-org/wago", filepath.Join(checkout, ".audit", "wago"), wagoRevision)
	assertWorkspaceModule(t, checkout, workspace, lnetoModulePath, filepath.Join(checkout, ".audit", "lneto"), lnetoRevision)

	wrong := exec.Command("bash", filepath.Join(checkout, "scripts", "ci-prepare-dependencies.sh"))
	wrong.Env = append(os.Environ(),
		"CI_WAGO_REPOSITORY="+wagoRepository,
		"CI_WAGO_REVISION="+strings.Repeat("0", 40),
		"CI_LNETO_REPOSITORY="+lnetoRepository,
		"CI_LNETO_REVISION="+lnetoRevision,
		"GOWORK=off",
		"GOPROXY=off",
		"GOTOOLCHAIN=local",
	)
	if output, err := wrong.CombinedOutput(); err == nil {
		t.Fatalf("wrong revision unexpectedly succeeded:\n%s", output)
	}
}

func newFakeModuleRepository(t *testing.T, directory, module string) (string, string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte("module "+module+"\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, directory, "init", "--quiet")
	runGit(t, directory, "add", "go.mod")
	runGit(t, directory, "-c", "user.name=CI Test", "-c", "user.email=ci@example.invalid", "commit", "--quiet", "-m", "fixture")
	return directory, strings.TrimSpace(runGit(t, directory, "rev-parse", "HEAD"))
}

func assertWorkspaceModule(t *testing.T, checkout, workspace, module, wantDirectory, wantRevision string) {
	t.Helper()
	command := exec.Command("go", "list", "-m", "-json", module)
	command.Dir = checkout
	command.Env = append(os.Environ(), "GOWORK="+workspace, "GOPROXY=off", "GOTOOLCHAIN=local")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("%s: %v", strings.Join(command.Args, " "), err)
	}
	var result struct {
		Replace *struct {
			Dir string
		}
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if result.Replace == nil {
		t.Fatalf("%s has no replacement", module)
	}
	gotDirectory, err := filepath.EvalSymlinks(result.Replace.Dir)
	if err != nil {
		t.Fatal(err)
	}
	wantDirectory, err = filepath.EvalSymlinks(wantDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if gotDirectory != wantDirectory {
		t.Fatalf("%s replacement = %s, want %s", module, gotDirectory, wantDirectory)
	}
	if revision := strings.TrimSpace(runGit(t, gotDirectory, "rev-parse", "HEAD")); revision != wantRevision {
		t.Fatalf("%s revision = %s, want %s", module, revision, wantRevision)
	}
}

func runGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(command.Args, " "), err, output)
	}
	return string(output)
}
