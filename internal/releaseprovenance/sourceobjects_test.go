package releaseprovenance

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareSourceObjectOutputDirectoryRejectsUnsafePaths(t *testing.T) {
	repositories := newSourceObjectFixture(t)
	sets := fixtureSourceObjectSets(repositories)
	repoRoot := repositories.net.Directory
	homeDir := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workingDir := filepath.Join(t.TempDir(), "working")
	if err := os.MkdirAll(workingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(repoRoot, ".wago")
	if err := os.MkdirAll(artifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	unsafeLink := filepath.Join(artifactRoot, "unsafe-link")
	if err := os.Symlink(homeDir, unsafeLink); err != nil {
		t.Fatal(err)
	}

	options := SourceObjectExportOptions{
		RepositoryRoot:   repoRoot,
		WorkingDirectory: workingDir,
		HomeDirectory:    homeDir,
	}
	for _, test := range []struct {
		name    string
		output  string
		wantErr string
	}{
		{name: "filesystem root", output: string(filepath.Separator), wantErr: "filesystem root"},
		{name: "repository root", output: repoRoot, wantErr: "source repository"},
		{name: "repository parent", output: filepath.Dir(repoRoot), wantErr: "source repository"},
		{name: "home directory", output: homeDir, wantErr: "home directory"},
		{name: "source repository directory", output: repositories.wago.Directory, wantErr: "source repository"},
		{name: "ancestor of source repository", output: filepath.Dir(repositories.wago.Directory), wantErr: "source repository"},
		{name: "current working directory", output: workingDir, wantErr: "current working directory"},
		{name: "symlink resolving to unsafe directory", output: filepath.Join(unsafeLink, "source-objects"), wantErr: "resolves through"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareSourceObjectOutputDirectory(test.output, sets, options)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("prepare(%q) error = %v, want substring %q", test.output, err, test.wantErr)
			}
		})
	}
}

func TestPrepareSourceObjectOutputDirectoryAllowsArtifactSubdirectory(t *testing.T) {
	repositories := newSourceObjectFixture(t)
	sets := fixtureSourceObjectSets(repositories)
	repoRoot := repositories.net.Directory
	homeDir := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workingDir := filepath.Join(t.TempDir(), "working")
	if err := os.MkdirAll(workingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(repoRoot, ".wago", "release-signoff", "source-objects")
	prepared, err := prepareSourceObjectOutputDirectory(outputDir, sets, SourceObjectExportOptions{
		RepositoryRoot:   repoRoot,
		WorkingDirectory: workingDir,
		HomeDirectory:    homeDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, _, err := resolveArtifactPath(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.outputDir != resolved {
		t.Fatalf("prepared output = %q, want %q", prepared.outputDir, resolved)
	}
}

func TestExportSourceObjectsReplacesExistingDirectoryAtomically(t *testing.T) {
	repositories := newSourceObjectFixture(t)
	sets := fixtureSourceObjectSets(repositories)
	outputDir := filepath.Join(repositories.net.Directory, ".wago", "release-signoff", "source-objects")
	options := SourceObjectExportOptions{RepositoryRoot: repositories.net.Directory}
	if err := ExportSourceObjectsWithOptions(outputDir, sets, options); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(outputDir, "stale.txt"), "stale\n")
	if err := ExportSourceObjectsWithOptions(outputDir, sets, options); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "stale.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale file stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "net.pack")); err != nil {
		t.Fatalf("replacement output missing net.pack: %v", err)
	}
}

func TestReplaceDirectoryAtomicallyPreservesPreviousOutputOnFailure(t *testing.T) {
	repositories := newSourceObjectFixture(t)
	sets := fixtureSourceObjectSets(repositories)
	outputDir := filepath.Join(repositories.net.Directory, ".wago", "release-signoff", "source-objects")
	prepared, err := prepareSourceObjectOutputDirectory(outputDir, sets, SourceObjectExportOptions{RepositoryRoot: repositories.net.Directory})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prepared.outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(prepared.outputDir, "keep.txt"), "previous\n")
	boom := errors.New("boom")
	if err := replaceDirectoryAtomically(prepared.outputDir, func(stageDir string) error {
		writeTestFile(t, filepath.Join(stageDir, "keep.txt"), "next\n")
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("replace error = %v, want %v", err, boom)
	}
	data, err := os.ReadFile(filepath.Join(prepared.outputDir, "keep.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "previous\n" {
		t.Fatalf("preserved output = %q, want previous", data)
	}
}
