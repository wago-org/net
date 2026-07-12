//go:build !tinygo

package releaseprovenance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type testSourceRepository struct {
	Repository
	Directory string
}

type testSourceRepositories struct {
	net, wago, lneto, wasi, currentNet, currentWago, workers testSourceRepository
}

func newSourceObjectFixture(t *testing.T) testSourceRepositories {
	t.Helper()
	return testSourceRepositories{
		net:         newLinearSourceRepository(t, "net"),
		wago:        newMergeSourceRepository(t, "wago"),
		lneto:       newLinearSourceRepository(t, "lneto"),
		wasi:        newLinearSourceRepository(t, "wasi"),
		currentNet:  newReviewSourceRepository(t, "net-current-review"),
		currentWago: newReviewSourceRepository(t, "wago-current-review"),
		workers:     newMergeSourceRepository(t, "workers-current"),
	}
}

func fixtureSourceObjectSets(repositories testSourceRepositories) []SourceObjectSet {
	return []SourceObjectSet{
		{Name: "net", Directory: repositories.net.Directory, Revisions: []string{repositories.net.Revision}},
		{Name: "wago", Directory: repositories.wago.Directory, Revisions: append([]string{repositories.wago.Revision}, repositories.wago.Parents...)},
		{Name: "lneto", Directory: repositories.lneto.Directory, Revisions: []string{repositories.lneto.Revision}},
		{Name: "wasi", Directory: repositories.wasi.Directory, Revisions: []string{repositories.wasi.Revision}},
		{Name: "net-current-review", Directory: repositories.currentNet.Directory, Revisions: []string{repositories.currentNet.Revision}},
		{Name: "wago-current-review", Directory: repositories.currentWago.Directory, Revisions: []string{repositories.currentWago.Revision}},
		{Name: "workers-current", Directory: repositories.workers.Directory, Revisions: []string{repositories.workers.Revision}},
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

func newReviewSourceRepository(t *testing.T, name string) testSourceRepository {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
	runTestGit(t, "", "init", "--quiet", "--initial-branch=main", directory)
	writeTestFile(t, filepath.Join(directory, "base.txt"), "base\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "base")
	parent := testGitText(t, directory, "rev-parse", "HEAD")
	writeTestFile(t, filepath.Join(directory, name+".txt"), name+" source\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", name+" review")
	return testRepositoryIdentity(t, directory, name, []string{parent})
}

func newMergeSourceRepository(t *testing.T, name string) testSourceRepository {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
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
	return testRepositoryIdentity(t, directory, name, []string{parent1, parent2})
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
