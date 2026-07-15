package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanArtifactsIsSortedChecksummedAndExcludesProvenance(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "z.txt"), "z")
	writeTestFile(t, filepath.Join(dir, "bench-poll.txt"), "bench")
	writeTestFile(t, filepath.Join(dir, "fuzz", "github.com", "wago-org", "net", "FuzzGuestDNSMemory.log"), "fuzz")
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-go.json"), "inspection")
	writeTestFile(t, filepath.Join(dir, "provenance.json"), "exclude")
	writeTestFile(t, filepath.Join(dir, "provenance.sha256"), "exclude")
	writeTestFile(t, filepath.Join(dir, "evidence.sha256"), "exclude")

	got, err := scanArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"bench-poll.txt", "custom-cli/inspection-go.json", "fuzz/github.com/wago-org/net/FuzzGuestDNSMemory.log", "z.txt"}
	var gotPaths []string
	for _, artifact := range got {
		gotPaths = append(gotPaths, artifact.Path)
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("artifact paths = %v, want %v", gotPaths, wantPaths)
	}
	if got[0].Kind != "benchmark" || got[1].Kind != "inspection" || got[2].Kind != "fuzz" || got[3].Kind != "support" {
		t.Fatalf("artifact kinds = %q %q %q %q", got[0].Kind, got[1].Kind, got[2].Kind, got[3].Kind)
	}
	sum := sha256.Sum256([]byte("bench"))
	if got[0].SHA256 != hex.EncodeToString(sum[:]) || got[0].Size != 5 {
		t.Fatalf("benchmark artifact = %+v", got[0])
	}
}

func TestReadChecksAndInspection(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "checks.tsv"), "go-test\tpass\nknown\taccepted-exception\tdocumented\n")
	checks, err := readChecks(filepath.Join(dir, "checks.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if got := checkStatus(checks, "go-test"); got != "pass" {
		t.Fatalf("go-test status = %q", got)
	}
	if checks[1].Detail != "documented" || checkStatus(checks, "missing") != "missing" {
		t.Fatalf("checks = %+v", checks)
	}

	inspection := `{"capabilities":["net.dns","net.info","net.tcp","net.udp"],"imports":[{"module":"wago_net"},{"module":"wago_net_udp"},{"module":"wago_net_udp"}]}`
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-go.json"), inspection)
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-tinygo.json"), inspection)
	var got Inspection
	if err := readInspection(dir, &got); err != nil {
		t.Fatal(err)
	}
	if !got.GoTinyGoEqual || got.ImportCount != 3 || got.ImportsByModule["wago_net_udp"] != 2 {
		t.Fatalf("inspection = %+v", got)
	}
}

func TestReadChecksRejectsMalformedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checks.tsv")
	writeTestFile(t, path, "missing-status\n")
	if _, err := readChecks(path); err == nil {
		t.Fatal("malformed checks unexpectedly accepted")
	}
}

func writeTestFile(t testing.TB, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
