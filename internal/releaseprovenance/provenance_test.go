package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	writeTestFile(t, filepath.Join(dir, "inspection-net-go.json"), inspection)
	writeTestFile(t, filepath.Join(dir, "inspection-net-tinygo.json"), inspection)
	got, err := readBundleInspection(dir, "net")
	if err != nil {
		t.Fatal(err)
	}
	if !got.GoTinyGoEqual || got.ImportCount != 3 || got.ImportsByModule["wago_net_udp"] != 2 {
		t.Fatalf("inspection = %+v", got)
	}
}

func TestInspectionEvidenceRejectsStaleAggregateAndRequiresEveryBundle(t *testing.T) {
	dir := t.TempDir()
	writeCanonicalInspectionEvidence(t, dir)
	var current Inspection
	if err := readInspection(dir, &current); err != nil {
		t.Fatalf("current all-protocol inspection: %v", err)
	}
	if len(current.Capabilities) != 12 || current.ImportCount != 84 {
		t.Fatalf("current aggregate = %d capabilities, %d imports", len(current.Capabilities), current.ImportCount)
	}

	stale := `{"capabilities":["net.dns","net.info","net.tcp","net.udp"],"imports":[{"module":"wago_net"},{"module":"wago_net_dns"},{"module":"wago_net_tcp"},{"module":"wago_net_udp"}]}`
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-net-go.json"), stale)
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-net-tinygo.json"), stale)
	if err := readInspection(dir, new(Inspection)); err == nil {
		t.Fatal("stale four-capability aggregate unexpectedly accepted")
	}

	dir = t.TempDir()
	writeCanonicalInspectionEvidence(t, dir)
	if err := os.Remove(filepath.Join(dir, "custom-cli", "inspection-net-udp-tinygo.json")); err != nil {
		t.Fatal(err)
	}
	if err := readInspection(dir, new(Inspection)); err == nil {
		t.Fatal("missing granular TinyGo inspection unexpectedly accepted")
	}
}

func TestReadBenchmarkEvidenceRequiresCanonicalNonEmptyCompleteLogs(t *testing.T) {
	pairs := [][2]string{
		{"github.com/wago-org/net/internal/resource", "BenchmarkTableLookup"},
		{"github.com/wago-org/net/internal/namespace/core", "BenchmarkComposeNamespace"},
	}
	dir := t.TempDir()
	facts := writeBenchmarkEvidence(t, dir, pairs)
	checks := []Check{{Name: releaseBenchmarkCheck, Status: "pass", Detail: benchmarkDetail(facts)}}
	got, err := readBenchmarkEvidence(dir, checks)
	if err != nil {
		t.Fatalf("current benchmark evidence: %v", err)
	}
	if got != facts {
		t.Fatalf("benchmark facts = %+v, want %+v", got, facts)
	}

	writeTestFile(t, filepath.Join(dir, "benchmark", "detail.txt"), "targets=99 packages=99 benchtime=100ms count=1 cpu=1 benchmem=true\n")
	if _, err := readBenchmarkEvidence(dir, checks); err == nil {
		t.Fatal("tampered benchmark detail unexpectedly accepted")
	}

	dir = t.TempDir()
	facts = writeBenchmarkEvidence(t, dir, pairs)
	checks[0].Detail = benchmarkDetail(facts)
	if err := os.Remove(filepath.Join(dir, "benchmark", "logs", pairs[0][0], pairs[0][1]+".log")); err != nil {
		t.Fatal(err)
	}
	if _, err := readBenchmarkEvidence(dir, checks); err == nil {
		t.Fatal("missing per-target benchmark log unexpectedly accepted")
	}

	dir = t.TempDir()
	writeTestFile(t, filepath.Join(dir, "benchmark", "targets.tsv"), "")
	if _, err := readBenchmarkEvidence(dir, checks); err == nil {
		t.Fatal("empty benchmark target manifest unexpectedly accepted")
	}
}

func TestReadChecksRejectsMalformedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checks.tsv")
	writeTestFile(t, path, "missing-status\n")
	if _, err := readChecks(path); err == nil {
		t.Fatal("malformed checks unexpectedly accepted")
	}
}

func writeBenchmarkEvidence(t testing.TB, dir string, pairs [][2]string) BenchmarkEvidence {
	t.Helper()
	pairs = append([][2]string(nil), pairs...)
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	packages := make(map[string]struct{})
	var targets strings.Builder
	for _, pair := range pairs {
		packages[pair[0]] = struct{}{}
		targets.WriteString(pair[0] + "\t" + pair[1] + "\n")
		writeTestFile(t, filepath.Join(dir, "benchmark", "logs", pair[0], pair[1]+".log"),
			pair[1]+"-1\t1\t100 ns/op\t8 B/op\t1 allocs/op\n")
	}
	writeTestFile(t, filepath.Join(dir, "benchmark", "targets.tsv"), targets.String())
	facts := BenchmarkEvidence{
		TargetCount: len(pairs), PackageCount: len(packages), Benchtime: releaseBenchmarkBenchtime,
		Count: releaseBenchmarkCount, CPU: releaseBenchmarkCPU, Benchmem: true,
	}
	writeTestFile(t, filepath.Join(dir, "benchmark", "detail.txt"), benchmarkDetail(facts)+"\n")
	return facts
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
