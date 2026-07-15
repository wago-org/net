//go:build !tinygo

package releaseprovenance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBenchmarkSmokeDiscoveryEvidenceAndFailureAggregation(t *testing.T) {
	const packageA = "github.com/wago-org/net/internal/namespace/core"
	const packageB = "github.com/wago-org/net/internal/resource"

	t.Run("zero", func(t *testing.T) {
		result := runBenchmarkSmokeFixture(t, nil, "")
		if result.err == nil || !strings.Contains(result.output, "no benchmarks discovered") {
			t.Fatalf("zero-target result = %v\n%s", result.err, result.output)
		}
	})

	t.Run("one", func(t *testing.T) {
		result := runBenchmarkSmokeFixture(t, [][2]string{{packageB, "BenchmarkTableLookup"}}, "")
		if result.err != nil {
			t.Fatalf("benchmark smoke: %v\n%s", result.err, result.output)
		}
		assertTestFile(t, filepath.Join(result.evidence, "targets.tsv"), packageB+"\tBenchmarkTableLookup\n")
		assertTestFile(t, filepath.Join(result.evidence, "detail.txt"), "targets=1 packages=1 benchtime=100ms count=1 cpu=1 benchmem=true\n")
		logData, err := os.ReadFile(filepath.Join(result.evidence, "logs", packageB, "BenchmarkTableLookup.log"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(logData), "BenchmarkTableLookup-1") || !strings.Contains(string(logData), "B/op") {
			t.Fatalf("benchmark log = %q", logData)
		}
		invocations, err := os.ReadFile(result.invocations)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{packageB, "BenchmarkTableLookup", "-benchmem", "-benchtime=100ms", "-count=1", "-cpu=1"} {
			if !strings.Contains(string(invocations), required) {
				t.Fatalf("invocation missing %q: %s", required, invocations)
			}
		}
	})

	t.Run("multiple sorted and grouped", func(t *testing.T) {
		result := runBenchmarkSmokeFixture(t, [][2]string{
			{packageB, "BenchmarkTableClose"},
			{packageA, "BenchmarkComposeNamespace"},
			{packageB, "BenchmarkTableClose"},
		}, "")
		if result.err != nil {
			t.Fatalf("benchmark smoke: %v\n%s", result.err, result.output)
		}
		wantTargets := packageA + "\tBenchmarkComposeNamespace\n" + packageB + "\tBenchmarkTableClose\n"
		assertTestFile(t, filepath.Join(result.evidence, "targets.tsv"), wantTargets)
		assertTestFile(t, filepath.Join(result.evidence, "detail.txt"), "targets=2 packages=2 benchtime=100ms count=1 cpu=1 benchmem=true\n")
		for _, pair := range [][2]string{{packageA, "BenchmarkComposeNamespace"}, {packageB, "BenchmarkTableClose"}} {
			if _, err := os.Stat(filepath.Join(result.evidence, "logs", pair[0], pair[1]+".log")); err != nil {
				t.Fatalf("grouped log for %s %s: %v", pair[0], pair[1], err)
			}
		}
	})

	t.Run("continues after failure", func(t *testing.T) {
		result := runBenchmarkSmokeFixture(t, [][2]string{
			{packageB, "BenchmarkAFail"},
			{packageB, "BenchmarkZPass"},
		}, "BenchmarkAFail")
		if result.err == nil || !strings.Contains(result.output, "1 of 2 benchmarks failed") {
			t.Fatalf("failure aggregation result = %v\n%s", result.err, result.output)
		}
		invocations, err := os.ReadFile(result.invocations)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(invocations), "BenchmarkAFail") || !strings.Contains(string(invocations), "BenchmarkZPass") {
			t.Fatalf("runner stopped before all targets: %s", invocations)
		}
		for _, target := range []string{"BenchmarkAFail", "BenchmarkZPass"} {
			if _, err := os.Stat(filepath.Join(result.evidence, "logs", packageB, target+".log")); err != nil {
				t.Fatalf("failure-run log for %s: %v", target, err)
			}
		}
	})
}

type benchmarkSmokeResult struct {
	evidence    string
	invocations string
	output      string
	err         error
}

func runBenchmarkSmokeFixture(t *testing.T, pairs [][2]string, failTarget string) benchmarkSmokeResult {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeGo := `#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  if [[ $argument == -json ]]; then
    cat "$FAKE_BENCH_DISCOVERY"
    exit 0
  fi
done
package=$2
target=
previous=
for argument in "$@"; do
  if [[ $previous == -bench ]]; then
    target=${argument#^}
    target=${target%$}
  fi
  previous=$argument
done
printf '%s\t%s\t%s\n' "$package" "$target" "$*" >>"$FAKE_BENCH_INVOCATIONS"
if [[ -n ${FAKE_BENCH_FAIL_TARGET:-} && $target == "$FAKE_BENCH_FAIL_TARGET" ]]; then
  printf '%s-1\t1\t100 ns/op\t8 B/op\t1 allocs/op\n' "$target"
  exit 1
fi
printf '%s-1\t1\t100 ns/op\t8 B/op\t1 allocs/op\nPASS\n' "$target"
`
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0o755); err != nil {
		t.Fatal(err)
	}
	discovery := filepath.Join(tmp, "discovery.json")
	file, err := os.Create(discovery)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	for _, pair := range pairs {
		if err := encoder.Encode(map[string]string{"Package": pair[0], "Output": pair[1] + "\n"}); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(tmp, "evidence")
	invocations := filepath.Join(tmp, "invocations.tsv")
	command := exec.Command("bash", "../../scripts/benchmark-smoke.sh")
	command.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GOWORK=off",
		"BENCH_LOG_DIR="+evidence,
		"FAKE_BENCH_DISCOVERY="+discovery,
		"FAKE_BENCH_INVOCATIONS="+invocations,
		"FAKE_BENCH_FAIL_TARGET="+failTarget,
	)
	output, runErr := command.CombinedOutput()
	return benchmarkSmokeResult{evidence: evidence, invocations: invocations, output: string(output), err: runErr}
}

func assertTestFile(t testing.TB, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
}
