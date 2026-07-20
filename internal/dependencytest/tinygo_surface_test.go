//go:build !tinygo

package dependencytest

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestTinyGoExclusionManifestIsReviewedAndFailClosed(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "scripts", "tinygo-excluded-packages.tsv")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	rows := parseTinyGoManifest(t, manifest)
	if len(rows) == 0 {
		t.Fatal("TinyGo exclusion manifest is empty")
	}
	packages := make([]string, len(rows))
	for index, row := range rows {
		packages[index] = row[0]
		if strings.TrimSpace(row[1]) == "" {
			t.Fatalf("excluded package %q has no reason", row[0])
		}
	}
	if !sort.StringsAreSorted(packages) {
		t.Fatalf("excluded package manifest is not sorted: %v", packages)
	}
	for index := 1; index < len(packages); index++ {
		if packages[index] == packages[index-1] {
			t.Fatalf("duplicate excluded package %q", packages[index])
		}
	}

	runTinyGoBoundaryValidation(t, root, manifestPath, true)

	// Removing an actual TLS-closure package simulates unreviewed exclusion
	// growth: discovery must reject the now-unlisted package.
	withoutPublicTLS := make([][]string, 0, len(rows)-1)
	for _, row := range rows {
		if row[0] != modulePath+"/tls" {
			withoutPublicTLS = append(withoutPublicTLS, row)
		}
	}
	if len(withoutPublicTLS) == len(rows) {
		t.Fatal("public TLS exclusion is absent")
	}
	runTinyGoBoundaryValidation(t, root, writeTinyGoManifest(t, withoutPublicTLS), false)

	// Adding an unrelated supported package must not be accepted as an
	// exclusion merely because someone listed it in the manifest.
	withUnrelated := append([][]string(nil), rows...)
	withUnrelated = append(withUnrelated, []string{modulePath + "/udp", "unrelated exclusion must fail"})
	sort.Slice(withUnrelated, func(i, j int) bool { return withUnrelated[i][0] < withUnrelated[j][0] })
	runTinyGoBoundaryValidation(t, root, writeTinyGoManifest(t, withUnrelated), false)
}

func parseTinyGoManifest(t testing.TB, data []byte) [][]string {
	t.Helper()
	var rows [][]string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
			t.Fatalf("invalid TinyGo exclusion row %q", scanner.Text())
		}
		rows = append(rows, fields)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

func writeTinyGoManifest(t testing.TB, rows [][]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "excluded.tsv")
	var content strings.Builder
	for _, row := range rows {
		content.WriteString(row[0])
		content.WriteByte('\t')
		content.WriteString(row[1])
		content.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runTinyGoBoundaryValidation(t testing.TB, root, manifest string, wantSuccess bool) {
	t.Helper()
	bin := t.TempDir()
	fakeTinyGo := filepath.Join(bin, "tinygo")
	if err := os.WriteFile(fakeTinyGo, []byte("#!/bin/sh\necho 'tinygo version test-boundary'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(root, "scripts", "tinygo-supported-test.sh"))
	command.Dir = root
	command.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TINYGO_VALIDATE_ONLY=1",
		"TINYGO_EXCLUSION_MANIFEST="+manifest,
		"TINYGO_LOG_DIR="+filepath.Join(t.TempDir(), "evidence"),
	)
	output, err := command.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("TinyGo boundary validation failed: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("TinyGo boundary validation unexpectedly accepted manifest\n%s", output)
	}
}
