package releaseprovenance

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	platformRepositoryPackages = 128
	platformSupportedPackages  = 123
	platformExcludedPackages   = 5
	platformTLSTestTargets     = 109
)

var platformExcludedPackageNames = []string{
	"github.com/wago-org/net/internal/backend/gotls",
	"github.com/wago-org/net/internal/backend/lneto/tls",
	"github.com/wago-org/net/internal/dependencytest/testdata/tcptls",
	"github.com/wago-org/net/internal/dependencytest/testdata/tls",
	"github.com/wago-org/net/tls",
}

func validateTLSPlatformArtifacts(root string, checks []Check) error {
	if checkStatus(checks, "tls-standard-go") != "pass" {
		return fmt.Errorf("release provenance: schema-v3 evidence requires tls-standard-go")
	}
	if err := validateTLSArtifacts(root, checks); err != nil {
		return err
	}
	return validateTinyGoArtifacts(root, checks)
}

func validateTLSArtifacts(root string, checks []Check) error {
	detailData, err := os.ReadFile(filepath.Join(root, "tls", "detail.txt"))
	if err != nil {
		return err
	}
	detail := flattenCanonicalDetail(detailData)
	if detail == "" || detail != checkDetail(checks, "tls-standard-go") {
		return fmt.Errorf("release provenance: TLS detail does not match tls-standard-go check")
	}
	if err := validateTLSCheckDetails(detail, checkDetail(checks, "tinygo-test")); err != nil {
		return err
	}

	packageData, err := os.ReadFile(filepath.Join(root, "tls", "packages.tsv"))
	if err != nil {
		return err
	}
	packageRows, err := canonicalTSVRows(packageData, 4, "TLS package manifest")
	if err != nil {
		return err
	}
	if len(packageRows) != 17 {
		return fmt.Errorf("release provenance: TLS package run count %d, want 17", len(packageRows))
	}
	wantOrdinary := []string{
		"github.com/wago-org/net/internal/abi/tls",
		"github.com/wago-org/net/internal/backend/gotls",
		"github.com/wago-org/net/internal/backend/lneto/core",
		"github.com/wago-org/net/internal/backend/lneto/tcp",
		"github.com/wago-org/net/internal/backend/lneto/tls",
		"github.com/wago-org/net/internal/binding/tls",
		"github.com/wago-org/net/internal/dependencytest",
		"github.com/wago-org/net/internal/instance/tls",
		"github.com/wago-org/net/internal/namespace/tls",
		"github.com/wago-org/net/tls",
	}
	wantRace := []string{
		"github.com/wago-org/net/internal/backend/gotls",
		"github.com/wago-org/net/internal/backend/lneto/core",
		"github.com/wago-org/net/internal/backend/lneto/tcp",
		"github.com/wago-org/net/internal/backend/lneto/tls",
		"github.com/wago-org/net/internal/binding/tls",
		"github.com/wago-org/net/internal/instance/tls",
		"github.com/wago-org/net/tls",
	}
	var ordinary, race []string
	expectedLogs := make(map[string]struct{})
	for _, row := range packageRows {
		mode, packagePath := row[0], row[1]
		if mode == "ordinary" {
			ordinary = append(ordinary, packagePath)
		} else if mode == "race" {
			race = append(race, packagePath)
		} else {
			return fmt.Errorf("release provenance: invalid TLS test mode %q", mode)
		}
		relative := strings.TrimPrefix(packagePath, "github.com/wago-org/net/")
		if relative == packagePath || relative == "" {
			return fmt.Errorf("release provenance: invalid TLS package %q", packagePath)
		}
		expectedLogs[filepath.ToSlash(filepath.Join("tls", "logs", mode, relative, "list.log"))] = struct{}{}
		expectedLogs[filepath.ToSlash(filepath.Join("tls", "logs", mode, relative, "test.log"))] = struct{}{}
	}
	if !equalStrings(ordinary, wantOrdinary) || !equalStrings(race, wantRace) {
		return fmt.Errorf("release provenance: TLS package matrix differs from reviewed ordinary/race sets")
	}

	testData, err := os.ReadFile(filepath.Join(root, "tls", "tests.tsv"))
	if err != nil {
		return err
	}
	testRows, err := canonicalTSVRows(testData, 3, "TLS test manifest")
	if err != nil {
		return err
	}
	if len(testRows) != platformTLSTestTargets {
		return fmt.Errorf("release provenance: TLS test target count %d, want %d", len(testRows), platformTLSTestTargets)
	}
	testsByRun := make(map[string][]string)
	allTests := make(map[string]struct{}, len(testRows))
	for _, row := range testRows {
		if !strings.HasPrefix(row[2], "Test") {
			return fmt.Errorf("release provenance: invalid TLS test name %q", row[2])
		}
		key := row[0] + "\t" + row[1]
		testsByRun[key] = append(testsByRun[key], row[2])
		allTests[row[2]] = struct{}{}
	}
	for _, required := range []string{
		"TestRegisterExposesOnlyTLSAndSharedCore", "TestTCPAndTLSComposeWithoutCapabilityWidening",
		"TestUnknownRootFailsAuthentication", "TestWrongIPSANFailsAuthentication", "TestClientRejectsWrongHostname",
		"TestMissingAndInvalidIntermediateFailAuthentication", "TestCertificateValidityWindowIsEnforced",
		"TestRequiredALPNMissingFailsAuthentication", "TestTLSVersionBelowMinimumFailsClosed", "TestCorruptedRecordFailsTLSProtocol",
		"TestCloseDuringHandshakeJoinsWorkers", "TestTransportEOFConsumesExactlyOneServiceOperation",
		"TestCloseNotifyProducesStableEOFWithoutRepeatedServiceWork", "TestRawEOFWithoutCloseNotifyIsTLSProtocolFailure",
		"TestRawTCPThenTLSAndTLSThenRawShareLivePortDomain", "TestMixedTCPListenerPreventsTLSOutboundPortCollision",
		"TestCheckCreateRejectsOverlapAndOverflow", "TestTLSHandleIsCrossInstanceAndWrongKindSafe",
		"TestFixtureDependencyBoundaries", "TestSelfRegisterPackageDependencyBoundaries",
	} {
		if _, ok := allTests[required]; !ok {
			return fmt.Errorf("release provenance: required TLS test %q is absent", required)
		}
	}
	for key, tests := range testsByRun {
		mode, packagePath, _ := strings.Cut(key, "\t")
		relative := strings.TrimPrefix(packagePath, "github.com/wago-org/net/")
		for _, filename := range []string{"list.log", "test.log"} {
			data, err := os.ReadFile(filepath.Join(root, "tls", "logs", mode, relative, filename))
			if err != nil {
				return err
			}
			if len(data) == 0 {
				return fmt.Errorf("release provenance: empty TLS log for %s %s", mode, packagePath)
			}
			for _, test := range tests {
				if !bytes.Contains(data, []byte(test)) {
					return fmt.Errorf("release provenance: TLS log for %s %s omits %s", mode, packagePath, test)
				}
			}
		}
	}
	return validateExactLogInventory(root, filepath.Join(root, "tls", "logs"), expectedLogs, "TLS")
}

func validateTinyGoArtifacts(root string, checks []Check) error {
	detailData, err := os.ReadFile(filepath.Join(root, "tinygo", "detail.txt"))
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(detailData)), "\n")
	values := make(map[string]string)
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" {
			return fmt.Errorf("release provenance: malformed TinyGo detail line %q", line)
		}
		values[key] = value
	}
	if values["mode"] != "test" || values["tinygo_version"] == "" || values["repository_packages"] != "128" ||
		values["supported_packages"] != "123" || values["excluded_packages"] != "5" ||
		values["exclusion_root"] != "github.com/wago-org/net/internal/backend/gotls" || len(values) != 6 {
		return fmt.Errorf("release provenance: TinyGo detail does not match the reviewed supported surface")
	}
	checkWant := strings.Join([]string{
		"repository_packages=" + values["repository_packages"],
		"supported_packages=" + values["supported_packages"],
		"excluded_packages=" + values["excluded_packages"],
		"exclusion_root=" + values["exclusion_root"],
	}, " ")
	if checkDetail(checks, "tinygo-test") != checkWant {
		return fmt.Errorf("release provenance: TinyGo check detail does not match retained evidence")
	}

	supportedData, err := os.ReadFile(filepath.Join(root, "tinygo", "supported-packages.tsv"))
	if err != nil {
		return err
	}
	supportedRows, err := canonicalTSVRows(supportedData, 1, "TinyGo supported package manifest")
	if err != nil {
		return err
	}
	if len(supportedRows) != platformSupportedPackages {
		return fmt.Errorf("release provenance: TinyGo supported package count %d, want %d", len(supportedRows), platformSupportedPackages)
	}
	excludedData, err := os.ReadFile(filepath.Join(root, "tinygo", "excluded-packages.tsv"))
	if err != nil {
		return err
	}
	excludedRows, err := canonicalTSVRows(excludedData, 2, "TinyGo excluded package manifest")
	if err != nil {
		return err
	}
	if len(excludedRows) != platformExcludedPackages {
		return fmt.Errorf("release provenance: TinyGo excluded package count %d, want %d", len(excludedRows), platformExcludedPackages)
	}
	gotExcluded := make([]string, len(excludedRows))
	excluded := make(map[string]struct{}, len(excludedRows))
	for index, row := range excludedRows {
		gotExcluded[index] = row[0]
		excluded[row[0]] = struct{}{}
		if strings.TrimSpace(row[1]) == "" {
			return fmt.Errorf("release provenance: TinyGo exclusion %q has no reason", row[0])
		}
	}
	if !equalStrings(gotExcluded, platformExcludedPackageNames) {
		return fmt.Errorf("release provenance: TinyGo excluded package set differs from reviewed TLS closure")
	}
	expectedLogs := make(map[string]struct{}, len(supportedRows))
	supported := make(map[string]struct{}, len(supportedRows))
	for _, row := range supportedRows {
		packagePath := row[0]
		if packagePath != "github.com/wago-org/net" && !strings.HasPrefix(packagePath, "github.com/wago-org/net/") {
			return fmt.Errorf("release provenance: TinyGo supported package is outside the repository: %q", packagePath)
		}
		if _, isExcluded := excluded[packagePath]; isExcluded {
			return fmt.Errorf("release provenance: package %q is both supported and excluded", packagePath)
		}
		supported[packagePath] = struct{}{}
		relative := strings.TrimPrefix(packagePath, "github.com/wago-org/net")
		relative = strings.TrimPrefix(relative, "/")
		if relative == "" {
			relative = "_root"
		}
		expectedLogs[filepath.ToSlash(filepath.Join("tinygo", "logs", relative, "test.log"))] = struct{}{}
	}
	for _, required := range []string{"github.com/wago-org/net", "github.com/wago-org/net/register"} {
		if _, ok := supported[required]; !ok {
			return fmt.Errorf("release provenance: TinyGo supported package set omits %q", required)
		}
	}
	if _, ok := supported["github.com/wago-org/net/tls"]; ok {
		return fmt.Errorf("release provenance: public TLS package is incorrectly TinyGo-supported")
	}
	if len(supportedRows)+len(excludedRows) != platformRepositoryPackages {
		return fmt.Errorf("release provenance: TinyGo package manifests do not cover the repository package count")
	}
	return validateExactLogInventory(root, filepath.Join(root, "tinygo", "logs"), expectedLogs, "TinyGo")
}

func canonicalTSVRows(data []byte, fields int, label string) ([][]string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("release provenance: %s is empty or noncanonical", label)
	}
	var rows [][]string
	previous := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != fields || line <= previous {
			return nil, fmt.Errorf("release provenance: invalid or unsorted %s row %q", label, line)
		}
		for _, part := range parts {
			if part == "" {
				return nil, fmt.Errorf("release provenance: empty %s field", label)
			}
		}
		previous = line
		rows = append(rows, parts)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func validateExactLogInventory(root, logsRoot string, expected map[string]struct{}, label string) error {
	seen := make(map[string]struct{}, len(expected))
	if err := filepath.WalkDir(logsRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("release provenance: %s log is not regular: %s", label, path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, ok := expected[relative]; !ok {
			return fmt.Errorf("release provenance: unexpected %s log %q", label, relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return fmt.Errorf("release provenance: empty %s log %q", label, relative)
		}
		seen[relative] = struct{}{}
		return nil
	}); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("release provenance: %s logs are incomplete", label)
	}
	return nil
}

func flattenCanonicalDetail(data []byte) string {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return ""
	}
	return strings.Join(strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), " ")
}

func checkDetail(checks []Check, name string) string {
	for _, check := range checks {
		if check.Name == name {
			return check.Detail
		}
	}
	return ""
}
