//go:build !tinygo

package releaseprovenance

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestTLSPlatformEvidenceValidation(t *testing.T) {
	checks := platformFixture(t)
	if err := validateTLSPlatformArtifacts(t.TempDir(), checks); err == nil {
		t.Fatal("missing platform artifacts unexpectedly accepted")
	}

	t.Run("positive", func(t *testing.T) {
		dir := t.TempDir()
		writePlatformFixture(t, dir)
		if err := validateTLSPlatformArtifacts(dir, checks); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing artifact", func(t *testing.T) {
		dir := t.TempDir()
		writePlatformFixture(t, dir)
		if err := os.Remove(filepath.Join(dir, "tinygo", "detail.txt")); err != nil {
			t.Fatal(err)
		}
		if err := validateTLSPlatformArtifacts(dir, checks); err == nil {
			t.Fatal("missing TinyGo detail unexpectedly accepted")
		}
	})
	t.Run("extra artifact", func(t *testing.T) {
		dir := t.TempDir()
		writePlatformFixture(t, dir)
		writeTestFile(t, filepath.Join(dir, "tls", "logs", "extra.log"), "unexpected\n")
		if err := validateTLSPlatformArtifacts(dir, checks); err == nil {
			t.Fatal("extra TLS log unexpectedly accepted")
		}
	})
	t.Run("wrong package count", func(t *testing.T) {
		dir := t.TempDir()
		writePlatformFixture(t, dir)
		path := filepath.Join(dir, "tinygo", "supported-packages.tsv")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		writeTestFile(t, path, strings.Join(lines[:len(lines)-1], "\n")+"\n")
		if err := validateTLSPlatformArtifacts(dir, checks); err == nil {
			t.Fatal("wrong TinyGo package count unexpectedly accepted")
		}
	})
	t.Run("incorrect exclusion", func(t *testing.T) {
		dir := t.TempDir()
		writePlatformFixture(t, dir)
		path := filepath.Join(dir, "tinygo", "excluded-packages.tsv")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, path, strings.Replace(string(data), "github.com/wago-org/net/tls\t", "github.com/wago-org/net/udp\t", 1))
		if err := validateTLSPlatformArtifacts(dir, checks); err == nil {
			t.Fatal("incorrect TinyGo exclusion unexpectedly accepted")
		}
	})
}

func platformFixture(t testing.TB) []Check {
	t.Helper()
	return []Check{
		{Name: "tls-standard-go", Status: "pass", Detail: "standard_go_tls=tested aggregate_registration=absent self_registration=absent scope=outbound-client-only ordinary_packages=10 race_packages=7 test_targets=109 package_runs=17"},
		{Name: "tinygo-test", Status: "pass", Detail: "repository_packages=128 supported_packages=123 excluded_packages=5 exclusion_root=github.com/wago-org/net/internal/backend/gotls"},
	}
}

func writePlatformFixture(t testing.TB, dir string) {
	t.Helper()
	checks := platformFixture(t)
	tlsDetail := strings.ReplaceAll(checks[0].Detail, " ", "\n") + "\n"
	writeTestFile(t, filepath.Join(dir, "tls", "detail.txt"), tlsDetail)
	packageData, err := os.ReadFile("../../scripts/tls-signoff-packages.tsv")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "tls", "packages.tsv"), string(packageData))
	packageRows, err := canonicalTSVRows(packageData, 4, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"TestRegisterExposesOnlyTLSAndSharedCore", "TestTCPAndTLSComposeWithoutCapabilityWidening",
		"TestUnknownRootFailsAuthentication", "TestWrongIPSANFailsAuthentication", "TestClientRejectsWrongHostname",
		"TestMissingAndInvalidIntermediateFailAuthentication", "TestCertificateValidityWindowIsEnforced",
		"TestRequiredALPNMissingFailsAuthentication", "TestTLSVersionBelowMinimumFailsClosed", "TestCorruptedRecordFailsTLSProtocol",
		"TestCloseDuringHandshakeJoinsWorkers", "TestTransportEOFConsumesExactlyOneServiceOperation",
		"TestCloseNotifyProducesStableEOFWithoutRepeatedServiceWork", "TestRawEOFWithoutCloseNotifyIsTLSProtocolFailure",
		"TestRawTCPThenTLSAndTLSThenRawShareLivePortDomain", "TestMixedTCPListenerPreventsTLSOutboundPortCollision",
		"TestCheckCreateRejectsOverlapAndOverflow", "TestTLSHandleIsCrossInstanceAndWrongKindSafe",
		"TestFixtureDependencyBoundaries", "TestSelfRegisterPackageDependencyBoundaries",
	}
	var testRows []string
	testsByRun := make(map[string][]string)
	for index, row := range packageRows {
		name := fmt.Sprintf("TestPlatformRun%02d", index)
		key := row[0] + "\t" + row[1]
		testsByRun[key] = append(testsByRun[key], name)
		testRows = append(testRows, key+"\t"+name)
	}
	for index, name := range required {
		row := packageRows[index%len(packageRows)]
		key := row[0] + "\t" + row[1]
		testsByRun[key] = append(testsByRun[key], name)
		testRows = append(testRows, key+"\t"+name)
	}
	for len(testRows) < platformTLSTestTargets {
		index := len(testRows)
		row := packageRows[index%len(packageRows)]
		name := fmt.Sprintf("TestPlatformSynthetic%03d", index)
		key := row[0] + "\t" + row[1]
		testsByRun[key] = append(testsByRun[key], name)
		testRows = append(testRows, key+"\t"+name)
	}
	sort.Strings(testRows)
	writeTestFile(t, filepath.Join(dir, "tls", "tests.tsv"), strings.Join(testRows, "\n")+"\n")
	for key, tests := range testsByRun {
		mode, packagePath, _ := strings.Cut(key, "\t")
		relative := strings.TrimPrefix(packagePath, "github.com/wago-org/net/")
		content := strings.Join(tests, "\n") + "\nPASS\n"
		writeTestFile(t, filepath.Join(dir, "tls", "logs", mode, relative, "list.log"), content)
		writeTestFile(t, filepath.Join(dir, "tls", "logs", mode, relative, "test.log"), content)
	}

	writeTestFile(t, filepath.Join(dir, "tinygo", "detail.txt"), "mode=test\ntinygo_version=tinygo version fixture\nrepository_packages=128\nsupported_packages=123\nexcluded_packages=5\nexclusion_root=github.com/wago-org/net/internal/backend/gotls\n")
	var supported []string
	supported = append(supported, "github.com/wago-org/net", "github.com/wago-org/net/register")
	for index := 0; len(supported) < platformSupportedPackages; index++ {
		supported = append(supported, fmt.Sprintf("github.com/wago-org/net/synthetic%03d", index))
	}
	sort.Strings(supported)
	writeTestFile(t, filepath.Join(dir, "tinygo", "supported-packages.tsv"), strings.Join(supported, "\n")+"\n")
	for _, packagePath := range supported {
		relative := strings.TrimPrefix(packagePath, "github.com/wago-org/net")
		relative = strings.TrimPrefix(relative, "/")
		if relative == "" {
			relative = "_root"
		}
		writeTestFile(t, filepath.Join(dir, "tinygo", "logs", relative, "test.log"), "PASS "+packagePath+"\n")
	}
	var excluded strings.Builder
	for _, packagePath := range platformExcludedPackageNames {
		excluded.WriteString(packagePath + "\treviewed standard-Go-only TLS closure\n")
	}
	writeTestFile(t, filepath.Join(dir, "tinygo", "excluded-packages.tsv"), excluded.String())
}
