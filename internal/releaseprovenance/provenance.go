// Package releaseprovenance emits deterministic machine-readable release evidence.
package releaseprovenance

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/wago-org/net/internal/inspectionpolicy"
)

const (
	SchemaV2 = "github.com/wago-org/net/release-provenance/v2"
	SchemaV3 = "github.com/wago-org/net/release-provenance/v3"
)

type Config struct {
	OutputDir      string
	PluginDir      string
	WagoDir        string
	LnetoDir       string
	WASIDir        string
	CurrentNetDir  string
	CurrentWagoDir string
	WorkersDir     string
	CrossGOOS      string
	CrossGOARCH    string
}

type Manifest struct {
	Schema         string            `json:"schema"`
	Subject        Repository        `json:"subject"`
	Inputs         []Repository      `json:"inputs"`
	ReviewSubjects []Repository      `json:"reviewSubjects"`
	Publication    PublicationStatus `json:"publication"`
	Toolchains     Toolchains        `json:"toolchains"`
	Inspection     Inspection        `json:"inspection"`
	Benchmarks     BenchmarkEvidence `json:"benchmarks"`
	Targets        Targets           `json:"targets"`
	Checks         []Check           `json:"checks"`
	Artifacts      []Artifact        `json:"artifacts"`
	Exceptions     []Exception       `json:"acceptedExceptions,omitempty"`
	Limitations    []Limitation      `json:"limitations,omitempty"`
}

type Repository struct {
	Name     string   `json:"name"`
	Revision string   `json:"revision"`
	Tree     string   `json:"tree"`
	Parents  []string `json:"parents,omitempty"`
}

type PublicationStatus struct {
	CurrentPlugin           string `json:"currentPlugin"`
	ProductionWagoMerge     string `json:"productionWagoMerge"`
	ExternalWorkers         string `json:"externalWorkers"`
	Pooling                 string `json:"pooling"`
	PublisherAuthentication string `json:"publisherAuthentication"`
	HostedReleaseAutomation string `json:"hostedReleaseAutomation"`
}

type Toolchains struct {
	Go     string `json:"go"`
	TinyGo string `json:"tinygo"`
}

type Inspection struct {
	SHA256          string         `json:"sha256"`
	GoTinyGoEqual   bool           `json:"goTinyGoByteIdentical"`
	Capabilities    []string       `json:"capabilities"`
	ImportCount     int            `json:"importCount"`
	ImportsByModule map[string]int `json:"importsByModule"`
}

type BenchmarkEvidence struct {
	TargetCount  int    `json:"targetCount"`
	PackageCount int    `json:"packageCount"`
	Benchtime    string `json:"benchtime"`
	Count        int    `json:"count"`
	CPU          int    `json:"cpu"`
	Benchmem     bool   `json:"benchmem"`
}

type Targets struct {
	CrossBuild     TargetResult `json:"crossBuild"`
	Arm64Execution TargetResult `json:"arm64Execution"`
}

type TargetResult struct {
	GOOS         string         `json:"goos"`
	GOARCH       string         `json:"goarch"`
	Status       string         `json:"status"`
	Runner       string         `json:"runner,omitempty"`
	BinarySHA256 string         `json:"binarySha256,omitempty"` // Historical single-binary evidence.
	Binaries     []TargetBinary `json:"binaries,omitempty"`
}

type TargetBinary struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Artifact struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Exception struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Limitation struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Generate(cfg Config) (*Manifest, error) {
	checks, err := readChecks(filepath.Join(cfg.OutputDir, "checks.tsv"))
	if err != nil {
		return nil, err
	}
	manifest := &Manifest{
		Schema:  SchemaV3,
		Subject: repo(cfg.PluginDir, "net", false),
		Inputs: []Repository{
			repo(cfg.WagoDir, "wago", true),
			repo(cfg.LnetoDir, "lneto", false),
			repo(cfg.WASIDir, "wasi", false),
		},
		ReviewSubjects: []Repository{
			repo(cfg.CurrentNetDir, "net-current-review", true),
			repo(cfg.CurrentWagoDir, "wago-current-review", true),
			repo(cfg.WorkersDir, "workers-current", true),
		},
		Checks: checks,
		Targets: Targets{
			CrossBuild: TargetResult{GOOS: cfg.CrossGOOS, GOARCH: cfg.CrossGOARCH, Status: checkStatus(checks, "cross-build")},
		},
	}
	repositories := append([]Repository{manifest.Subject}, manifest.Inputs...)
	repositories = append(repositories, manifest.ReviewSubjects...)
	for _, repository := range repositories {
		if repository.Revision == "" || repository.Tree == "" {
			return nil, fmt.Errorf("release provenance: cannot resolve %s repository", repository.Name)
		}
	}
	if err := readPublication(filepath.Join(cfg.OutputDir, "publication.txt"), &manifest.Publication); err != nil {
		return nil, err
	}
	if err := readToolchains(filepath.Join(cfg.OutputDir, "toolchains.txt"), &manifest.Toolchains); err != nil {
		return nil, err
	}
	if err := readInspection(cfg.OutputDir, &manifest.Inspection); err != nil {
		return nil, err
	}
	manifest.Benchmarks, err = readBenchmarkEvidence(cfg.OutputDir, checks)
	if err != nil {
		return nil, err
	}
	if manifest.Targets.CrossBuild.Status != "pass" {
		return nil, fmt.Errorf("release provenance: cross-build status is %q, want pass", manifest.Targets.CrossBuild.Status)
	}
	if err := readArm64(cfg.OutputDir, &manifest.Targets.Arm64Execution); err != nil {
		return nil, err
	}
	if status := manifest.Targets.Arm64Execution.Status; !strings.HasPrefix(status, "executed-") && !strings.HasPrefix(status, "skipped-") {
		return nil, fmt.Errorf("release provenance: invalid arm64 execution status %q", status)
	}
	if err := validateTLSPlatformArtifacts(cfg.OutputDir, checks); err != nil {
		return nil, err
	}
	manifest.Artifacts, err = scanArtifacts(cfg.OutputDir)
	if err != nil {
		return nil, err
	}
	for _, check := range checks {
		if check.Status == "accepted-exception" {
			manifest.Exceptions = append(manifest.Exceptions, Exception{ID: check.Name, Status: check.Status, Detail: check.Detail})
		}
	}
	if strings.HasPrefix(manifest.Targets.Arm64Execution.Status, "skipped-") {
		manifest.Limitations = append(manifest.Limitations, Limitation{
			ID: "linux-arm64-execution", Status: manifest.Targets.Arm64Execution.Status,
			Detail: "cross-build passed, but this release gate did not execute the arm64 smoke binaries",
		})
	}
	if checkStatus(checks, "tls-standard-go") == "pass" {
		manifest.Limitations = append(manifest.Limitations, Limitation{
			ID: "tls-tinygo", Status: "unsupported-explicit",
			Detail: "outbound client TLS is tested under standard Go and intentionally unavailable under TinyGo; no stub or guest module is registered",
		})
	}
	return manifest, nil
}

func Write(cfg Config) error {
	manifest, err := Generate(cfg)
	if err != nil {
		return err
	}
	if err := writeEvidenceChecksums(cfg.OutputDir, manifest.Artifacts); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	manifestPath := filepath.Join(cfg.OutputDir, "provenance.json")
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	line := hex.EncodeToString(sum[:]) + "  provenance.json\n"
	return os.WriteFile(filepath.Join(cfg.OutputDir, "provenance.sha256"), []byte(line), 0o644)
}

func repo(dir, name string, parents bool) Repository {
	r := Repository{Name: name, Revision: git(dir, "rev-parse", "HEAD"), Tree: git(dir, "rev-parse", "HEAD^{tree}")}
	if parents {
		fields := strings.Fields(git(dir, "rev-list", "--parents", "-n", "1", "HEAD"))
		if len(fields) > 1 {
			r.Parents = append([]string(nil), fields[1:]...)
		}
	}
	return r
}

func git(dir string, args ...string) string {
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readChecks(path string) ([]Check, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var checks []Check
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 2 || len(fields) > 3 || fields[0] == "" || fields[1] == "" {
			return nil, fmt.Errorf("release provenance: malformed check line %q", scanner.Text())
		}
		if _, duplicate := seen[fields[0]]; duplicate {
			return nil, fmt.Errorf("release provenance: duplicate check %q", fields[0])
		}
		seen[fields[0]] = struct{}{}
		check := Check{Name: fields[0], Status: fields[1]}
		if len(fields) == 3 {
			check.Detail = fields[2]
		}
		checks = append(checks, check)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return checks, nil
}

func checkStatus(checks []Check, name string) string {
	for _, check := range checks {
		if check.Name == name {
			return check.Status
		}
	}
	return "missing"
}

func readPublication(path string, dst *PublicationStatus) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) != 7 || lines[6] != "" {
		return fmt.Errorf("release provenance: publication status is not canonical")
	}
	values := []*string{
		&dst.CurrentPlugin, &dst.ProductionWagoMerge, &dst.ExternalWorkers,
		&dst.Pooling, &dst.PublisherAuthentication, &dst.HostedReleaseAutomation,
	}
	keys := []string{
		"current_plugin", "production_wago_merge", "external_workers",
		"pooling", "publisher_authentication", "hosted_release_automation",
	}
	for i, key := range keys {
		gotKey, value, ok := strings.Cut(lines[i], "=")
		if !ok || gotKey != key || value == "" {
			return fmt.Errorf("release provenance: publication status line %d is not canonical", i+1)
		}
		*values[i] = value
	}
	return nil
}

func readToolchains(path string, dst *Toolchains) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch key {
		case "go":
			dst.Go = value
		case "tinygo":
			dst.TinyGo = strings.TrimSpace(value)
		}
	}
	if dst.Go == "" || dst.TinyGo == "" {
		return fmt.Errorf("release provenance: incomplete toolchains file")
	}
	return nil
}

func readInspection(out string, dst *Inspection) error {
	policyData, err := os.ReadFile(filepath.Join(out, "custom-cli", "inspection-policy.json"))
	if err != nil {
		return err
	}
	if !bytes.Equal(policyData, inspectionpolicy.Data()) {
		return fmt.Errorf("release provenance: archived inspection policy does not match verifier policy")
	}
	policy, err := inspectionpolicy.Load()
	if err != nil {
		return err
	}
	foundAggregate := false
	for _, bundle := range policy.Bundles {
		inspection, err := readBundleInspection(filepath.Join(out, "custom-cli"), bundle.Key)
		if err != nil {
			return err
		}
		if !inspection.GoTinyGoEqual || !reflect.DeepEqual(inspection.Capabilities, bundle.Capabilities) ||
			inspection.ImportCount != inspectionpolicy.ImportCount(bundle) || !reflect.DeepEqual(inspection.ImportsByModule, bundle.Imports) {
			return fmt.Errorf("release provenance: inspection facts for %q do not match policy", bundle.Key)
		}
		if bundle.Key == inspectionpolicy.AggregateKey {
			*dst = inspection
			foundAggregate = true
		}
	}
	if !foundAggregate {
		return fmt.Errorf("release provenance: aggregate inspection is missing from policy")
	}
	return nil
}

func readBundleInspection(directory, key string) (Inspection, error) {
	goPath := filepath.Join(directory, "inspection-"+key+"-go.json")
	tinyPath := filepath.Join(directory, "inspection-"+key+"-tinygo.json")
	goData, err := os.ReadFile(goPath)
	if err != nil {
		return Inspection{}, err
	}
	tinyData, err := os.ReadFile(tinyPath)
	if err != nil {
		return Inspection{}, err
	}
	var decoded struct {
		Capabilities []string `json:"capabilities"`
		Imports      []struct {
			Module string `json:"module"`
		} `json:"imports"`
	}
	if err := json.Unmarshal(goData, &decoded); err != nil {
		return Inspection{}, err
	}
	sum := sha256.Sum256(goData)
	inspection := Inspection{
		SHA256:          hex.EncodeToString(sum[:]),
		GoTinyGoEqual:   string(goData) == string(tinyData),
		Capabilities:    append([]string(nil), decoded.Capabilities...),
		ImportCount:     len(decoded.Imports),
		ImportsByModule: make(map[string]int),
	}
	for _, item := range decoded.Imports {
		inspection.ImportsByModule[item.Module]++
	}
	return inspection, nil
}

const (
	releaseBenchmarkBenchtime = "100ms"
	releaseBenchmarkCount     = 1
	releaseBenchmarkCPU       = 1
)

var (
	benchmarkPackagePattern = regexp.MustCompile(`^github\.com/wago-org/net(?:/[A-Za-z0-9_.-]+)*$`)
	benchmarkNamePattern    = regexp.MustCompile(`^Benchmark[A-Za-z0-9_]+$`)
)

func readBenchmarkEvidence(out string, checks []Check) (BenchmarkEvidence, error) {
	targetData, err := os.ReadFile(filepath.Join(out, "benchmark", "targets.tsv"))
	if err != nil {
		return BenchmarkEvidence{}, err
	}
	if len(targetData) == 0 || targetData[len(targetData)-1] != '\n' {
		return BenchmarkEvidence{}, fmt.Errorf("release provenance: benchmark target manifest is empty or noncanonical")
	}
	packages := make(map[string]struct{})
	expectedLogs := make(map[string]string)
	previous := ""
	scanner := bufio.NewScanner(bytes.NewReader(targetData))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || !benchmarkPackagePattern.MatchString(fields[0]) || !benchmarkNamePattern.MatchString(fields[1]) || line <= previous {
			return BenchmarkEvidence{}, fmt.Errorf("release provenance: invalid or unsorted benchmark target %q", line)
		}
		previous = line
		packages[fields[0]] = struct{}{}
		logPath := filepath.ToSlash(filepath.Join("benchmark", "logs", fields[0], fields[1]+".log"))
		expectedLogs[logPath] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return BenchmarkEvidence{}, err
	}
	if len(expectedLogs) == 0 {
		return BenchmarkEvidence{}, fmt.Errorf("release provenance: benchmark target manifest is empty")
	}
	facts := BenchmarkEvidence{
		TargetCount: len(expectedLogs), PackageCount: len(packages), Benchtime: releaseBenchmarkBenchtime,
		Count: releaseBenchmarkCount, CPU: releaseBenchmarkCPU, Benchmem: true,
	}
	detail := benchmarkDetail(facts)
	detailData, err := os.ReadFile(filepath.Join(out, "benchmark", "detail.txt"))
	if err != nil {
		return BenchmarkEvidence{}, err
	}
	if string(detailData) != detail+"\n" {
		return BenchmarkEvidence{}, fmt.Errorf("release provenance: benchmark detail does not match discovered targets and required settings")
	}
	benchmarkCheck := Check{}
	for _, check := range checks {
		if check.Name == releaseBenchmarkCheck {
			benchmarkCheck = check
			break
		}
	}
	if benchmarkCheck.Status != "pass" || benchmarkCheck.Detail != detail {
		return BenchmarkEvidence{}, fmt.Errorf("release provenance: benchmark check does not match archived evidence")
	}
	seenLogs := make(map[string]struct{}, len(expectedLogs))
	logsRoot := filepath.Join(out, "benchmark", "logs")
	if err := filepath.WalkDir(logsRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("release provenance: benchmark log %s is not a regular file", path)
		}
		rel, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		target, expected := expectedLogs[rel]
		if !expected {
			return fmt.Errorf("release provenance: unexpected benchmark log %q", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) == 0 || !bytes.Contains(data, []byte(target)) || !bytes.Contains(data, []byte("B/op")) || !bytes.Contains(data, []byte("allocs/op")) {
			return fmt.Errorf("release provenance: benchmark log %q lacks benchmark or benchmem output", rel)
		}
		seenLogs[rel] = struct{}{}
		return nil
	}); err != nil {
		return BenchmarkEvidence{}, err
	}
	if len(seenLogs) != len(expectedLogs) {
		return BenchmarkEvidence{}, fmt.Errorf("release provenance: benchmark logs are incomplete")
	}
	return facts, nil
}

func benchmarkDetail(benchmark BenchmarkEvidence) string {
	return fmt.Sprintf("targets=%d packages=%d benchtime=%s count=%d cpu=%d benchmem=%t",
		benchmark.TargetCount, benchmark.PackageCount, benchmark.Benchtime, benchmark.Count, benchmark.CPU, benchmark.Benchmem)
}

func readArm64(out string, dst *TargetResult) error {
	dst.GOOS, dst.GOARCH = "linux", "arm64"
	status, err := readKeyValue(filepath.Join(out, "arm64", "status.txt"), "status")
	if err != nil {
		return err
	}
	runner, err := readKeyValue(filepath.Join(out, "arm64", "runner.txt"), "runner")
	if err != nil {
		return err
	}
	dst.Status, dst.Runner = status, runner
	multiPath := filepath.Join(out, "arm64", "binaries.sha256")
	checksum, err := os.ReadFile(multiPath)
	if err == nil {
		if len(checksum) == 0 || checksum[len(checksum)-1] != '\n' {
			return fmt.Errorf("release provenance: empty or noncanonical arm64 binary checksums")
		}
		previous := ""
		scanner := bufio.NewScanner(bytes.NewReader(checksum))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 2 || !validSHA256(fields[0]) || !strings.HasPrefix(fields[1], "binaries/") || fields[1] <= previous {
				return fmt.Errorf("release provenance: invalid or unsorted arm64 binary checksum %q", scanner.Text())
			}
			previous = fields[1]
			dst.Binaries = append(dst.Binaries, TargetBinary{Name: fields[1], SHA256: fields[0]})
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		if len(dst.Binaries) == 0 {
			return fmt.Errorf("release provenance: arm64 binary checksum set is empty")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	checksum, err = os.ReadFile(filepath.Join(out, "arm64", "binary.sha256"))
	if err == nil {
		fields := strings.Fields(string(checksum))
		if len(fields) == 0 || !validSHA256(fields[0]) {
			return fmt.Errorf("release provenance: empty arm64 binary checksum")
		}
		dst.BinarySHA256 = fields[0]
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func readKeyValue(path, want string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok && key == want {
			return value, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("release provenance: %s missing from %s", want, path)
}

func scanArtifacts(root string) ([]Artifact, error) {
	var artifacts []Artifact
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch rel {
		case "evidence.sha256", "provenance.json", "provenance.sha256":
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		sum, err := hashFile(path)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, Artifact{Path: rel, Kind: artifactKind(rel), Size: info.Size(), SHA256: sum})
		return nil
	})
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return artifacts, err
}

func artifactKind(path string) string {
	switch {
	case strings.HasPrefix(path, "fuzz-") || strings.HasPrefix(path, "fuzz/"):
		return "fuzz"
	case strings.HasPrefix(path, "bench-") || strings.HasPrefix(path, "benchmark-") || strings.HasPrefix(path, "benchmark/"):
		return "benchmark"
	case strings.HasPrefix(path, "custom-cli/inspection-"):
		return "inspection"
	case strings.HasPrefix(path, "arm64/"):
		return "arm64"
	case strings.HasPrefix(path, "tls/") || path == "tls-signoff.txt":
		return "tls"
	case strings.HasPrefix(path, "tinygo/") || path == "tinygo-supported-test.txt":
		return "tinygo"
	case path == "wasi-test.txt" || path == "wasi-status.txt" || strings.HasPrefix(path, "wasi-upstream/"):
		return "exception"
	case path == "checks.tsv":
		return "checks"
	case strings.HasPrefix(path, "source-objects/"):
		return "source-object"
	case path == "toolchains.txt" || path == "revisions.txt" || path == "packages.txt" || path == "publication.txt":
		return "inventory"
	default:
		return "support"
	}
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeEvidenceChecksums(out string, artifacts []Artifact) error {
	var builder strings.Builder
	for _, artifact := range artifacts {
		fmt.Fprintf(&builder, "%s  %s\n", artifact.SHA256, artifact.Path)
	}
	return os.WriteFile(filepath.Join(out, "evidence.sha256"), []byte(builder.String()), 0o644)
}
