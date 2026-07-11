// Package releaseprovenance emits deterministic machine-readable release evidence.
package releaseprovenance

import (
	"bufio"
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
	"sort"
	"strings"
)

const SchemaV2 = "github.com/wago-org/net/release-provenance/v2"

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
	Schema         string       `json:"schema"`
	Subject        Repository   `json:"subject"`
	Inputs         []Repository `json:"inputs"`
	ReviewSubjects []Repository `json:"reviewSubjects"`
	Toolchains     Toolchains   `json:"toolchains"`
	Inspection     Inspection   `json:"inspection"`
	Targets        Targets      `json:"targets"`
	Checks         []Check      `json:"checks"`
	Artifacts      []Artifact   `json:"artifacts"`
	Exceptions     []Exception  `json:"acceptedExceptions,omitempty"`
	Limitations    []Limitation `json:"limitations,omitempty"`
}

type Repository struct {
	Name     string   `json:"name"`
	Revision string   `json:"revision"`
	Tree     string   `json:"tree"`
	Parents  []string `json:"parents,omitempty"`
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

type Targets struct {
	CrossBuild     TargetResult `json:"crossBuild"`
	Arm64Execution TargetResult `json:"arm64Execution"`
}

type TargetResult struct {
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	Status       string `json:"status"`
	Runner       string `json:"runner,omitempty"`
	BinarySHA256 string `json:"binarySha256,omitempty"`
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
		Schema:  SchemaV2,
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
	if err := readToolchains(filepath.Join(cfg.OutputDir, "toolchains.txt"), &manifest.Toolchains); err != nil {
		return nil, err
	}
	if err := readInspection(cfg.OutputDir, &manifest.Inspection); err != nil {
		return nil, err
	}
	wantCapabilities := []string{"net.dns", "net.info", "net.tcp", "net.udp"}
	wantImports := map[string]int{"wago_net": 1, "wago_net_dns": 6, "wago_net_tcp": 11, "wago_net_udp": 6}
	if !manifest.Inspection.GoTinyGoEqual || !reflect.DeepEqual(manifest.Inspection.Capabilities, wantCapabilities) ||
		manifest.Inspection.ImportCount != 24 || !reflect.DeepEqual(manifest.Inspection.ImportsByModule, wantImports) {
		return nil, fmt.Errorf("release provenance: inspection facts do not match the complete advertised networking surface")
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
			Detail: "cross-build passed, but this release gate did not execute the arm64 smoke binary",
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
	goPath := filepath.Join(out, "custom-cli", "inspection-go.json")
	tinyPath := filepath.Join(out, "custom-cli", "inspection-tinygo.json")
	goData, err := os.ReadFile(goPath)
	if err != nil {
		return err
	}
	tinyData, err := os.ReadFile(tinyPath)
	if err != nil {
		return err
	}
	var decoded struct {
		Capabilities []string `json:"capabilities"`
		Imports      []struct {
			Module string `json:"module"`
		} `json:"imports"`
	}
	if err := json.Unmarshal(goData, &decoded); err != nil {
		return err
	}
	sum := sha256.Sum256(goData)
	dst.SHA256 = hex.EncodeToString(sum[:])
	dst.GoTinyGoEqual = string(goData) == string(tinyData)
	dst.Capabilities = append([]string(nil), decoded.Capabilities...)
	dst.ImportCount = len(decoded.Imports)
	dst.ImportsByModule = map[string]int{}
	for _, item := range decoded.Imports {
		dst.ImportsByModule[item.Module]++
	}
	return nil
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
	checksum, err := os.ReadFile(filepath.Join(out, "arm64", "binary.sha256"))
	if err == nil {
		fields := strings.Fields(string(checksum))
		if len(fields) == 0 {
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
	case strings.HasPrefix(path, "fuzz-"):
		return "fuzz"
	case strings.HasPrefix(path, "bench-"):
		return "benchmark"
	case strings.HasPrefix(path, "custom-cli/inspection-"):
		return "inspection"
	case strings.HasPrefix(path, "arm64/"):
		return "arm64"
	case path == "wasi-test.txt" || path == "wasi-status.txt" || strings.HasPrefix(path, "wasi-upstream/"):
		return "exception"
	case path == "checks.tsv":
		return "checks"
	case strings.HasPrefix(path, "source-objects/"):
		return "source-object"
	case path == "toolchains.txt" || path == "revisions.txt" || path == "packages.txt":
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
