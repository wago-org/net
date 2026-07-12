package releaseprovenance

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	ExpectedWagoRevision  = "97e6f91e6c822491577faa86f3c30aa5a8fff1e8"
	ExpectedWagoParent1   = "54499ba5135f69a062e23a7255f4a408d6cecf8c"
	ExpectedWagoParent2   = "ffd5ef4b122cbd019897eeea3503789ab5860e4a"
	ExpectedLnetoRevision = "ab1a0c735a8b534a1d6322a3e245bc11a09431e7"
	ExpectedWASIRevision  = "3df6c766ad00e83b314da799dbf9a77b409ad19d"

	ExpectedCurrentWagoRevision = "d556b20ff8667a8ae17b1ca399c74a949ac78f2f"
	ExpectedCurrentWagoTree     = "457770eff0a8af628715ae1305151d5f534d0af4"
	ExpectedCurrentWagoParent   = "59ce1c136492be44f8f4d252096bda01d3ef4a22"
	ExpectedCurrentNetRevision  = "173b38a4d5a0db0e6058544576942a46b9d543df"
	ExpectedCurrentNetTree      = "ca7534943e653a6c04c63ec458fc00feb6350799"
	ExpectedCurrentNetParent    = "164ee79e98d7e51bf3553fb18b46fd2044b223aa"
	ExpectedWorkersRevision     = "1e9139756d8a3c631c59c00b028038c83bfa8341"
	ExpectedWorkersTree         = "ca79d1fb02f19ae15d7b166ffc179c01f9a7c212"
	ExpectedWorkersParent1      = "5cb4efff83f0a519311fcf03b63496433f2901f0"
	ExpectedWorkersParent2      = "08466d04599d7c0da88d4c5cda73a62c775a8dfc"
)

const (
	maxBundleFiles = 1024
	maxBundleFile  = 128 << 20
	maxBundleBytes = 512 << 20
)

type VerifyOptions struct {
	ExpectedSubject      string
	ExpectedBundleSHA256 string
	StrictDistribution   bool

	// expectedInputs and expectedReviewSources are test-only policy injection.
	// External callers always use the immutable release pins below because these
	// fields are unexported.
	expectedInputs        []Repository
	expectedReviewSources []Repository
}

type Verification struct {
	Manifest         *Manifest
	ProvenanceSHA256 string
	BundleSHA256     string
}

// Verify validates either an extracted release-signoff directory or a
// deterministic .tar.gz review bundle without accessing source repositories or
// rerunning release tests.
func Verify(bundle string, opts VerifyOptions) (*Verification, error) {
	info, err := os.Stat(bundle)
	if err != nil {
		return nil, err
	}
	if opts.StrictDistribution && (opts.ExpectedSubject == "" || opts.ExpectedBundleSHA256 == "") {
		return nil, fmt.Errorf("release provenance: strict distribution verification requires expected subject and bundle SHA-256")
	}
	if info.IsDir() {
		if opts.ExpectedBundleSHA256 != "" || opts.StrictDistribution {
			return nil, fmt.Errorf("release provenance: bundle SHA-256 policy requires a .tar.gz review bundle")
		}
		return verifyDirectory(bundle, opts)
	}
	bundleHash, err := hashFile(bundle)
	if err != nil {
		return nil, err
	}
	if opts.ExpectedBundleSHA256 != "" {
		if !validSHA256(opts.ExpectedBundleSHA256) {
			return nil, fmt.Errorf("release provenance: expected bundle SHA-256 is not 64-character lowercase hex")
		}
		if bundleHash != opts.ExpectedBundleSHA256 {
			return nil, fmt.Errorf("release provenance: review bundle SHA-256 %s, want %s", bundleHash, opts.ExpectedBundleSHA256)
		}
	}
	tmp, err := os.MkdirTemp("", "wago-net-review-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := extractBundle(bundle, tmp); err != nil {
		return nil, err
	}
	verified, err := verifyDirectory(tmp, opts)
	if err != nil {
		return nil, err
	}
	verified.BundleSHA256 = bundleHash
	return verified, nil
}

// ExportBundle verifies source and writes a deterministic gzip-compressed tar
// containing only manifest-listed evidence and the three provenance metadata
// files. Given byte-identical source evidence, the output is byte-identical.
func ExportBundle(source, destination string, opts VerifyOptions) (*Verification, string, error) {
	if opts.ExpectedBundleSHA256 != "" || opts.StrictDistribution {
		return nil, "", fmt.Errorf("release provenance: strict bundle hash policy applies only when verifying an existing archive")
	}
	verified, err := verifyDirectory(source, opts)
	if err != nil {
		return nil, "", err
	}
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return nil, "", err
	}
	destinationAbs, err := filepath.Abs(destination)
	if err != nil {
		return nil, "", err
	}
	if destinationAbs == sourceAbs || strings.HasPrefix(destinationAbs, sourceAbs+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("release provenance: review bundle must be outside the evidence directory")
	}
	if err := os.MkdirAll(filepath.Dir(destinationAbs), 0o755); err != nil {
		return nil, "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destinationAbs), ".review-bundle-*.tar.gz")
	if err != nil {
		return nil, "", err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(tmpName)
		}
	}()

	gzipWriter, err := gzip.NewWriterLevel(tmp, gzip.BestCompression)
	if err != nil {
		return nil, "", err
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	files := []string{"evidence.sha256", "provenance.json", "provenance.sha256"}
	for _, artifact := range verified.Manifest.Artifacts {
		files = append(files, artifact.Path)
	}
	sort.Strings(files)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(sourceAbs, filepath.FromSlash(name)))
		if err != nil {
			return nil, "", err
		}
		header := &tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg,
			ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, "", err
		}
		if _, err := tarWriter.Write(data); err != nil {
			return nil, "", err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, "", err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, "", err
	}
	if err := tmp.Sync(); err != nil {
		return nil, "", err
	}
	if err := tmp.Close(); err != nil {
		return nil, "", err
	}
	if err := os.Rename(tmpName, destinationAbs); err != nil {
		return nil, "", err
	}
	ok = true
	bundleHash, err := hashFile(destinationAbs)
	if err != nil {
		return nil, "", err
	}
	return verified, bundleHash, nil
}

func verifyDirectory(root string, opts VerifyOptions) (*Verification, error) {
	provenancePath := filepath.Join(root, "provenance.json")
	data, err := os.ReadFile(provenancePath)
	if err != nil {
		return nil, err
	}
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("release provenance: manifest exceeds size limit")
	}
	provenanceHash := sha256.Sum256(data)
	provenanceHex := hex.EncodeToString(provenanceHash[:])
	if err := verifyChecksumFile(filepath.Join(root, "provenance.sha256"), provenanceHex, "provenance.json"); err != nil {
		return nil, err
	}

	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("release provenance: decode manifest: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("release provenance: trailing manifest data")
	}
	canonical, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	canonical = append(canonical, '\n')
	if !reflect.DeepEqual(data, canonical) {
		return nil, fmt.Errorf("release provenance: manifest is not canonical indented JSON")
	}
	if err := validateManifest(&manifest, opts); err != nil {
		return nil, err
	}

	actual, err := scanArtifacts(root)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(actual, manifest.Artifacts) {
		return nil, fmt.Errorf("release provenance: manifest artifact inventory does not match bundle contents")
	}
	var evidence strings.Builder
	for _, artifact := range manifest.Artifacts {
		fmt.Fprintf(&evidence, "%s  %s\n", artifact.SHA256, artifact.Path)
	}
	evidenceData, err := os.ReadFile(filepath.Join(root, "evidence.sha256"))
	if err != nil {
		return nil, err
	}
	if string(evidenceData) != evidence.String() {
		return nil, fmt.Errorf("release provenance: evidence.sha256 is not the exact sorted manifest inventory")
	}

	checks, err := readChecks(filepath.Join(root, "checks.tsv"))
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(checks, manifest.Checks) {
		return nil, fmt.Errorf("release provenance: checks.tsv does not match manifest checks")
	}
	var publication PublicationStatus
	if err := readPublication(filepath.Join(root, "publication.txt"), &publication); err != nil {
		return nil, err
	}
	if publication != manifest.Publication {
		return nil, fmt.Errorf("release provenance: publication.txt does not match manifest publication status")
	}
	var toolchains Toolchains
	if err := readToolchains(filepath.Join(root, "toolchains.txt"), &toolchains); err != nil {
		return nil, err
	}
	if toolchains != manifest.Toolchains {
		return nil, fmt.Errorf("release provenance: toolchains.txt does not match manifest toolchains")
	}
	var inspection Inspection
	if err := readInspection(root, &inspection); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(inspection, manifest.Inspection) {
		return nil, fmt.Errorf("release provenance: inspection evidence does not match manifest facts")
	}
	var arm64 TargetResult
	if err := readArm64(root, &arm64); err != nil {
		return nil, err
	}
	if arm64 != manifest.Targets.Arm64Execution {
		return nil, fmt.Errorf("release provenance: arm64 evidence does not match manifest target")
	}
	if err := verifyRevisions(filepath.Join(root, "revisions.txt"), &manifest); err != nil {
		return nil, err
	}
	if err := verifySourceObjects(root, &manifest); err != nil {
		return nil, err
	}
	return &Verification{Manifest: &manifest, ProvenanceSHA256: provenanceHex}, nil
}

func validateManifest(manifest *Manifest, opts VerifyOptions) error {
	if manifest.Schema != SchemaV2 {
		return fmt.Errorf("release provenance: schema %q, want %q", manifest.Schema, SchemaV2)
	}
	if manifest.Subject.Name != "net" || !validObjectID(manifest.Subject.Revision) || !validObjectID(manifest.Subject.Tree) || len(manifest.Subject.Parents) != 0 {
		return fmt.Errorf("release provenance: invalid net subject identity")
	}
	if opts.ExpectedSubject != "" {
		if !validObjectID(opts.ExpectedSubject) {
			return fmt.Errorf("release provenance: expected subject is not a 40-character lowercase object ID")
		}
		if manifest.Subject.Revision != opts.ExpectedSubject {
			return fmt.Errorf("release provenance: subject revision %s, want %s", manifest.Subject.Revision, opts.ExpectedSubject)
		}
	}
	wantInputs := expectedInputRepositories(opts)
	if len(manifest.Inputs) != len(wantInputs) {
		return fmt.Errorf("release provenance: input count %d, want %d", len(manifest.Inputs), len(wantInputs))
	}
	for i, want := range wantInputs {
		got := manifest.Inputs[i]
		if got.Name != want.Name || got.Revision != want.Revision || !validObjectID(got.Tree) || !reflect.DeepEqual(got.Parents, want.Parents) {
			return fmt.Errorf("release provenance: invalid %s input identity or ordered parents", want.Name)
		}
	}
	wantReviewSubjects := expectedReviewSourceRepositories(opts)
	if len(manifest.ReviewSubjects) != len(wantReviewSubjects) {
		return fmt.Errorf("release provenance: review subject count %d, want %d", len(manifest.ReviewSubjects), len(wantReviewSubjects))
	}
	for i, want := range wantReviewSubjects {
		got := manifest.ReviewSubjects[i]
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("release provenance: invalid %s review identity, tree, or ordered parents", want.Name)
		}
	}
	publication := manifest.Publication
	if publication.CurrentPlugin != "review-only" && publication.CurrentPlugin != "adopted" {
		return fmt.Errorf("release provenance: invalid current plugin publication status %q", publication.CurrentPlugin)
	}
	if publication.ProductionWagoMerge != "unpublished" && publication.ProductionWagoMerge != "published" {
		return fmt.Errorf("release provenance: invalid production Wago publication status %q", publication.ProductionWagoMerge)
	}
	if publication.ExternalWorkers != "published" || publication.Pooling != "unsupported" ||
		publication.PublisherAuthentication != "external-required" || publication.HostedReleaseAutomation != "disabled" {
		return fmt.Errorf("release provenance: publication status overclaims distribution, pooling, authentication, or hosted activation")
	}
	if manifest.Toolchains.Go == "" || manifest.Toolchains.TinyGo == "" {
		return fmt.Errorf("release provenance: incomplete toolchains")
	}
	wantCapabilities := []string{"net.dns", "net.info", "net.tcp", "net.udp"}
	wantImports := map[string]int{"wago_net": 1, "wago_net_dns": 6, "wago_net_tcp": 11, "wago_net_udp": 6}
	if !validSHA256(manifest.Inspection.SHA256) || !manifest.Inspection.GoTinyGoEqual ||
		!reflect.DeepEqual(manifest.Inspection.Capabilities, wantCapabilities) || manifest.Inspection.ImportCount != 24 ||
		!reflect.DeepEqual(manifest.Inspection.ImportsByModule, wantImports) {
		return fmt.Errorf("release provenance: inspection facts do not match the complete advertised networking surface")
	}
	if manifest.Targets.CrossBuild != (TargetResult{GOOS: "linux", GOARCH: "arm64", Status: "pass"}) {
		return fmt.Errorf("release provenance: cross-build target is not the required linux/arm64 pass")
	}
	arm64 := manifest.Targets.Arm64Execution
	if arm64.GOOS != "linux" || arm64.GOARCH != "arm64" || !validSHA256(arm64.BinarySHA256) ||
		(!strings.HasPrefix(arm64.Status, "executed-") && !strings.HasPrefix(arm64.Status, "skipped-")) {
		return fmt.Errorf("release provenance: invalid arm64 execution result")
	}
	if strings.HasPrefix(arm64.Status, "executed-") && (arm64.Runner == "" || arm64.Runner == "none") {
		return fmt.Errorf("release provenance: executed arm64 result has no runner")
	}
	if strings.HasPrefix(arm64.Status, "skipped-") && arm64.Runner != "none" {
		return fmt.Errorf("release provenance: skipped arm64 result names runner %q", arm64.Runner)
	}
	if err := validateChecks(manifest.Checks, arm64.Status); err != nil {
		return err
	}
	if err := validateArtifacts(manifest.Artifacts); err != nil {
		return err
	}
	var exceptions []Exception
	for _, check := range manifest.Checks {
		if check.Status == "accepted-exception" {
			exceptions = append(exceptions, Exception{ID: check.Name, Status: check.Status, Detail: check.Detail})
		}
	}
	if !reflect.DeepEqual(manifest.Exceptions, exceptions) {
		return fmt.Errorf("release provenance: accepted exceptions do not exactly match check outcomes")
	}
	var limitations []Limitation
	if strings.HasPrefix(arm64.Status, "skipped-") {
		limitations = []Limitation{{
			ID: "linux-arm64-execution", Status: arm64.Status,
			Detail: "cross-build passed, but this release gate did not execute the arm64 smoke binary",
		}}
	}
	if !reflect.DeepEqual(manifest.Limitations, limitations) {
		return fmt.Errorf("release provenance: limitations do not exactly match target truth")
	}
	lower, _ := json.Marshal(manifest)
	if strings.Contains(strings.ToLower(string(lower)), "hosted ci") {
		return fmt.Errorf("release provenance: manifest must not claim hosted CI")
	}
	return nil
}

func expectedInputRepositories(opts VerifyOptions) []Repository {
	if opts.expectedInputs != nil {
		return opts.expectedInputs
	}
	return []Repository{
		{Name: "wago", Revision: ExpectedWagoRevision, Parents: []string{ExpectedWagoParent1, ExpectedWagoParent2}},
		{Name: "lneto", Revision: ExpectedLnetoRevision},
		{Name: "wasi", Revision: ExpectedWASIRevision},
	}
}

func expectedReviewSourceRepositories(opts VerifyOptions) []Repository {
	if opts.expectedReviewSources != nil {
		return opts.expectedReviewSources
	}
	return []Repository{
		{Name: "net-current-review", Revision: ExpectedCurrentNetRevision, Tree: ExpectedCurrentNetTree, Parents: []string{ExpectedCurrentNetParent}},
		{Name: "wago-current-review", Revision: ExpectedCurrentWagoRevision, Tree: ExpectedCurrentWagoTree, Parents: []string{ExpectedCurrentWagoParent}},
		{Name: "workers-current", Revision: ExpectedWorkersRevision, Tree: ExpectedWorkersTree, Parents: []string{ExpectedWorkersParent1, ExpectedWorkersParent2}},
	}
}

func validateChecks(checks []Check, arm64Status string) error {
	requiredPass := []string{
		"pinned-revisions", "initial-clean-trees", "wago-plugin-plan-compat", "current-plugin-topology-audit", "wasi-preview1-fix-review",
		"go-test-workspace", "go-test-module", "go-test-race", "go-vet", "go-list", "go-mod-tidy",
		"fuzz-dns-wire", "fuzz-dns-layout", "fuzz-dns-guest", "fuzz-shared-layout",
		"benchmark-guest-poll", "benchmark-udp-queue", "tinygo-test", "cross-build",
		"source-boundaries", "custom-cli-inspection", "wago-lifecycle-worker-tests", "lneto-test", "final-clean-trees",
		"source-object-packs", "current-plugin-review-signoff",
	}
	seen := map[string]Check{}
	for _, check := range checks {
		if check.Name == "" || check.Status == "" {
			return fmt.Errorf("release provenance: empty check name or status")
		}
		if _, duplicate := seen[check.Name]; duplicate {
			return fmt.Errorf("release provenance: duplicate check %q", check.Name)
		}
		seen[check.Name] = check
		switch check.Status {
		case "pass":
		case "accepted-exception":
			if check.Name != "wasi-upstream-preview1-audit" && check.Name != "wasi-preview1-native-sigsegv" {
				return fmt.Errorf("release provenance: unrecognized accepted exception %q", check.Name)
			}
			if check.Detail == "" {
				return fmt.Errorf("release provenance: accepted exception %q has no detail", check.Name)
			}
		default:
			if check.Name != "arm64-execution" || check.Status != arm64Status {
				return fmt.Errorf("release provenance: check %q has non-release status %q", check.Name, check.Status)
			}
		}
	}
	for _, name := range requiredPass {
		if seen[name].Status != "pass" {
			return fmt.Errorf("release provenance: required check %q is %q, want pass", name, seen[name].Status)
		}
	}
	if seen["arm64-execution"].Status != arm64Status {
		return fmt.Errorf("release provenance: arm64 check does not match target status")
	}
	if status := seen["wasi-upstream-preview1-audit"].Status; status != "pass" && status != "accepted-exception" {
		return fmt.Errorf("release provenance: reviewed WASI upstream audit status is %q", status)
	}
	pinnedWASI := seen["wasi-preview1-native-sigsegv"].Status == "accepted-exception"
	fixedWASI := seen["wasi-test"].Status == "pass"
	if pinnedWASI == fixedWASI {
		return fmt.Errorf("release provenance: require exactly one pinned WASI pass or accepted preview-1 exception")
	}
	return nil
}

func validateArtifacts(artifacts []Artifact) error {
	previous := ""
	for _, artifact := range artifacts {
		if !validBundlePath(artifact.Path) || artifact.Path <= previous || artifact.Size < 0 || !validSHA256(artifact.SHA256) || artifact.Kind != artifactKind(artifact.Path) {
			return fmt.Errorf("release provenance: invalid or unsorted artifact %+v", artifact)
		}
		previous = artifact.Path
	}
	return nil
}

func verifyRevisions(file string, manifest *Manifest) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	want := fmt.Sprintf("plugin: %s\nWago: %s\nlneto: %s\nWASI: %s\ncurrent net review: %s\ncurrent Wago review: %s\nworkers: %s\n",
		manifest.Subject.Revision, manifest.Inputs[0].Revision, manifest.Inputs[1].Revision, manifest.Inputs[2].Revision,
		manifest.ReviewSubjects[0].Revision, manifest.ReviewSubjects[1].Revision, manifest.ReviewSubjects[2].Revision)
	if string(data) != want {
		return fmt.Errorf("release provenance: revisions.txt does not match manifest revisions")
	}
	return nil
}

func verifyChecksumFile(file, wantHash, wantName string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	want := wantHash + "  " + wantName + "\n"
	if string(data) != want {
		return fmt.Errorf("release provenance: invalid checksum file %s", filepath.Base(file))
	}
	return nil
}

func validObjectID(value string) bool { return len(value) == 40 && lowerHex(value) }
func validSHA256(value string) bool   { return len(value) == 64 && lowerHex(value) }
func lowerHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func validBundlePath(name string) bool {
	return name != "" && name == path.Clean(name) && !path.IsAbs(name) && name != "." &&
		!strings.HasPrefix(name, "../") && !strings.Contains(name, "\\")
}

func extractBundle(bundle, destination string) error {
	file, err := os.Open(bundle)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("release provenance: open review bundle: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	seen := map[string]struct{}{}
	var files int
	var total int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("release provenance: read review bundle: %w", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("release provenance: bundle entry %q is not a regular file", header.Name)
		}
		if !validBundlePath(header.Name) {
			return fmt.Errorf("release provenance: unsafe bundle path %q", header.Name)
		}
		if _, duplicate := seen[header.Name]; duplicate {
			return fmt.Errorf("release provenance: duplicate bundle path %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		files++
		total += header.Size
		if files > maxBundleFiles || header.Size < 0 || header.Size > maxBundleFile || total > maxBundleBytes {
			return fmt.Errorf("release provenance: review bundle exceeds resource limits")
		}
		destinationPath := filepath.Join(destination, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(out, tarReader, header.Size)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
