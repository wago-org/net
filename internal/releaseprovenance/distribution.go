package releaseprovenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	DistributionStatementSchemaV1   = "github.com/wago-org/net/distribution-statement/v1"
	DistributionTrustPolicySchemaV1 = "github.com/wago-org/net/distribution-trust-policy/v1"
)

// DistributionStatement is the minimal deterministic payload intended for
// detached signing by a publisher-controlled system. It contains no signature,
// key discovery hint, or publisher identity claim.
type DistributionStatement struct {
	Schema             string            `json:"schema"`
	Subject            string            `json:"subject"`
	ProvenanceSHA256   string            `json:"provenanceSha256"`
	ReviewBundleSHA256 string            `json:"reviewBundleSha256"`
	ReviewSubjects     []Repository      `json:"reviewSubjects"`
	Publication        PublicationStatus `json:"publication"`
}

// DistributionTrustPolicy is supplied explicitly by the verifier. KeyID is an
// operator label only; it is never interpreted as a path, URL, or discovery key.
// Optional exact constraints let the operator pin the intended statement and
// subject independently of the signing key.
type DistributionTrustPolicy struct {
	Schema          string `json:"schema"`
	KeyID           string `json:"keyId"`
	Algorithm       string `json:"algorithm"`
	PublicKey       string `json:"publicKey"`
	StatementSHA256 string `json:"statementSha256,omitempty"`
	Subject         string `json:"subject,omitempty"`
}

// TrustedDistribution binds a valid detached signature to the independently
// verified review archive and canonical provenance it names.
type TrustedDistribution struct {
	Statement         *DistributionStatement
	Verification      *Verification
	KeyID             string
	StatementSHA256   string
	TrustPolicySHA256 string
}

// WriteDistributionStatement verifies an existing review archive and writes a
// canonical statement beside or outside it. The statement is deliberately not
// embedded in the archive whose digest it records.
func WriteDistributionStatement(bundle, destination string, opts VerifyOptions) (*DistributionStatement, string, error) {
	verified, err := Verify(bundle, opts)
	if err != nil {
		return nil, "", err
	}
	if verified.BundleSHA256 == "" {
		return nil, "", fmt.Errorf("release provenance: distribution statements require a .tar.gz review bundle")
	}
	statement := &DistributionStatement{
		Schema:             DistributionStatementSchemaV1,
		Subject:            verified.Manifest.Subject.Revision,
		ProvenanceSHA256:   verified.ProvenanceSHA256,
		ReviewBundleSHA256: verified.BundleSHA256,
		ReviewSubjects:     append([]Repository(nil), verified.Manifest.ReviewSubjects...),
		Publication:        verified.Manifest.Publication,
	}
	data, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return nil, "", err
	}
	data = append(data, '\n')
	if err := writeAtomic(destination, data); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return statement, hex.EncodeToString(sum[:]), nil
}

// VerifySignedDistribution verifies a raw detached Ed25519 signature over the
// exact canonical statement bytes using only the explicitly supplied trust
// policy, then binds every statement field back to the review archive.
func VerifySignedDistribution(bundle, statementPath, signaturePath, trustPolicyPath string) (*TrustedDistribution, error) {
	return verifySignedDistribution(bundle, statementPath, signaturePath, trustPolicyPath, VerifyOptions{})
}

func verifySignedDistribution(bundle, statementPath, signaturePath, trustPolicyPath string, opts VerifyOptions) (*TrustedDistribution, error) {
	statementData, err := readBoundedFile(statementPath, 1<<20, "distribution statement")
	if err != nil {
		return nil, err
	}
	var statement DistributionStatement
	if err := decodeCanonicalJSON(statementData, &statement, "distribution statement"); err != nil {
		return nil, err
	}
	if err := validateDistributionStatement(&statement, opts); err != nil {
		return nil, err
	}

	policyData, err := readBoundedFile(trustPolicyPath, 64<<10, "distribution trust policy")
	if err != nil {
		return nil, err
	}
	var policy DistributionTrustPolicy
	if err := decodeCanonicalJSON(policyData, &policy, "distribution trust policy"); err != nil {
		return nil, err
	}
	publicKey, err := validateDistributionTrustPolicy(&policy)
	if err != nil {
		return nil, err
	}
	policySum := sha256.Sum256(policyData)
	trustPolicySHA256 := hex.EncodeToString(policySum[:])
	statementSum := sha256.Sum256(statementData)
	statementSHA256 := hex.EncodeToString(statementSum[:])
	if err := enforceDistributionTrustConstraints(&policy, &statement, statementSHA256); err != nil {
		return nil, err
	}
	signature, err := readBoundedFile(signaturePath, ed25519.SignatureSize, "detached signature")
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("release provenance: detached signature size %d, want %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(publicKey, statementData, signature) {
		return nil, fmt.Errorf("release provenance: detached signature verification failed for trust policy key %q", policy.KeyID)
	}

	archiveOpts := opts
	archiveOpts.ExpectedSubject = statement.Subject
	archiveOpts.ExpectedBundleSHA256 = statement.ReviewBundleSHA256
	archiveOpts.StrictDistribution = true
	verified, err := Verify(bundle, archiveOpts)
	if err != nil {
		return nil, err
	}
	if verified.ProvenanceSHA256 != statement.ProvenanceSHA256 ||
		!reflect.DeepEqual(verified.Manifest.ReviewSubjects, statement.ReviewSubjects) ||
		verified.Manifest.Publication != statement.Publication {
		return nil, fmt.Errorf("release provenance: signed distribution statement does not match verified archive provenance")
	}
	return &TrustedDistribution{
		Statement: &statement, Verification: verified, KeyID: policy.KeyID,
		StatementSHA256: statementSHA256, TrustPolicySHA256: trustPolicySHA256,
	}, nil
}

func validateDistributionStatement(statement *DistributionStatement, opts VerifyOptions) error {
	if statement.Schema != DistributionStatementSchemaV1 || !validObjectID(statement.Subject) ||
		!validSHA256(statement.ProvenanceSHA256) || !validSHA256(statement.ReviewBundleSHA256) {
		return fmt.Errorf("release provenance: invalid distribution statement identity or digest")
	}
	wantReviewSubjects := expectedReviewSourceRepositories(opts)
	if !reflect.DeepEqual(statement.ReviewSubjects, wantReviewSubjects) {
		return fmt.Errorf("release provenance: distribution statement review subjects do not match immutable policy")
	}
	publication := statement.Publication
	if publication.CurrentPlugin != "review-only" && publication.CurrentPlugin != "adopted" {
		return fmt.Errorf("release provenance: invalid signed current plugin publication status %q", publication.CurrentPlugin)
	}
	if publication.ProductionWagoMerge != "unpublished" && publication.ProductionWagoMerge != "published" {
		return fmt.Errorf("release provenance: invalid signed production Wago publication status %q", publication.ProductionWagoMerge)
	}
	if publication.ExternalWorkers != "published" || publication.Pooling != "unsupported" ||
		publication.PublisherAuthentication != "external-required" || publication.HostedReleaseAutomation != "disabled" {
		return fmt.Errorf("release provenance: signed publication status overclaims distribution or activation")
	}
	return nil
}

func validateDistributionTrustPolicy(policy *DistributionTrustPolicy) (ed25519.PublicKey, error) {
	if policy.Schema != DistributionTrustPolicySchemaV1 || policy.Algorithm != "ed25519" {
		return nil, fmt.Errorf("release provenance: unsupported distribution trust policy schema or algorithm")
	}
	if policy.KeyID == "" || len(policy.KeyID) > 128 || strings.IndexFunc(policy.KeyID, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r))
	}) >= 0 {
		return nil, fmt.Errorf("release provenance: invalid distribution trust policy key ID")
	}
	if policy.StatementSHA256 != "" && !validSHA256(policy.StatementSHA256) {
		return nil, fmt.Errorf("release provenance: invalid distribution trust policy statement SHA-256")
	}
	if policy.Subject != "" && !validObjectID(policy.Subject) {
		return nil, fmt.Errorf("release provenance: invalid distribution trust policy subject")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(policy.PublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != policy.PublicKey {
		return nil, fmt.Errorf("release provenance: distribution trust policy public key is not canonical Ed25519 base64")
	}
	return ed25519.PublicKey(decoded), nil
}

func enforceDistributionTrustConstraints(policy *DistributionTrustPolicy, statement *DistributionStatement, statementSHA256 string) error {
	if policy.StatementSHA256 != "" && policy.StatementSHA256 != statementSHA256 {
		return fmt.Errorf("release provenance: distribution trust policy statement SHA-256 does not match supplied statement")
	}
	if policy.Subject != "" && policy.Subject != statement.Subject {
		return fmt.Errorf("release provenance: distribution trust policy subject does not match supplied statement")
	}
	return nil
}

func decodeCanonicalJSON(data []byte, dst any, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("release provenance: decode %s: %w", label, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("release provenance: trailing %s data", label)
	}
	canonical, err := json.MarshalIndent(dst, "", "  ")
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("release provenance: %s is not canonical indented JSON", label)
	}
	return nil
}

func readBoundedFile(path string, limit int64, label string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("release provenance: %s path is required", label)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("release provenance: %s is not a bounded regular file", label)
	}
	return os.ReadFile(path)
}

func writeAtomic(destination string, data []byte) error {
	if destination == "" {
		return fmt.Errorf("release provenance: output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".distribution-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, destination); err != nil {
		return err
	}
	ok = true
	return nil
}
