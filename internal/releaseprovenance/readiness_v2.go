package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const ProductionReadinessSchemaV2 = "github.com/wago-org/net/production-readiness/v2"

// ProductionReadinessV2 is a deterministic activation decision recomputed from
// the original archive, statement, detached signature, and explicit trust
// policy. It additionally binds the exact retained trusted-distribution receipt
// that records the preceding verification step.
type ProductionReadinessV2 struct {
	Schema                           string             `json:"schema"`
	Ready                            bool               `json:"ready"`
	Algorithm                        string             `json:"algorithm"`
	TrustedKeyID                     string             `json:"trustedKeyId"`
	TrustPolicySHA256                string             `json:"trustPolicySha256"`
	Subject                          string             `json:"subject"`
	StatementSHA256                  string             `json:"statementSha256"`
	SignatureSHA256                  string             `json:"signatureSha256"`
	TrustedDistributionReceiptSHA256 string             `json:"trustedDistributionReceiptSha256"`
	ProvenanceSHA256                 string             `json:"provenanceSha256"`
	ReviewBundleSHA256               string             `json:"reviewBundleSha256"`
	Blockers                         []ReadinessBlocker `json:"blockers"`
}

// VerifyProductionReleaseCandidateWithTrustedReceipt performs fresh signature,
// archive, and readiness verification from the original inputs, independently
// verifies the retained trusted-distribution receipt, and requires the two
// results to describe the same exact evidence before producing a v2 decision.
func VerifyProductionReleaseCandidateWithTrustedReceipt(bundle, statementPath, signaturePath, trustPolicyPath, trustedReceiptPath string) (*ProductionReadinessV2, error) {
	return verifyProductionReleaseCandidateWithTrustedReceipt(bundle, statementPath, signaturePath, trustPolicyPath, trustedReceiptPath, VerifyOptions{})
}

func verifyProductionReleaseCandidateWithTrustedReceipt(bundle, statementPath, signaturePath, trustPolicyPath, trustedReceiptPath string, opts VerifyOptions) (*ProductionReadinessV2, error) {
	trusted, err := verifySignedDistribution(bundle, statementPath, signaturePath, trustPolicyPath, opts)
	if err != nil {
		return nil, err
	}
	receipt, receiptSHA256, err := VerifyTrustedDistributionReceipt(trustedReceiptPath, TrustedDistributionReceiptVerifyOptions{
		ExpectedSubject: trusted.Statement.Subject, ExpectedStatementSHA256: trusted.StatementSHA256,
		ExpectedSignatureSHA256: trusted.SignatureSHA256, ExpectedTrustPolicySHA256: trusted.TrustPolicySHA256,
	})
	if err != nil {
		return nil, err
	}
	if receipt.Algorithm != "ed25519" || receipt.TrustedKeyID != trusted.KeyID ||
		receipt.ProvenanceSHA256 != trusted.Verification.ProvenanceSHA256 ||
		receipt.ReviewBundleSHA256 != trusted.Verification.BundleSHA256 {
		return nil, fmt.Errorf("release provenance: trusted distribution receipt does not match fresh signed distribution verification")
	}
	return assessProductionReadinessV2(trusted, receiptSHA256), nil
}

func assessProductionReadinessV2(trusted *TrustedDistribution, trustedReceiptSHA256 string) *ProductionReadinessV2 {
	v1 := assessProductionReadiness(trusted)
	return &ProductionReadinessV2{
		Schema: ProductionReadinessSchemaV2, Ready: v1.Ready, Algorithm: "ed25519", TrustedKeyID: v1.TrustedKeyID,
		TrustPolicySHA256: v1.TrustPolicySHA256, Subject: v1.Subject, StatementSHA256: v1.StatementSHA256,
		SignatureSHA256: trusted.SignatureSHA256, TrustedDistributionReceiptSHA256: trustedReceiptSHA256,
		ProvenanceSHA256: v1.ProvenanceSHA256, ReviewBundleSHA256: v1.ReviewBundleSHA256,
		Blockers: append([]ReadinessBlocker(nil), v1.Blockers...),
	}
}

// WriteProductionReadinessReceiptV2 atomically replaces a canonical linked
// readiness decision and then its adjacent SHA-256 sidecar.
func WriteProductionReadinessReceiptV2(destination string, report *ProductionReadinessV2) (string, error) {
	if destination == "" {
		return "", fmt.Errorf("release provenance: production readiness v2 receipt path is required")
	}
	if err := validateProductionReadinessV2(report); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	checksumPath := destination + ".sha256"
	if err := os.Remove(checksumPath); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := writeAtomic(destination, data); err != nil {
		return "", err
	}
	checksum := []byte(digest + "  " + filepath.Base(destination) + "\n")
	if err := writeAtomic(checksumPath, checksum); err != nil {
		return "", err
	}
	return digest, nil
}

func validateProductionReadinessV2(report *ProductionReadinessV2) error {
	if report == nil || report.Schema != ProductionReadinessSchemaV2 || report.Algorithm != "ed25519" ||
		!validDistributionKeyID(report.TrustedKeyID) || !validSHA256(report.TrustPolicySHA256) ||
		!validObjectID(report.Subject) || !validSHA256(report.StatementSHA256) || !validSHA256(report.SignatureSHA256) ||
		!validSHA256(report.TrustedDistributionReceiptSHA256) || !validSHA256(report.ProvenanceSHA256) ||
		!validSHA256(report.ReviewBundleSHA256) || report.Ready != (len(report.Blockers) == 0) {
		return fmt.Errorf("release provenance: invalid production readiness v2 receipt")
	}
	for _, blocker := range report.Blockers {
		if blocker.ID == "" || blocker.Detail == "" {
			return fmt.Errorf("release provenance: invalid production readiness v2 blocker")
		}
	}
	return nil
}
