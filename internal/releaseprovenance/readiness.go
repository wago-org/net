package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const ProductionReadinessSchemaV1 = "github.com/wago-org/net/production-readiness/v1"

// ProductionReadiness is a deterministic activation decision made only after a
// distribution statement has passed explicit-policy signature verification.
type ProductionReadiness struct {
	Schema             string             `json:"schema"`
	Ready              bool               `json:"ready"`
	TrustedKeyID       string             `json:"trustedKeyId"`
	Subject            string             `json:"subject"`
	StatementSHA256    string             `json:"statementSha256"`
	ProvenanceSHA256   string             `json:"provenanceSha256"`
	ReviewBundleSHA256 string             `json:"reviewBundleSha256"`
	Blockers           []ReadinessBlocker `json:"blockers"`
}

type ReadinessBlocker struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// VerifyProductionReleaseCandidate verifies the trusted distribution first,
// then applies the strict activation profile. An invalid or absent signature is
// a verification error rather than a readiness result.
func VerifyProductionReleaseCandidate(bundle, statementPath, signaturePath, trustPolicyPath string) (*ProductionReadiness, error) {
	trusted, err := VerifySignedDistribution(bundle, statementPath, signaturePath, trustPolicyPath)
	if err != nil {
		return nil, err
	}
	return assessProductionReadiness(trusted), nil
}

func assessProductionReadiness(trusted *TrustedDistribution) *ProductionReadiness {
	manifest := trusted.Verification.Manifest
	report := &ProductionReadiness{
		Schema: ProductionReadinessSchemaV1, TrustedKeyID: trusted.KeyID, Subject: manifest.Subject.Revision,
		StatementSHA256: trusted.StatementSHA256, ProvenanceSHA256: trusted.Verification.ProvenanceSHA256,
		ReviewBundleSHA256: trusted.Verification.BundleSHA256, Blockers: make([]ReadinessBlocker, 0),
	}
	if manifest.Publication.CurrentPlugin != "adopted" {
		report.Blockers = append(report.Blockers, ReadinessBlocker{
			ID: "current-plugin-not-adopted", Detail: fmt.Sprintf("current plugin publication is %s, want adopted", manifest.Publication.CurrentPlugin),
		})
	}
	if manifest.Publication.ProductionWagoMerge != "published" {
		report.Blockers = append(report.Blockers, ReadinessBlocker{
			ID: "production-wago-merge-unpublished", Detail: fmt.Sprintf("production Wago merge publication is %s, want published", manifest.Publication.ProductionWagoMerge),
		})
	}
	if !strings.HasPrefix(manifest.Targets.Arm64Execution.Status, "executed-") {
		report.Blockers = append(report.Blockers, ReadinessBlocker{
			ID: "linux-arm64-not-executed", Detail: fmt.Sprintf("linux/arm64 execution is %s, want executed-*", manifest.Targets.Arm64Execution.Status),
		})
	}
	for _, exception := range manifest.Exceptions {
		report.Blockers = append(report.Blockers, ReadinessBlocker{
			ID: "accepted-exception:" + exception.ID, Detail: exception.Detail,
		})
	}
	report.Ready = len(report.Blockers) == 0
	return report
}

// WriteProductionReadinessReceipt atomically replaces a canonical readiness
// decision and then its adjacent SHA-256 sidecar. A failed sidecar write leaves
// no stale checksum that external automation could mistake for the new receipt.
func WriteProductionReadinessReceipt(destination string, report *ProductionReadiness) (string, error) {
	if destination == "" || report == nil || report.Schema != ProductionReadinessSchemaV1 || report.TrustedKeyID == "" ||
		!validObjectID(report.Subject) || !validSHA256(report.StatementSHA256) || !validSHA256(report.ProvenanceSHA256) ||
		!validSHA256(report.ReviewBundleSHA256) || report.Ready != (len(report.Blockers) == 0) {
		return "", fmt.Errorf("release provenance: invalid production readiness receipt")
	}
	for _, blocker := range report.Blockers {
		if blocker.ID == "" || blocker.Detail == "" {
			return "", fmt.Errorf("release provenance: invalid production readiness blocker")
		}
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
