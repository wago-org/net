package releaseprovenance

import (
	"fmt"
	"strings"
)

const ProductionReadinessSchemaV1 = "github.com/wago-org/net/production-readiness/v1"

// ProductionReadiness is a deterministic activation decision made only after a
// distribution statement has passed explicit-policy signature verification.
type ProductionReadiness struct {
	Schema       string             `json:"schema"`
	Ready        bool               `json:"ready"`
	TrustedKeyID string             `json:"trustedKeyId"`
	Subject      string             `json:"subject"`
	Blockers     []ReadinessBlocker `json:"blockers"`
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
