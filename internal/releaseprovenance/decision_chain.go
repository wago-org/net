package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
)

// ProductionReadinessV2VerifyOptions are independently provisioned constraints
// for a retained linked readiness receipt. All fields are required.
type ProductionReadinessV2VerifyOptions struct {
	ExpectedSubject                          string
	ExpectedStatementSHA256                  string
	ExpectedSignatureSHA256                  string
	ExpectedTrustPolicySHA256                string
	ExpectedTrustedDistributionReceiptSHA256 string
}

// ReleaseDecisionChainVerifyOptions names the same complete constraint set when
// it is applied to both retained receipts together.
type ReleaseDecisionChainVerifyOptions = ProductionReadinessV2VerifyOptions

// ReleaseDecisionChain contains two canonical retained receipts whose exact
// linkage has been independently checked. This is retained evidence integrity,
// not fresh signature or archive verification and not a publisher identity.
type ReleaseDecisionChain struct {
	TrustedDistribution       *TrustedDistributionReceipt
	ProductionReadiness       *ProductionReadinessV2
	TrustedDistributionSHA256 string
	ProductionReadinessSHA256 string
}

// VerifyProductionReadinessReceiptV2 independently verifies canonical receipt
// bytes, the exact adjacent checksum sidecar, and all externally supplied
// selection and intermediary-receipt constraints. A valid blocked decision is
// returned without error.
func VerifyProductionReadinessReceiptV2(path string, opts ProductionReadinessV2VerifyOptions) (*ProductionReadinessV2, string, error) {
	if !validObjectID(opts.ExpectedSubject) || !validSHA256(opts.ExpectedStatementSHA256) ||
		!validSHA256(opts.ExpectedSignatureSHA256) || !validSHA256(opts.ExpectedTrustPolicySHA256) ||
		!validSHA256(opts.ExpectedTrustedDistributionReceiptSHA256) {
		return nil, "", fmt.Errorf("release provenance: explicit readiness v2 subject, statement, signature, trust policy, and trusted receipt constraints are required")
	}
	receiptData, err := readBoundedFile(path, 1<<20, "production readiness v2 receipt")
	if err != nil {
		return nil, "", err
	}
	receiptSum := sha256.Sum256(receiptData)
	digest := hex.EncodeToString(receiptSum[:])
	checksumData, err := readBoundedFile(path+".sha256", 256, "production readiness v2 checksum")
	if err != nil {
		return nil, "", err
	}
	wantChecksum := digest + "  " + filepath.Base(path) + "\n"
	if string(checksumData) != wantChecksum {
		return nil, "", fmt.Errorf("release provenance: production readiness v2 checksum does not match receipt")
	}
	var report ProductionReadinessV2
	if err := decodeCanonicalJSON(receiptData, &report, "production readiness v2 receipt"); err != nil {
		return nil, "", err
	}
	if err := validateProductionReadinessV2(&report); err != nil {
		return nil, "", err
	}
	if report.Subject != opts.ExpectedSubject {
		return nil, "", fmt.Errorf("release provenance: production readiness v2 subject does not match expected subject")
	}
	if report.StatementSHA256 != opts.ExpectedStatementSHA256 {
		return nil, "", fmt.Errorf("release provenance: production readiness v2 statement SHA-256 does not match expected statement")
	}
	if report.SignatureSHA256 != opts.ExpectedSignatureSHA256 {
		return nil, "", fmt.Errorf("release provenance: production readiness v2 signature SHA-256 does not match expected signature")
	}
	if report.TrustPolicySHA256 != opts.ExpectedTrustPolicySHA256 {
		return nil, "", fmt.Errorf("release provenance: production readiness v2 trust policy SHA-256 does not match expected trust policy")
	}
	if report.TrustedDistributionReceiptSHA256 != opts.ExpectedTrustedDistributionReceiptSHA256 {
		return nil, "", fmt.Errorf("release provenance: production readiness v2 trusted-distribution receipt SHA-256 does not match expected receipt")
	}
	return &report, digest, nil
}

// VerifyReleaseDecisionChain verifies both retained receipt/sidecar pairs under
// explicit external constraints and then requires every shared field and the
// intermediary receipt digest to match exactly. It does not repeat Ed25519 or
// archive verification and does not turn an opaque key label into identity.
func VerifyReleaseDecisionChain(trustedReceiptPath, readinessReceiptPath string, opts ReleaseDecisionChainVerifyOptions) (*ReleaseDecisionChain, error) {
	trusted, trustedSHA256, err := VerifyTrustedDistributionReceipt(trustedReceiptPath, TrustedDistributionReceiptVerifyOptions{
		ExpectedSubject: opts.ExpectedSubject, ExpectedStatementSHA256: opts.ExpectedStatementSHA256,
		ExpectedSignatureSHA256: opts.ExpectedSignatureSHA256, ExpectedTrustPolicySHA256: opts.ExpectedTrustPolicySHA256,
	})
	if err != nil {
		return nil, err
	}
	if trustedSHA256 != opts.ExpectedTrustedDistributionReceiptSHA256 {
		return nil, fmt.Errorf("release provenance: trusted-distribution receipt SHA-256 does not match expected intermediary receipt")
	}
	readiness, readinessSHA256, err := VerifyProductionReadinessReceiptV2(readinessReceiptPath, opts)
	if err != nil {
		return nil, err
	}
	if readiness.TrustedDistributionReceiptSHA256 != trustedSHA256 || readiness.Algorithm != trusted.Algorithm ||
		readiness.TrustedKeyID != trusted.TrustedKeyID || readiness.Subject != trusted.Subject ||
		readiness.StatementSHA256 != trusted.StatementSHA256 || readiness.SignatureSHA256 != trusted.SignatureSHA256 ||
		readiness.TrustPolicySHA256 != trusted.TrustPolicySHA256 || readiness.ProvenanceSHA256 != trusted.ProvenanceSHA256 ||
		readiness.ReviewBundleSHA256 != trusted.ReviewBundleSHA256 {
		return nil, fmt.Errorf("release provenance: production readiness v2 receipt does not match trusted-distribution receipt")
	}
	return &ReleaseDecisionChain{
		TrustedDistribution: trusted, ProductionReadiness: readiness,
		TrustedDistributionSHA256: trustedSHA256, ProductionReadinessSHA256: readinessSHA256,
	}, nil
}
