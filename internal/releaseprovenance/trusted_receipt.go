package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const TrustedDistributionReceiptSchemaV1 = "github.com/wago-org/net/trusted-distribution/v1"

// TrustedDistributionReceipt is retained evidence that exact signed
// distribution inputs passed explicit-policy cryptographic and archive
// verification. TrustedKeyID is only the opaque label from that policy; this
// receipt does not establish a real-world publisher identity.
type TrustedDistributionReceipt struct {
	Schema             string `json:"schema"`
	Algorithm          string `json:"algorithm"`
	TrustedKeyID       string `json:"trustedKeyId"`
	Subject            string `json:"subject"`
	StatementSHA256    string `json:"statementSha256"`
	SignatureSHA256    string `json:"signatureSha256"`
	TrustPolicySHA256  string `json:"trustPolicySha256"`
	ProvenanceSHA256   string `json:"provenanceSha256"`
	ReviewBundleSHA256 string `json:"reviewBundleSha256"`
}

// WriteTrustedDistributionReceipt atomically replaces a canonical trusted
// distribution receipt and then its adjacent SHA-256 sidecar. A failed sidecar
// write leaves no stale checksum that could be mistaken for the new receipt.
func WriteTrustedDistributionReceipt(destination string, trusted *TrustedDistribution) (string, error) {
	if destination == "" {
		return "", fmt.Errorf("release provenance: trusted distribution receipt path is required")
	}
	if trusted == nil || trusted.Statement == nil || trusted.Verification == nil || trusted.Verification.Manifest == nil {
		return "", fmt.Errorf("release provenance: invalid trusted distribution verification")
	}
	receipt := &TrustedDistributionReceipt{
		Schema: TrustedDistributionReceiptSchemaV1, Algorithm: "ed25519", TrustedKeyID: trusted.KeyID,
		Subject: trusted.Statement.Subject, StatementSHA256: trusted.StatementSHA256,
		SignatureSHA256: trusted.SignatureSHA256, TrustPolicySHA256: trusted.TrustPolicySHA256,
		ProvenanceSHA256:   trusted.Verification.ProvenanceSHA256,
		ReviewBundleSHA256: trusted.Verification.BundleSHA256,
	}
	if err := validateTrustedDistributionReceipt(receipt); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
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

func validateTrustedDistributionReceipt(receipt *TrustedDistributionReceipt) error {
	if receipt == nil || receipt.Schema != TrustedDistributionReceiptSchemaV1 || receipt.Algorithm != "ed25519" ||
		!validDistributionKeyID(receipt.TrustedKeyID) || !validObjectID(receipt.Subject) ||
		!validSHA256(receipt.StatementSHA256) || !validSHA256(receipt.SignatureSHA256) ||
		!validSHA256(receipt.TrustPolicySHA256) || !validSHA256(receipt.ProvenanceSHA256) ||
		!validSHA256(receipt.ReviewBundleSHA256) {
		return fmt.Errorf("release provenance: invalid trusted distribution receipt")
	}
	return nil
}
