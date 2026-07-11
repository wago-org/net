package releaseprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const DistributionStatementSchemaV1 = "github.com/wago-org/net/distribution-statement/v1"

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
