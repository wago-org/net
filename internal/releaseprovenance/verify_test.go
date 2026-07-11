//go:build !tinygo

package releaseprovenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVerifyAndDeterministicBundleExport(t *testing.T) {
	dir, opts := validReviewFixture(t)
	verified, err := Verify(dir, opts)
	if err != nil {
		t.Fatalf("Verify directory: %v", err)
	}
	if verified.Manifest.Subject.Revision != opts.ExpectedSubject || len(verified.Manifest.ReviewSubjects) != 3 ||
		len(verified.Manifest.Exceptions) != 2 || len(verified.Manifest.Limitations) != 1 {
		t.Fatalf("verification = %+v", verified)
	}

	first := filepath.Join(t.TempDir(), "first.tar.gz")
	second := filepath.Join(t.TempDir(), "second.tar.gz")
	_, firstHash, err := ExportBundle(dir, first, opts)
	if err != nil {
		t.Fatalf("ExportBundle first: %v", err)
	}
	_, secondHash, err := ExportBundle(dir, second, opts)
	if err != nil {
		t.Fatalf("ExportBundle second: %v", err)
	}
	firstData, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash || !reflect.DeepEqual(firstData, secondData) {
		t.Fatalf("deterministic exports differ: %s != %s", firstHash, secondHash)
	}
	if _, err := Verify(first, opts); err != nil {
		t.Fatalf("Verify archive: %v", err)
	}
	strict := opts
	strict.ExpectedBundleSHA256 = firstHash
	strict.StrictDistribution = true
	verifiedStrict, err := Verify(first, strict)
	if err != nil {
		t.Fatalf("Verify strict distribution: %v", err)
	}
	if verifiedStrict.BundleSHA256 != firstHash {
		t.Fatalf("verified bundle hash = %q, want %q", verifiedStrict.BundleSHA256, firstHash)
	}
	wrongHash := strict
	wrongHash.ExpectedBundleSHA256 = strings.Repeat("f", 64)
	if _, err := Verify(first, wrongHash); err == nil {
		t.Fatal("wrong trusted bundle hash unexpectedly accepted")
	}
	missingHash := opts
	missingHash.StrictDistribution = true
	if _, err := Verify(first, missingHash); err == nil {
		t.Fatal("strict distribution without bundle hash unexpectedly accepted")
	}
	if _, err := Verify(dir, strict); err == nil {
		t.Fatal("strict distribution directory unexpectedly accepted")
	}

	firstStatement := filepath.Join(t.TempDir(), "distribution.json")
	secondStatement := filepath.Join(t.TempDir(), "distribution.json")
	statement, firstStatementHash, err := WriteDistributionStatement(first, firstStatement, strict)
	if err != nil {
		t.Fatalf("WriteDistributionStatement first: %v", err)
	}
	_, secondStatementHash, err := WriteDistributionStatement(second, secondStatement, strict)
	if err != nil {
		t.Fatalf("WriteDistributionStatement second: %v", err)
	}
	firstStatementData, err := os.ReadFile(firstStatement)
	if err != nil {
		t.Fatal(err)
	}
	secondStatementData, err := os.ReadFile(secondStatement)
	if err != nil {
		t.Fatal(err)
	}
	if firstStatementHash != secondStatementHash || !reflect.DeepEqual(firstStatementData, secondStatementData) {
		t.Fatalf("deterministic statements differ: %s != %s", firstStatementHash, secondStatementHash)
	}
	if statement.Schema != DistributionStatementSchemaV1 || statement.Subject != opts.ExpectedSubject ||
		statement.ProvenanceSHA256 != verifiedStrict.ProvenanceSHA256 || statement.ReviewBundleSHA256 != firstHash ||
		!reflect.DeepEqual(statement.ReviewSubjects, verifiedStrict.Manifest.ReviewSubjects) ||
		statement.Publication != verifiedStrict.Manifest.Publication {
		t.Fatalf("distribution statement = %+v", statement)
	}
	if strings.Contains(string(firstStatementData), "signature") || strings.Contains(string(firstStatementData), "publisherIdentity") {
		t.Fatalf("unsigned distribution statement contains an authenticity claim: %s", firstStatementData)
	}
	if _, _, err := WriteDistributionStatement(dir, filepath.Join(t.TempDir(), "invalid.json"), opts); err == nil {
		t.Fatal("distribution statement from directory unexpectedly accepted")
	}
}

func TestVerifySignedDistributionRequiresExplicitPolicyAndMatchingSignature(t *testing.T) {
	fixture := newSignedDistributionFixture(t)
	trusted, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, fixture.policy, fixture.opts)
	if err != nil {
		t.Fatalf("verify signed distribution: %v", err)
	}
	if trusted.KeyID != fixture.keyID || trusted.Statement.Subject != fixture.opts.ExpectedSubject ||
		trusted.Verification.BundleSHA256 != fixture.bundleHash || trusted.StatementSHA256 != fixture.statementHash ||
		trusted.SignatureSHA256 != fixture.signatureHash || trusted.TrustPolicySHA256 != fixture.policyHash {
		t.Fatalf("trusted distribution = %+v", trusted)
	}
	receiptPath := filepath.Join(t.TempDir(), "trusted-distribution.json")
	receiptHash, err := WriteTrustedDistributionReceipt(receiptPath, trusted)
	if err != nil {
		t.Fatal(err)
	}
	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt TrustedDistributionReceipt
	if err := decodeCanonicalJSON(receiptData, &receipt, "trusted distribution receipt"); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != TrustedDistributionReceiptSchemaV1 || receipt.Algorithm != "ed25519" ||
		receipt.TrustedKeyID != fixture.keyID || receipt.Subject != fixture.opts.ExpectedSubject ||
		receipt.StatementSHA256 != fixture.statementHash || receipt.SignatureSHA256 != fixture.signatureHash ||
		receipt.TrustPolicySHA256 != fixture.policyHash || receipt.ProvenanceSHA256 != trusted.Verification.ProvenanceSHA256 ||
		receipt.ReviewBundleSHA256 != fixture.bundleHash {
		t.Fatalf("trusted distribution receipt = %+v", receipt)
	}
	receiptSum := sha256.Sum256(receiptData)
	if got := hex.EncodeToString(receiptSum[:]); got != receiptHash {
		t.Fatalf("trusted distribution receipt SHA-256 = %s, want %s", got, receiptHash)
	}
	checksumData, err := os.ReadFile(receiptPath + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if want := receiptHash + "  " + filepath.Base(receiptPath) + "\n"; string(checksumData) != want {
		t.Fatalf("trusted distribution checksum = %q, want %q", checksumData, want)
	}
	if secondHash, err := WriteTrustedDistributionReceipt(receiptPath, trusted); err != nil || secondHash != receiptHash {
		t.Fatalf("deterministic trusted distribution receipt rewrite = %q, %v", secondHash, err)
	}
	if _, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, "", fixture.opts); err == nil {
		t.Fatal("implicit trust policy discovery unexpectedly accepted")
	}
	policyData, err := os.ReadFile(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	var policy DistributionTrustPolicy
	if err := json.Unmarshal(policyData, &policy); err != nil {
		t.Fatal(err)
	}
	policy.StatementSHA256 = ""
	policy.Subject = ""
	policyData, err = json.MarshalIndent(&policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, fixture.policy, string(append(policyData, '\n')))
	if _, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, fixture.policy, fixture.opts); err != nil {
		t.Fatalf("key-only signed review mode: %v", err)
	}

	signature, err := os.ReadFile(fixture.signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0xff
	if err := os.WriteFile(fixture.signature, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, fixture.policy, fixture.opts); err == nil {
		t.Fatal("wrong detached signature unexpectedly accepted")
	}

	policyData, err = os.ReadFile(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(policyData, &policy); err != nil {
		t.Fatal(err)
	}
	policy.KeyID = "https://implicit.example/key"
	policyData, err = json.MarshalIndent(&policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	policyData = append(policyData, '\n')
	writeTestFile(t, fixture.policy, string(policyData))
	if _, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, fixture.policy, fixture.opts); err == nil {
		t.Fatal("discovery-shaped trust policy key ID unexpectedly accepted")
	}
}

func TestVerifyTrustedDistributionReceiptIndependently(t *testing.T) {
	fixture := newSignedDistributionFixture(t)
	trusted, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, fixture.policy, fixture.opts)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(t.TempDir(), "trusted-distribution.json")
	receiptHash, err := WriteTrustedDistributionReceipt(receiptPath, trusted)
	if err != nil {
		t.Fatal(err)
	}
	verifyOpts := TrustedDistributionReceiptVerifyOptions{
		ExpectedSubject: fixture.opts.ExpectedSubject, ExpectedStatementSHA256: fixture.statementHash,
		ExpectedSignatureSHA256: fixture.signatureHash, ExpectedTrustPolicySHA256: fixture.policyHash,
	}
	verified, verifiedHash, err := VerifyTrustedDistributionReceipt(receiptPath, verifyOpts)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedHash != receiptHash || verified.Subject != fixture.opts.ExpectedSubject ||
		verified.StatementSHA256 != fixture.statementHash || verified.SignatureSHA256 != fixture.signatureHash ||
		verified.TrustPolicySHA256 != fixture.policyHash || verified.ProvenanceSHA256 != trusted.Verification.ProvenanceSHA256 ||
		verified.ReviewBundleSHA256 != fixture.bundleHash {
		t.Fatalf("verified trusted distribution receipt = %+v, %s", verified, verifiedHash)
	}
	for _, test := range []struct {
		name   string
		mutate func(*TrustedDistributionReceiptVerifyOptions)
	}{
		{name: "subject", mutate: func(opts *TrustedDistributionReceiptVerifyOptions) { opts.ExpectedSubject = strings.Repeat("f", 40) }},
		{name: "statement", mutate: func(opts *TrustedDistributionReceiptVerifyOptions) {
			opts.ExpectedStatementSHA256 = strings.Repeat("f", 64)
		}},
		{name: "signature", mutate: func(opts *TrustedDistributionReceiptVerifyOptions) {
			opts.ExpectedSignatureSHA256 = strings.Repeat("f", 64)
		}},
		{name: "trust policy", mutate: func(opts *TrustedDistributionReceiptVerifyOptions) {
			opts.ExpectedTrustPolicySHA256 = strings.Repeat("f", 64)
		}},
	} {
		t.Run("trusted receipt constraint "+test.name, func(t *testing.T) {
			wrong := verifyOpts
			test.mutate(&wrong)
			if _, _, err := VerifyTrustedDistributionReceipt(receiptPath, wrong); err == nil {
				t.Fatalf("wrong %s constraint unexpectedly accepted", test.name)
			}
		})
	}

	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "trusted-distribution.json")
	tamperedData := bytes.Replace(receiptData, []byte(fixture.keyID), []byte("release-test-2027"), 1)
	if reflect.DeepEqual(tamperedData, receiptData) {
		t.Fatal("trusted distribution tamper did not change receipt")
	}
	if err := os.WriteFile(tamperedPath, tamperedData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedPath+".sha256", []byte(receiptHash+"  "+filepath.Base(tamperedPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyTrustedDistributionReceipt(tamperedPath, verifyOpts); err == nil {
		t.Fatal("tampered trusted distribution receipt unexpectedly accepted")
	}

	noncanonicalPath := filepath.Join(t.TempDir(), "trusted-distribution.json")
	noncanonicalData, err := json.Marshal(verified)
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalData = append(noncanonicalData, '\n')
	noncanonicalSum := sha256.Sum256(noncanonicalData)
	noncanonicalHash := hex.EncodeToString(noncanonicalSum[:])
	if err := os.WriteFile(noncanonicalPath, noncanonicalData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noncanonicalPath+".sha256", []byte(noncanonicalHash+"  "+filepath.Base(noncanonicalPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyTrustedDistributionReceipt(noncanonicalPath, verifyOpts); err == nil {
		t.Fatal("noncanonical trusted distribution receipt unexpectedly accepted")
	}
}

func TestVerifySignedDistributionEnforcesAntiRollbackConstraints(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*DistributionTrustPolicy)
	}{
		{name: "statement digest", mutate: func(policy *DistributionTrustPolicy) { policy.StatementSHA256 = strings.Repeat("f", 64) }},
		{name: "subject", mutate: func(policy *DistributionTrustPolicy) { policy.Subject = strings.Repeat("f", 40) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSignedDistributionFixture(t)
			policyData, err := os.ReadFile(fixture.policy)
			if err != nil {
				t.Fatal(err)
			}
			var policy DistributionTrustPolicy
			if err := json.Unmarshal(policyData, &policy); err != nil {
				t.Fatal(err)
			}
			test.mutate(&policy)
			policyData, err = json.MarshalIndent(&policy, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, fixture.policy, string(append(policyData, '\n')))
			if _, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, fixture.policy, fixture.opts); err == nil {
				t.Fatalf("mismatched %s constraint unexpectedly accepted", test.name)
			}
		})
	}
}

func TestDetachedSignatureInteroperabilityVectors(t *testing.T) {
	dir := filepath.Join("testdata", "distribution-signature-v1")
	vectorData, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema                 string `json:"schema"`
		Algorithm              string `json:"algorithm"`
		MessageEncoding        string `json:"messageEncoding"`
		PublicKeyBase64        string `json:"publicKeyBase64"`
		StatementSHA256        string `json:"statementSha256"`
		SignatureSHA256        string `json:"signatureSha256"`
		InvalidSignatureSHA256 string `json:"invalidSignatureSha256"`
		AlteredStatementSHA256 string `json:"alteredStatementSha256"`
		Cases                  []struct {
			Name      string `json:"name"`
			Statement string `json:"statement"`
			Signature string `json:"signature"`
			Result    string `json:"result"`
		} `json:"cases"`
	}
	if err := decodeCanonicalJSON(vectorData, &vectors, "distribution signature vectors"); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "github.com/wago-org/net/distribution-signature-vectors/v1" ||
		vectors.Algorithm != "ed25519" || vectors.MessageEncoding != "exact-file-bytes" || len(vectors.Cases) != 3 {
		t.Fatalf("vector metadata = %+v", vectors)
	}

	policyData, err := os.ReadFile(filepath.Join(dir, "trust-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy DistributionTrustPolicy
	if err := decodeCanonicalJSON(policyData, &policy, "distribution trust policy vector"); err != nil {
		t.Fatal(err)
	}
	publicKey, err := validateDistributionTrustPolicy(&policy)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(publicKey) != vectors.PublicKeyBase64 {
		t.Fatal("vector public key does not match trust policy")
	}

	wantDigests := map[string]string{
		"statement.json":            vectors.StatementSHA256,
		"statement-altered.json":    vectors.AlteredStatementSHA256,
		"signature.ed25519":         vectors.SignatureSHA256,
		"signature-invalid.ed25519": vectors.InvalidSignatureSHA256,
	}
	for name, want := range wantDigests {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("%s SHA-256 = %s, want %s", name, got, want)
		}
	}

	for _, vector := range vectors.Cases {
		statementData, err := os.ReadFile(filepath.Join(dir, vector.Statement))
		if err != nil {
			t.Fatal(err)
		}
		var statement DistributionStatement
		if err := decodeCanonicalJSON(statementData, &statement, "distribution statement vector"); err != nil {
			t.Fatal(err)
		}
		if err := validateDistributionStatement(&statement, VerifyOptions{}); err != nil {
			t.Fatal(err)
		}
		signature, err := os.ReadFile(filepath.Join(dir, vector.Signature))
		if err != nil {
			t.Fatal(err)
		}
		if len(signature) != ed25519.SignatureSize {
			t.Fatalf("%s signature size = %d", vector.Name, len(signature))
		}
		gotValid := ed25519.Verify(publicKey, statementData, signature)
		wantValid := vector.Result == "valid"
		if gotValid != wantValid {
			t.Fatalf("%s verification = %t, want %t", vector.Name, gotValid, wantValid)
		}
		sum := sha256.Sum256(statementData)
		constraintErr := enforceDistributionTrustConstraints(&policy, &statement, hex.EncodeToString(sum[:]))
		if (constraintErr == nil) != (vector.Statement == "statement.json") {
			t.Fatalf("%s anti-rollback constraint error = %v", vector.Name, constraintErr)
		}
	}
}

func TestTrustedDistributionReceiptInteroperabilityVectors(t *testing.T) {
	dir := filepath.Join("testdata", "trusted-distribution-receipt-v1")
	vectorData, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema            string `json:"schema"`
		ReceiptEncoding   string `json:"receiptEncoding"`
		Subject           string `json:"subject"`
		StatementSHA256   string `json:"statementSha256"`
		SignatureSHA256   string `json:"signatureSha256"`
		TrustPolicySHA256 string `json:"trustPolicySha256"`
		Files             []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
		Cases []struct {
			Name              string `json:"name"`
			Receipt           string `json:"receipt"`
			Subject           string `json:"subject"`
			StatementSHA256   string `json:"statementSha256"`
			SignatureSHA256   string `json:"signatureSha256"`
			TrustPolicySHA256 string `json:"trustPolicySha256"`
			Result            string `json:"result"`
		} `json:"cases"`
	}
	if err := decodeCanonicalJSON(vectorData, &vectors, "trusted distribution receipt vectors"); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "github.com/wago-org/net/trusted-distribution-receipt-vectors/v1" ||
		vectors.ReceiptEncoding != "exact-canonical-file-bytes-with-adjacent-sha256" ||
		!validObjectID(vectors.Subject) || !validSHA256(vectors.StatementSHA256) ||
		!validSHA256(vectors.SignatureSHA256) || !validSHA256(vectors.TrustPolicySHA256) ||
		len(vectors.Files) != 4 || len(vectors.Cases) != 6 {
		t.Fatalf("trusted distribution vector metadata = %+v", vectors)
	}

	fileDigests := make(map[string]string, len(vectors.Files))
	for _, file := range vectors.Files {
		data, err := os.ReadFile(filepath.Join(dir, file.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != file.SHA256 {
			t.Fatalf("%s SHA-256 = %s, want %s", file.Path, got, file.SHA256)
		}
		fileDigests[file.Path] = file.SHA256
	}
	receiptData, err := os.ReadFile(filepath.Join(dir, "trusted-distribution.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt TrustedDistributionReceipt
	if err := decodeCanonicalJSON(receiptData, &receipt, "trusted distribution receipt vector"); err != nil {
		t.Fatal(err)
	}
	if err := validateTrustedDistributionReceipt(&receipt); err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors.Cases {
		receipt, digest, err := VerifyTrustedDistributionReceipt(filepath.Join(dir, vector.Receipt), TrustedDistributionReceiptVerifyOptions{
			ExpectedSubject: vector.Subject, ExpectedStatementSHA256: vector.StatementSHA256,
			ExpectedSignatureSHA256: vector.SignatureSHA256, ExpectedTrustPolicySHA256: vector.TrustPolicySHA256,
		})
		switch vector.Result {
		case "reject":
			if err == nil {
				t.Fatalf("%s unexpectedly accepted: %+v, %s", vector.Name, receipt, digest)
			}
		case "valid":
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			if digest != fileDigests[vector.Receipt] || receipt.Subject != vectors.Subject ||
				receipt.StatementSHA256 != vectors.StatementSHA256 || receipt.SignatureSHA256 != vectors.SignatureSHA256 ||
				receipt.TrustPolicySHA256 != vectors.TrustPolicySHA256 {
				t.Fatalf("%s verification = %+v, %s", vector.Name, receipt, digest)
			}
		default:
			t.Fatalf("%s has unknown result %q", vector.Name, vector.Result)
		}
	}
}

func TestProductionReadinessReceiptInteroperabilityVectors(t *testing.T) {
	dir := filepath.Join("testdata", "readiness-receipt-v1")
	vectorData, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema            string `json:"schema"`
		ReceiptEncoding   string `json:"receiptEncoding"`
		Subject           string `json:"subject"`
		StatementSHA256   string `json:"statementSha256"`
		TrustPolicySHA256 string `json:"trustPolicySha256"`
		Files             []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
		Cases []struct {
			Name              string `json:"name"`
			Receipt           string `json:"receipt"`
			Subject           string `json:"subject"`
			StatementSHA256   string `json:"statementSha256"`
			TrustPolicySHA256 string `json:"trustPolicySha256"`
			Result            string `json:"result"`
		} `json:"cases"`
	}
	if err := decodeCanonicalJSON(vectorData, &vectors, "production readiness receipt vectors"); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "github.com/wago-org/net/readiness-receipt-vectors/v1" ||
		vectors.ReceiptEncoding != "exact-canonical-file-bytes-with-adjacent-sha256" ||
		!validObjectID(vectors.Subject) || !validSHA256(vectors.StatementSHA256) ||
		!validSHA256(vectors.TrustPolicySHA256) || len(vectors.Files) != 6 || len(vectors.Cases) != 6 {
		t.Fatalf("readiness vector metadata = %+v", vectors)
	}

	fileDigests := make(map[string]string, len(vectors.Files))
	for _, file := range vectors.Files {
		data, err := os.ReadFile(filepath.Join(dir, file.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != file.SHA256 {
			t.Fatalf("%s SHA-256 = %s, want %s", file.Path, got, file.SHA256)
		}
		fileDigests[file.Path] = file.SHA256
	}
	for _, receipt := range []string{"ready.json", "blocked.json"} {
		receiptData, err := os.ReadFile(filepath.Join(dir, receipt))
		if err != nil {
			t.Fatal(err)
		}
		var report ProductionReadiness
		if err := decodeCanonicalJSON(receiptData, &report, "production readiness receipt vector"); err != nil {
			t.Fatal(err)
		}
		if err := validateProductionReadiness(&report); err != nil {
			t.Fatal(err)
		}
	}

	for _, vector := range vectors.Cases {
		report, digest, err := VerifyProductionReadinessReceipt(filepath.Join(dir, vector.Receipt), ProductionReadinessVerifyOptions{
			ExpectedSubject: vector.Subject, ExpectedStatementSHA256: vector.StatementSHA256,
			ExpectedTrustPolicySHA256: vector.TrustPolicySHA256,
		})
		switch vector.Result {
		case "reject":
			if err == nil {
				t.Fatalf("%s unexpectedly accepted: %+v, %s", vector.Name, report, digest)
			}
		case "ready", "blocked":
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			wantReady := vector.Result == "ready"
			if report.Ready != wantReady || digest != fileDigests[vector.Receipt] ||
				report.Subject != vectors.Subject || report.StatementSHA256 != vectors.StatementSHA256 ||
				report.TrustPolicySHA256 != vectors.TrustPolicySHA256 {
				t.Fatalf("%s verification = %+v, %s", vector.Name, report, digest)
			}
		default:
			t.Fatalf("%s has unknown result %q", vector.Name, vector.Result)
		}
	}
}

func TestProductionReadinessProfileReportsExactCurrentBlockers(t *testing.T) {
	fixture := newSignedDistributionFixture(t)
	trusted, err := verifySignedDistribution(fixture.bundle, fixture.statement, fixture.signature, fixture.policy, fixture.opts)
	if err != nil {
		t.Fatal(err)
	}
	report := assessProductionReadiness(trusted)
	var got []string
	for _, blocker := range report.Blockers {
		got = append(got, blocker.ID)
	}
	want := []string{
		"current-plugin-not-adopted",
		"production-wago-merge-unpublished",
		"linux-arm64-not-executed",
		"accepted-exception:wasi-upstream-preview1-audit",
		"accepted-exception:wasi-preview1-native-sigsegv",
	}
	if report.Ready || report.Schema != ProductionReadinessSchemaV1 || report.TrustedKeyID != fixture.keyID ||
		report.TrustPolicySHA256 != fixture.policyHash || report.StatementSHA256 != fixture.statementHash ||
		report.ProvenanceSHA256 != trusted.Verification.ProvenanceSHA256 ||
		report.ReviewBundleSHA256 != fixture.bundleHash || !reflect.DeepEqual(got, want) {
		t.Fatalf("production readiness = %+v, blocker IDs %v", report, got)
	}

	receiptPath := filepath.Join(t.TempDir(), "production-readiness.json")
	receiptHash, err := WriteProductionReadinessReceipt(receiptPath, report)
	if err != nil {
		t.Fatal(err)
	}
	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ProductionReadiness
	if err := decodeCanonicalJSON(receiptData, &receipt, "production readiness receipt"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&receipt, report) {
		t.Fatalf("receipt = %+v, want %+v", receipt, report)
	}
	receiptSum := sha256.Sum256(receiptData)
	if got := hex.EncodeToString(receiptSum[:]); got != receiptHash {
		t.Fatalf("receipt SHA-256 = %s, want %s", got, receiptHash)
	}
	checksumData, err := os.ReadFile(receiptPath + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if wantChecksum := receiptHash + "  " + filepath.Base(receiptPath) + "\n"; string(checksumData) != wantChecksum {
		t.Fatalf("receipt checksum = %q, want %q", checksumData, wantChecksum)
	}
	secondHash, err := WriteProductionReadinessReceipt(receiptPath, report)
	if err != nil || secondHash != receiptHash {
		t.Fatalf("deterministic receipt rewrite = %q, %v", secondHash, err)
	}
	verifyOpts := ProductionReadinessVerifyOptions{
		ExpectedSubject: fixture.opts.ExpectedSubject, ExpectedStatementSHA256: fixture.statementHash,
		ExpectedTrustPolicySHA256: fixture.policyHash,
	}
	verifiedReceipt, verifiedHash, err := VerifyProductionReadinessReceipt(receiptPath, verifyOpts)
	if err != nil {
		t.Fatalf("verify blocked readiness receipt: %v", err)
	}
	if verifiedReceipt.Ready || verifiedHash != receiptHash || !reflect.DeepEqual(verifiedReceipt, report) {
		t.Fatalf("verified blocked receipt = %+v, %s", verifiedReceipt, verifiedHash)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProductionReadinessVerifyOptions)
	}{
		{name: "subject", mutate: func(opts *ProductionReadinessVerifyOptions) { opts.ExpectedSubject = strings.Repeat("f", 40) }},
		{name: "statement", mutate: func(opts *ProductionReadinessVerifyOptions) { opts.ExpectedStatementSHA256 = strings.Repeat("f", 64) }},
		{name: "trust policy", mutate: func(opts *ProductionReadinessVerifyOptions) { opts.ExpectedTrustPolicySHA256 = strings.Repeat("f", 64) }},
	} {
		t.Run("receipt constraint "+test.name, func(t *testing.T) {
			wrong := verifyOpts
			test.mutate(&wrong)
			if _, _, err := VerifyProductionReadinessReceipt(receiptPath, wrong); err == nil {
				t.Fatalf("wrong %s constraint unexpectedly accepted", test.name)
			}
		})
	}

	tamperedPath := filepath.Join(t.TempDir(), "production-readiness.json")
	tamperedData := bytes.Replace(receiptData, []byte(fixture.keyID), []byte("release-test-2027"), 1)
	if reflect.DeepEqual(tamperedData, receiptData) {
		t.Fatal("readiness tamper did not change receipt")
	}
	if err := os.WriteFile(tamperedPath, tamperedData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedPath+".sha256", []byte(receiptHash+"  "+filepath.Base(tamperedPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyProductionReadinessReceipt(tamperedPath, verifyOpts); err == nil {
		t.Fatal("tampered readiness receipt unexpectedly accepted")
	}

	noncanonicalPath := filepath.Join(t.TempDir(), "production-readiness.json")
	noncanonicalData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalData = append(noncanonicalData, '\n')
	noncanonicalSum := sha256.Sum256(noncanonicalData)
	noncanonicalHash := hex.EncodeToString(noncanonicalSum[:])
	if err := os.WriteFile(noncanonicalPath, noncanonicalData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noncanonicalPath+".sha256", []byte(noncanonicalHash+"  "+filepath.Base(noncanonicalPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyProductionReadinessReceipt(noncanonicalPath, verifyOpts); err == nil {
		t.Fatal("noncanonical readiness receipt unexpectedly accepted")
	}

	trusted.Verification.Manifest.Publication.CurrentPlugin = "adopted"
	trusted.Verification.Manifest.Publication.ProductionWagoMerge = "published"
	trusted.Verification.Manifest.Targets.Arm64Execution.Status = "executed-qemu"
	trusted.Verification.Manifest.Targets.Arm64Execution.Runner = "qemu-aarch64"
	trusted.Verification.Manifest.Exceptions = nil
	trusted.Verification.Manifest.Limitations = nil
	ready := assessProductionReadiness(trusted)
	if !ready.Ready || len(ready.Blockers) != 0 {
		t.Fatalf("ready production profile = %+v", ready)
	}
	readyPath := filepath.Join(t.TempDir(), "production-readiness.json")
	readyHash, err := WriteProductionReadinessReceipt(readyPath, ready)
	if err != nil {
		t.Fatal(err)
	}
	verifiedReady, verifiedReadyHash, err := VerifyProductionReadinessReceipt(readyPath, verifyOpts)
	if err != nil {
		t.Fatalf("verify ready receipt: %v", err)
	}
	if !verifiedReady.Ready || verifiedReadyHash != readyHash || len(verifiedReady.Blockers) != 0 {
		t.Fatalf("verified ready receipt = %+v, %s", verifiedReady, verifiedReadyHash)
	}
}

type signedDistributionFixture struct {
	bundle, statement, signature, policy                        string
	opts                                                        VerifyOptions
	keyID, bundleHash, statementHash, signatureHash, policyHash string
}

func newSignedDistributionFixture(t *testing.T) signedDistributionFixture {
	t.Helper()
	dir, opts := validReviewFixture(t)
	bundle := filepath.Join(t.TempDir(), "review.tar.gz")
	_, bundleHash, err := ExportBundle(dir, bundle, opts)
	if err != nil {
		t.Fatal(err)
	}
	strict := opts
	strict.ExpectedBundleSHA256 = bundleHash
	strict.StrictDistribution = true
	statementPath := filepath.Join(t.TempDir(), "distribution.json")
	if _, _, err := WriteDistributionStatement(bundle, statementPath, strict); err != nil {
		t.Fatal(err)
	}
	statementData, err := os.ReadFile(statementPath)
	if err != nil {
		t.Fatal(err)
	}
	statementSum := sha256.Sum256(statementData)
	statementHash := hex.EncodeToString(statementSum[:])
	seed := sha256.Sum256([]byte("wago net detached signature test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	policy := DistributionTrustPolicy{
		Schema: DistributionTrustPolicySchemaV1, KeyID: "release-test-2026", Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey), StatementSHA256: statementHash, Subject: opts.ExpectedSubject,
	}
	policyData, err := json.MarshalIndent(&policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	policyData = append(policyData, '\n')
	policySum := sha256.Sum256(policyData)
	policyHash := hex.EncodeToString(policySum[:])
	policyPath := filepath.Join(t.TempDir(), "trust-policy.json")
	writeTestFile(t, policyPath, string(policyData))
	signature := ed25519.Sign(privateKey, statementData)
	signatureSum := sha256.Sum256(signature)
	signatureHash := hex.EncodeToString(signatureSum[:])
	signaturePath := filepath.Join(t.TempDir(), "distribution.sig")
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	return signedDistributionFixture{
		bundle: bundle, statement: statementPath, signature: signaturePath, policy: policyPath,
		opts: opts, keyID: policy.KeyID, bundleHash: bundleHash, statementHash: statementHash,
		signatureHash: signatureHash, policyHash: policyHash,
	}
}

func TestExportSourceObjectsIsDeterministic(t *testing.T) {
	repositories := newSourceObjectFixture(t)
	sets := fixtureSourceObjectSets(repositories)
	first, second := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	if err := ExportSourceObjects(first, sets); err != nil {
		t.Fatal(err)
	}
	if err := ExportSourceObjects(second, sets); err != nil {
		t.Fatal(err)
	}
	for _, set := range sets {
		for _, suffix := range []string{".objects", ".pack"} {
			left, err := os.ReadFile(filepath.Join(first, set.Name+suffix))
			if err != nil {
				t.Fatal(err)
			}
			right, err := os.ReadFile(filepath.Join(second, set.Name+suffix))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(left, right) {
				t.Fatalf("%s%s exports differ", set.Name, suffix)
			}
		}
	}
}

func TestVerifyRejectsTamperedEvidenceAndWrongSubject(t *testing.T) {
	dir, opts := validReviewFixture(t)
	wrong := opts
	wrong.ExpectedSubject = strings.Repeat("f", 40)
	if _, err := Verify(dir, wrong); err == nil {
		t.Fatal("wrong expected subject unexpectedly accepted")
	}
	writeTestFile(t, filepath.Join(dir, "arm64", "runner.txt"), "runner=forged\n")
	if _, err := Verify(dir, opts); err == nil {
		t.Fatal("tampered evidence unexpectedly accepted")
	}

	dir, opts = validReviewFixture(t)
	packPath := filepath.Join(dir, "source-objects", "wago.pack")
	pack, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	pack[len(pack)/2] ^= 0xff
	if err := os.WriteFile(packPath, pack, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, opts); err == nil {
		t.Fatal("tampered source-object pack unexpectedly accepted")
	}
}

func TestVerifyRejectsNoncanonicalOrPolicyDriftedManifest(t *testing.T) {
	dir, opts := validReviewFixture(t)
	path := filepath.Join(dir, "provenance.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Inputs[0].Parents[0], manifest.Inputs[0].Parents[1] = manifest.Inputs[0].Parents[1], manifest.Inputs[0].Parents[0]
	writeManifestFixture(t, dir, &manifest)
	if _, err := Verify(dir, opts); err == nil {
		t.Fatal("reordered Wago parents unexpectedly accepted")
	}

	dir, opts = validReviewFixture(t)
	data, err = os.ReadFile(filepath.Join(dir, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.ReviewSubjects[2].Parents[0], manifest.ReviewSubjects[2].Parents[1] = manifest.ReviewSubjects[2].Parents[1], manifest.ReviewSubjects[2].Parents[0]
	writeManifestFixture(t, dir, &manifest)
	if _, err := Verify(dir, opts); err == nil {
		t.Fatal("reordered review subject parents unexpectedly accepted")
	}

	dir, opts = validReviewFixture(t)
	data, err = os.ReadFile(filepath.Join(dir, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Publication.HostedReleaseAutomation = "active"
	if err := validateManifest(&manifest, opts); err == nil {
		t.Fatal("hosted release activation overclaim unexpectedly accepted")
	}
}

func validReviewFixture(t *testing.T) (string, VerifyOptions) {
	t.Helper()
	dir := t.TempDir()
	repositories := newSourceObjectFixture(t)
	subject := repositories.net.Revision
	checks := []Check{
		{Name: "pinned-revisions", Status: "pass"},
		{Name: "initial-clean-trees", Status: "pass"},
		{Name: "wago-plugin-plan-compat", Status: "pass"},
		{Name: "current-plugin-topology-audit", Status: "pass"},
		{Name: "wasi-upstream-preview1-audit", Status: "accepted-exception", Detail: "reviewed docs/CI-only upstream retains crash"},
		{Name: "go-test-workspace", Status: "pass"},
		{Name: "go-test-module", Status: "pass"},
		{Name: "go-test-race", Status: "pass"},
		{Name: "go-vet", Status: "pass"},
		{Name: "go-list", Status: "pass"},
		{Name: "go-mod-tidy", Status: "pass"},
		{Name: "fuzz-dns-wire", Status: "pass"},
		{Name: "fuzz-dns-layout", Status: "pass"},
		{Name: "fuzz-dns-guest", Status: "pass"},
		{Name: "fuzz-shared-layout", Status: "pass"},
		{Name: "benchmark-guest-poll", Status: "pass"},
		{Name: "benchmark-udp-queue", Status: "pass"},
		{Name: "tinygo-test", Status: "pass"},
		{Name: "cross-build", Status: "pass"},
		{Name: "arm64-execution", Status: "skipped-no-runner"},
		{Name: "source-boundaries", Status: "pass"},
		{Name: "custom-cli-inspection", Status: "pass"},
		{Name: "wago-lifecycle-worker-tests", Status: "pass"},
		{Name: "lneto-test", Status: "pass"},
		{Name: "wasi-preview1-native-sigsegv", Status: "accepted-exception", Detail: "documented native preview-1 crash"},
		{Name: "final-clean-trees", Status: "pass"},
		{Name: "source-object-packs", Status: "pass"},
		{Name: "current-plugin-review-signoff", Status: "pass"},
	}
	var checkText strings.Builder
	for _, check := range checks {
		checkText.WriteString(check.Name + "\t" + check.Status)
		if check.Detail != "" {
			checkText.WriteString("\t" + check.Detail)
		}
		checkText.WriteByte('\n')
	}
	writeTestFile(t, filepath.Join(dir, "checks.tsv"), checkText.String())
	writeTestFile(t, filepath.Join(dir, "publication.txt"), "current_plugin=review-only\nproduction_wago_merge=unpublished\nexternal_workers=published\npooling=unsupported\npublisher_authentication=external-required\nhosted_release_automation=disabled\n")
	writeTestFile(t, filepath.Join(dir, "toolchains.txt"), "go: go version go1.24.4 linux/amd64\ntinygo: tinygo version 0.41.1 linux/amd64\n")
	writeTestFile(t, filepath.Join(dir, "revisions.txt"), "plugin: "+subject+"\nWago: "+repositories.wago.Revision+"\nlneto: "+repositories.lneto.Revision+"\nWASI: "+repositories.wasi.Revision+"\ncurrent net review: "+repositories.currentNet.Revision+"\ncurrent Wago review: "+repositories.currentWago.Revision+"\nworkers: "+repositories.workers.Revision+"\n")
	writeTestFile(t, filepath.Join(dir, "arm64", "status.txt"), "status=skipped-no-runner\n")
	writeTestFile(t, filepath.Join(dir, "arm64", "runner.txt"), "runner=none\n")
	binaryHash := strings.Repeat("b", 64)
	writeTestFile(t, filepath.Join(dir, "arm64", "binary.sha256"), binaryHash+"  net-arm64.test\n")

	var imports []map[string]string
	for module, count := range map[string]int{"wago_net": 1, "wago_net_dns": 6, "wago_net_tcp": 11, "wago_net_udp": 6} {
		for i := 0; i < count; i++ {
			imports = append(imports, map[string]string{"module": module})
		}
	}
	sortInspectionImports(imports)
	inspectionData, err := json.Marshal(struct {
		Capabilities []string            `json:"capabilities"`
		Imports      []map[string]string `json:"imports"`
	}{Capabilities: []string{"net.dns", "net.info", "net.tcp", "net.udp"}, Imports: imports})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-go.json"), string(inspectionData))
	writeTestFile(t, filepath.Join(dir, "custom-cli", "inspection-tinygo.json"), string(inspectionData))

	var inspection Inspection
	if err := readInspection(dir, &inspection); err != nil {
		t.Fatal(err)
	}
	if err := ExportSourceObjects(filepath.Join(dir, "source-objects"), fixtureSourceObjectSets(repositories)); err != nil {
		t.Fatal(err)
	}
	artifacts, err := scanArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &Manifest{
		Schema:  SchemaV2,
		Subject: repositories.net.Repository,
		Inputs: []Repository{
			repositories.wago.Repository,
			repositories.lneto.Repository,
			repositories.wasi.Repository,
		},
		ReviewSubjects: []Repository{
			repositories.currentNet.Repository,
			repositories.currentWago.Repository,
			repositories.workers.Repository,
		},
		Publication: PublicationStatus{
			CurrentPlugin: "review-only", ProductionWagoMerge: "unpublished", ExternalWorkers: "published",
			Pooling: "unsupported", PublisherAuthentication: "external-required", HostedReleaseAutomation: "disabled",
		},
		Toolchains: Toolchains{Go: "go version go1.24.4 linux/amd64", TinyGo: "tinygo version 0.41.1 linux/amd64"},
		Inspection: inspection,
		Targets: Targets{
			CrossBuild:     TargetResult{GOOS: "linux", GOARCH: "arm64", Status: "pass"},
			Arm64Execution: TargetResult{GOOS: "linux", GOARCH: "arm64", Status: "skipped-no-runner", Runner: "none", BinarySHA256: binaryHash},
		},
		Checks:    checks,
		Artifacts: artifacts,
		Exceptions: []Exception{
			{ID: "wasi-upstream-preview1-audit", Status: "accepted-exception", Detail: "reviewed docs/CI-only upstream retains crash"},
			{ID: "wasi-preview1-native-sigsegv", Status: "accepted-exception", Detail: "documented native preview-1 crash"},
		},
		Limitations: []Limitation{{
			ID: "linux-arm64-execution", Status: "skipped-no-runner",
			Detail: "cross-build passed, but this release gate did not execute the arm64 smoke binary",
		}},
	}
	var evidence strings.Builder
	for _, artifact := range artifacts {
		evidence.WriteString(artifact.SHA256 + "  " + artifact.Path + "\n")
	}
	writeTestFile(t, filepath.Join(dir, "evidence.sha256"), evidence.String())
	writeManifestFixture(t, dir, manifest)
	return dir, VerifyOptions{
		ExpectedSubject: subject,
		expectedInputs: []Repository{
			repositories.wago.Repository,
			repositories.lneto.Repository,
			repositories.wasi.Repository,
		},
		expectedReviewSources: []Repository{
			repositories.currentNet.Repository,
			repositories.currentWago.Repository,
			repositories.workers.Repository,
		},
	}
}

type testSourceRepository struct {
	Repository
	Directory string
}

type testSourceRepositories struct {
	net, wago, lneto, wasi, currentNet, currentWago, workers testSourceRepository
}

func newSourceObjectFixture(t *testing.T) testSourceRepositories {
	t.Helper()
	return testSourceRepositories{
		net:         newLinearSourceRepository(t, "net"),
		wago:        newMergeSourceRepository(t, "wago"),
		lneto:       newLinearSourceRepository(t, "lneto"),
		wasi:        newLinearSourceRepository(t, "wasi"),
		currentNet:  newReviewSourceRepository(t, "net-current-review"),
		currentWago: newReviewSourceRepository(t, "wago-current-review"),
		workers:     newMergeSourceRepository(t, "workers-current"),
	}
}

func fixtureSourceObjectSets(repositories testSourceRepositories) []SourceObjectSet {
	return []SourceObjectSet{
		{Name: "net", Directory: repositories.net.Directory, Revisions: []string{repositories.net.Revision}},
		{Name: "wago", Directory: repositories.wago.Directory, Revisions: append([]string{repositories.wago.Revision}, repositories.wago.Parents...)},
		{Name: "lneto", Directory: repositories.lneto.Directory, Revisions: []string{repositories.lneto.Revision}},
		{Name: "wasi", Directory: repositories.wasi.Directory, Revisions: []string{repositories.wasi.Revision}},
		{Name: "net-current-review", Directory: repositories.currentNet.Directory, Revisions: []string{repositories.currentNet.Revision}},
		{Name: "wago-current-review", Directory: repositories.currentWago.Directory, Revisions: []string{repositories.currentWago.Revision}},
		{Name: "workers-current", Directory: repositories.workers.Directory, Revisions: []string{repositories.workers.Revision}},
	}
}

func newLinearSourceRepository(t *testing.T, name string) testSourceRepository {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
	runTestGit(t, "", "init", "--quiet", "--initial-branch=main", directory)
	writeTestFile(t, filepath.Join(directory, name+".txt"), name+" source\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", name+" source")
	return testRepositoryIdentity(t, directory, name, nil)
}

func newReviewSourceRepository(t *testing.T, name string) testSourceRepository {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
	runTestGit(t, "", "init", "--quiet", "--initial-branch=main", directory)
	writeTestFile(t, filepath.Join(directory, "base.txt"), "base\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "base")
	parent := testGitText(t, directory, "rev-parse", "HEAD")
	writeTestFile(t, filepath.Join(directory, name+".txt"), name+" source\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", name+" review")
	return testRepositoryIdentity(t, directory, name, []string{parent})
}

func newMergeSourceRepository(t *testing.T, name string) testSourceRepository {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
	runTestGit(t, "", "init", "--quiet", "--initial-branch=main", directory)
	writeTestFile(t, filepath.Join(directory, "base.txt"), "base\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "base")
	base := testGitText(t, directory, "rev-parse", "HEAD")

	writeTestFile(t, filepath.Join(directory, "main.txt"), "main parent\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "main parent")
	parent1 := testGitText(t, directory, "rev-parse", "HEAD")

	runTestGit(t, directory, "checkout", "--quiet", "-b", "workers", base)
	writeTestFile(t, filepath.Join(directory, "workers.txt"), "worker parent\n")
	runTestGit(t, directory, "add", ".")
	runTestGit(t, directory, "commit", "--quiet", "-m", "worker parent")
	parent2 := testGitText(t, directory, "rev-parse", "HEAD")

	runTestGit(t, directory, "checkout", "--quiet", "main")
	runTestGit(t, directory, "merge", "--quiet", "--no-ff", "-m", "merge parents", "workers")
	return testRepositoryIdentity(t, directory, name, []string{parent1, parent2})
}

func testRepositoryIdentity(t *testing.T, directory, name string, parents []string) testSourceRepository {
	t.Helper()
	return testSourceRepository{
		Repository: Repository{
			Name: name, Revision: testGitText(t, directory, "rev-parse", "HEAD"),
			Tree: testGitText(t, directory, "rev-parse", "HEAD^{tree}"), Parents: parents,
		},
		Directory: directory,
	}
}

func runTestGit(t *testing.T, directory string, args ...string) {
	t.Helper()
	commandArgs := append([]string{}, args...)
	if directory != "" {
		commandArgs = append([]string{"-C", directory}, commandArgs...)
	}
	command := exec.Command("git", commandArgs...)
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Release Test", "GIT_AUTHOR_EMAIL=release@example.com",
		"GIT_COMMITTER_NAME=Release Test", "GIT_COMMITTER_EMAIL=release@example.com",
		"GIT_AUTHOR_DATE=2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2000-01-01T00:00:00Z",
	)
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(commandArgs, " "), err, data)
	}
}

func testGitText(t *testing.T, directory string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", directory}, args...)
	data, err := exec.Command("git", commandArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(commandArgs, " "), err, data)
	}
	return strings.TrimSpace(string(data))
}

func sortInspectionImports(imports []map[string]string) {
	for i := 1; i < len(imports); i++ {
		for j := i; j > 0 && imports[j]["module"] < imports[j-1]["module"]; j-- {
			imports[j], imports[j-1] = imports[j-1], imports[j]
		}
	}
}

func writeManifestFixture(t *testing.T, dir string, manifest *Manifest) {
	t.Helper()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	writeTestFile(t, filepath.Join(dir, "provenance.sha256"), hex.EncodeToString(sum[:])+"  provenance.json\n")
}
