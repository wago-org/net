package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/wago-org/net/internal/releaseprovenance"
)

func main() {
	mode := flag.String("mode", "verify", "operation: verify, export, statement, verify-signed, verify-trusted-receipt, verify-production-candidate, verify-production-candidate-chain, verify-readiness-receipt, or verify-release-decision-chain")
	source := flag.String("source", "", "extracted release-signoff evidence directory")
	bundle := flag.String("bundle", "", "review bundle directory or .tar.gz path")
	out := flag.String("out", "", "mode-specific destination path")
	subject := flag.String("subject", "", "optional exact net commit required by policy")
	bundleSHA256 := flag.String("bundle-sha256", "", "optional exact review bundle SHA-256 required by policy")
	strictDistribution := flag.Bool("strict-distribution", false, "require separately supplied subject and bundle SHA-256")
	statementPath := flag.String("statement", "", "canonical distribution statement path")
	signaturePath := flag.String("signature", "", "raw detached Ed25519 signature path")
	trustPolicyPath := flag.String("trust-policy", "", "explicit canonical distribution trust policy path")
	receiptPath := flag.String("receipt", "", "canonical retained receipt path")
	trustedReceiptPath := flag.String("trusted-receipt", "", "canonical trusted-distribution receipt path")
	statementSHA256 := flag.String("statement-sha256", "", "exact statement SHA-256 required by receipt policy")
	signatureSHA256 := flag.String("signature-sha256", "", "exact signature SHA-256 required by receipt policy")
	trustPolicySHA256 := flag.String("trust-policy-sha256", "", "exact trust-policy SHA-256 required by receipt policy")
	trustedReceiptSHA256 := flag.String("trusted-receipt-sha256", "", "exact trusted-distribution receipt SHA-256 required by chain policy")
	flag.Parse()
	opts := releaseprovenance.VerifyOptions{
		ExpectedSubject: *subject, ExpectedBundleSHA256: *bundleSHA256, StrictDistribution: *strictDistribution,
	}
	switch *mode {
	case "verify":
		if *bundle == "" {
			fmt.Fprintln(os.Stderr, "release-review: -bundle is required for verify")
			os.Exit(2)
		}
		verified, err := releaseprovenance.Verify(*bundle, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printVerification("verified", *bundle, verified, "")
	case "export":
		if *source == "" || *out == "" {
			fmt.Fprintln(os.Stderr, "release-review: -source and -out are required for export")
			os.Exit(2)
		}
		verified, bundleHash, err := releaseprovenance.ExportBundle(*source, *out, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printVerification("exported", *out, verified, bundleHash)
	case "statement":
		if *bundle == "" || *out == "" {
			fmt.Fprintln(os.Stderr, "release-review: -bundle and -out are required for statement")
			os.Exit(2)
		}
		statement, statementHash, err := releaseprovenance.WriteDistributionStatement(*bundle, *out, opts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("release-review: wrote distribution statement %s\n", *out)
		fmt.Printf("schema=%s\nsubject=%s\nprovenance_sha256=%s\nbundle_sha256=%s\nstatement_sha256=%s\n",
			statement.Schema, statement.Subject, statement.ProvenanceSHA256, statement.ReviewBundleSHA256, statementHash)
	case "verify-signed":
		if *bundle == "" || *statementPath == "" || *signaturePath == "" || *trustPolicyPath == "" {
			fmt.Fprintln(os.Stderr, "release-review: -bundle, -statement, -signature, and -trust-policy are required for verify-signed")
			os.Exit(2)
		}
		trusted, err := releaseprovenance.VerifySignedDistribution(*bundle, *statementPath, *signaturePath, *trustPolicyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printVerification("verified signed distribution", *bundle, trusted.Verification, "")
		fmt.Printf("trusted_key_id=%s\nstatement_sha256=%s\nsignature_sha256=%s\ntrust_policy_sha256=%s\n",
			trusted.KeyID, trusted.StatementSHA256, trusted.SignatureSHA256, trusted.TrustPolicySHA256)
		if *out != "" {
			receiptHash, err := releaseprovenance.WriteTrustedDistributionReceipt(*out, trusted)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("release-review: wrote trusted distribution receipt %s\ntrusted_distribution_sha256=%s\n", *out, receiptHash)
		}
	case "verify-trusted-receipt":
		if *receiptPath == "" || *subject == "" || *statementSHA256 == "" || *signatureSHA256 == "" || *trustPolicySHA256 == "" {
			fmt.Fprintln(os.Stderr, "release-review: -receipt, -subject, -statement-sha256, -signature-sha256, and -trust-policy-sha256 are required for verify-trusted-receipt")
			os.Exit(2)
		}
		receipt, receiptHash, err := releaseprovenance.VerifyTrustedDistributionReceipt(*receiptPath, releaseprovenance.TrustedDistributionReceiptVerifyOptions{
			ExpectedSubject: *subject, ExpectedStatementSHA256: *statementSHA256,
			ExpectedSignatureSHA256: *signatureSHA256, ExpectedTrustPolicySHA256: *trustPolicySHA256,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("release-review: verified trusted distribution receipt %s\n", *receiptPath)
		fmt.Printf("trusted_distribution_sha256=%s\nsubject=%s\nstatement_sha256=%s\nsignature_sha256=%s\ntrust_policy_sha256=%s\nprovenance_sha256=%s\nbundle_sha256=%s\n",
			receiptHash, receipt.Subject, receipt.StatementSHA256, receipt.SignatureSHA256,
			receipt.TrustPolicySHA256, receipt.ProvenanceSHA256, receipt.ReviewBundleSHA256)
	case "verify-production-candidate":
		if *bundle == "" || *statementPath == "" || *signaturePath == "" || *trustPolicyPath == "" {
			fmt.Fprintln(os.Stderr, "release-review: -bundle, -statement, -signature, and -trust-policy are required for verify-production-candidate")
			os.Exit(2)
		}
		report, err := releaseprovenance.VerifyProductionReleaseCandidate(*bundle, *statementPath, *signaturePath, *trustPolicyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if *out == "" {
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(string(data))
		} else {
			receiptHash, err := releaseprovenance.WriteProductionReadinessReceipt(*out, report)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("release-review: wrote production readiness receipt %s\nreadiness_sha256=%s\n", *out, receiptHash)
		}
		if !report.Ready {
			os.Exit(1)
		}
	case "verify-production-candidate-chain":
		if *bundle == "" || *statementPath == "" || *signaturePath == "" || *trustPolicyPath == "" || *trustedReceiptPath == "" {
			fmt.Fprintln(os.Stderr, "release-review: -bundle, -statement, -signature, -trust-policy, and -trusted-receipt are required for verify-production-candidate-chain")
			os.Exit(2)
		}
		report, err := releaseprovenance.VerifyProductionReleaseCandidateWithTrustedReceipt(
			*bundle, *statementPath, *signaturePath, *trustPolicyPath, *trustedReceiptPath,
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if *out == "" {
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(string(data))
		} else {
			receiptHash, err := releaseprovenance.WriteProductionReadinessReceiptV2(*out, report)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("release-review: wrote linked production readiness receipt %s\nreadiness_sha256=%s\n", *out, receiptHash)
		}
		if !report.Ready {
			os.Exit(1)
		}
	case "verify-readiness-receipt":
		if *receiptPath == "" || *subject == "" || *statementSHA256 == "" || *trustPolicySHA256 == "" {
			fmt.Fprintln(os.Stderr, "release-review: -receipt, -subject, -statement-sha256, and -trust-policy-sha256 are required for verify-readiness-receipt")
			os.Exit(2)
		}
		report, receiptHash, err := releaseprovenance.VerifyProductionReadinessReceipt(*receiptPath, releaseprovenance.ProductionReadinessVerifyOptions{
			ExpectedSubject: *subject, ExpectedStatementSHA256: *statementSHA256, ExpectedTrustPolicySHA256: *trustPolicySHA256,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("release-review: verified production readiness receipt %s\n", *receiptPath)
		fmt.Printf("readiness_sha256=%s\nready=%t\nsubject=%s\nstatement_sha256=%s\ntrust_policy_sha256=%s\nblockers=%d\n",
			receiptHash, report.Ready, report.Subject, report.StatementSHA256, report.TrustPolicySHA256, len(report.Blockers))
	case "verify-release-decision-chain":
		if *trustedReceiptPath == "" || *receiptPath == "" || *subject == "" || *statementSHA256 == "" ||
			*signatureSHA256 == "" || *trustPolicySHA256 == "" || *trustedReceiptSHA256 == "" {
			fmt.Fprintln(os.Stderr, "release-review: -trusted-receipt, -receipt, -subject, -statement-sha256, -signature-sha256, -trust-policy-sha256, and -trusted-receipt-sha256 are required for verify-release-decision-chain")
			os.Exit(2)
		}
		chain, err := releaseprovenance.VerifyReleaseDecisionChain(*trustedReceiptPath, *receiptPath, releaseprovenance.ReleaseDecisionChainVerifyOptions{
			ExpectedSubject: *subject, ExpectedStatementSHA256: *statementSHA256,
			ExpectedSignatureSHA256: *signatureSHA256, ExpectedTrustPolicySHA256: *trustPolicySHA256,
			ExpectedTrustedDistributionReceiptSHA256: *trustedReceiptSHA256,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("release-review: verified release decision chain %s -> %s\n", *trustedReceiptPath, *receiptPath)
		fmt.Printf("trusted_distribution_sha256=%s\nreadiness_sha256=%s\nready=%t\nsubject=%s\nstatement_sha256=%s\nsignature_sha256=%s\ntrust_policy_sha256=%s\nblockers=%d\n",
			chain.TrustedDistributionSHA256, chain.ProductionReadinessSHA256, chain.ProductionReadiness.Ready,
			chain.ProductionReadiness.Subject, chain.ProductionReadiness.StatementSHA256,
			chain.ProductionReadiness.SignatureSHA256, chain.ProductionReadiness.TrustPolicySHA256,
			len(chain.ProductionReadiness.Blockers))
	default:
		fmt.Fprintf(os.Stderr, "release-review: unsupported mode %q\n", *mode)
		os.Exit(2)
	}
}

func printVerification(action, path string, verified *releaseprovenance.Verification, bundleHash string) {
	manifest := verified.Manifest
	fmt.Printf("release-review: %s %s\n", action, path)
	fmt.Printf("schema=%s\nsubject=%s\nprovenance_sha256=%s\ncurrent_plugin=%s\nproduction_wago_merge=%s\npublisher_authentication=%s\nhosted_release_automation=%s\nartifacts=%d\naccepted_exceptions=%d\nlimitations=%d\n",
		manifest.Schema, manifest.Subject.Revision, verified.ProvenanceSHA256,
		manifest.Publication.CurrentPlugin, manifest.Publication.ProductionWagoMerge,
		manifest.Publication.PublisherAuthentication, manifest.Publication.HostedReleaseAutomation,
		len(manifest.Artifacts), len(manifest.Exceptions), len(manifest.Limitations))
	if verified.BundleSHA256 != "" {
		fmt.Printf("verified_bundle_sha256=%s\n", verified.BundleSHA256)
	}
	if bundleHash != "" {
		fmt.Printf("bundle_sha256=%s\n", bundleHash)
	}
}
