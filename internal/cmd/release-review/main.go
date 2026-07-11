package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/wago-org/net/internal/releaseprovenance"
)

func main() {
	mode := flag.String("mode", "verify", "operation: verify, export, statement, verify-signed, or verify-production-candidate")
	source := flag.String("source", "", "extracted release-signoff evidence directory")
	bundle := flag.String("bundle", "", "review bundle directory or .tar.gz path")
	out := flag.String("out", "", "destination .tar.gz path for export")
	subject := flag.String("subject", "", "optional exact net commit required by policy")
	bundleSHA256 := flag.String("bundle-sha256", "", "optional exact review bundle SHA-256 required by policy")
	strictDistribution := flag.Bool("strict-distribution", false, "require separately supplied subject and bundle SHA-256")
	statementPath := flag.String("statement", "", "canonical distribution statement path")
	signaturePath := flag.String("signature", "", "raw detached Ed25519 signature path")
	trustPolicyPath := flag.String("trust-policy", "", "explicit canonical distribution trust policy path")
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
		fmt.Printf("trusted_key_id=%s\nstatement_sha256=%s\n", trusted.KeyID, trusted.StatementSHA256)
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
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		if !report.Ready {
			os.Exit(1)
		}
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
