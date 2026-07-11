package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wago-org/net/internal/releaseprovenance"
)

func main() {
	mode := flag.String("mode", "verify", "operation: verify or export")
	source := flag.String("source", "", "extracted release-signoff evidence directory")
	bundle := flag.String("bundle", "", "review bundle directory or .tar.gz path")
	out := flag.String("out", "", "destination .tar.gz path for export")
	subject := flag.String("subject", "", "optional exact net commit required by policy")
	flag.Parse()
	opts := releaseprovenance.VerifyOptions{ExpectedSubject: *subject}
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
	default:
		fmt.Fprintf(os.Stderr, "release-review: unsupported mode %q\n", *mode)
		os.Exit(2)
	}
}

func printVerification(action, path string, verified *releaseprovenance.Verification, bundleHash string) {
	manifest := verified.Manifest
	fmt.Printf("release-review: %s %s\n", action, path)
	fmt.Printf("schema=%s\nsubject=%s\nprovenance_sha256=%s\nartifacts=%d\naccepted_exceptions=%d\nlimitations=%d\n",
		manifest.Schema, manifest.Subject.Revision, verified.ProvenanceSHA256,
		len(manifest.Artifacts), len(manifest.Exceptions), len(manifest.Limitations))
	if bundleHash != "" {
		fmt.Printf("bundle_sha256=%s\n", bundleHash)
	}
}
