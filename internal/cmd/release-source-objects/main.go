package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wago-org/net/internal/releaseprovenance"
)

func main() {
	var out, plugin, subject, wago, lneto, wasi, currentNet, currentWago, workers string
	var allowOutsideArtifactRoot bool
	flag.StringVar(&out, "out", "", "output directory")
	flag.StringVar(&plugin, "plugin", ".", "plugin repository")
	flag.StringVar(&subject, "subject", "HEAD", "exact plugin subject revision")
	flag.StringVar(&wago, "wago", "", "production Wago repository")
	flag.StringVar(&lneto, "lneto", "", "lneto repository")
	flag.StringVar(&wasi, "wasi", "", "WASI repository")
	flag.StringVar(&currentNet, "current-net", "", "current networking review repository")
	flag.StringVar(&currentWago, "current-wago", "", "current Wago review repository")
	flag.StringVar(&workers, "workers", "", "external workers repository")
	flag.BoolVar(&allowOutsideArtifactRoot, "allow-outside-artifact-root", false, "allow output outside the plugin .wago artifact root")
	flag.Parse()
	if out == "" || wago == "" || lneto == "" || wasi == "" || currentNet == "" || currentWago == "" || workers == "" {
		fmt.Fprintln(os.Stderr, "release-source-objects: -out, -wago, -lneto, -wasi, -current-net, -current-wago, and -workers are required")
		os.Exit(2)
	}
	err := releaseprovenance.ExportSourceObjectsWithOptions(out, []releaseprovenance.SourceObjectSet{
		{Name: "net", Directory: plugin, Revisions: []string{subject}},
		{Name: "wago", Directory: wago, Revisions: []string{
			releaseprovenance.ExpectedWagoRevision,
			releaseprovenance.ExpectedWagoParent1,
			releaseprovenance.ExpectedWagoParent2,
		}},
		{Name: "lneto", Directory: lneto, Revisions: []string{releaseprovenance.ExpectedLnetoRevision}},
		{Name: "wasi", Directory: wasi, Revisions: []string{releaseprovenance.ExpectedWASIRevision}},
		{Name: "net-current-review", Directory: currentNet, Revisions: []string{releaseprovenance.ExpectedCurrentNetRevision}},
		{Name: "wago-current-review", Directory: currentWago, Revisions: []string{releaseprovenance.ExpectedCurrentWagoRevision}},
		{Name: "workers-current", Directory: workers, Revisions: []string{releaseprovenance.ExpectedWorkersRevision}},
	}, releaseprovenance.SourceObjectExportOptions{
		RepositoryRoot:           plugin,
		AllowOutsideArtifactRoot: allowOutsideArtifactRoot,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
