package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wago-org/net/internal/releaseprovenance"
)

func main() {
	var out, plugin, subject, wago, lneto, wasi string
	flag.StringVar(&out, "out", "", "output directory")
	flag.StringVar(&plugin, "plugin", ".", "plugin repository")
	flag.StringVar(&subject, "subject", "HEAD", "exact plugin subject revision")
	flag.StringVar(&wago, "wago", "", "Wago repository")
	flag.StringVar(&lneto, "lneto", "", "lneto repository")
	flag.StringVar(&wasi, "wasi", "", "WASI repository")
	flag.Parse()
	if out == "" || wago == "" || lneto == "" || wasi == "" {
		fmt.Fprintln(os.Stderr, "release-source-objects: -out, -wago, -lneto, and -wasi are required")
		os.Exit(2)
	}
	err := releaseprovenance.ExportSourceObjects(out, []releaseprovenance.SourceObjectSet{
		{Name: "net", Directory: plugin, Revisions: []string{subject}},
		{Name: "wago", Directory: wago, Revisions: []string{
			releaseprovenance.ExpectedWagoRevision,
			releaseprovenance.ExpectedWagoParent1,
			releaseprovenance.ExpectedWagoParent2,
		}},
		{Name: "lneto", Directory: lneto, Revisions: []string{releaseprovenance.ExpectedLnetoRevision}},
		{Name: "wasi", Directory: wasi, Revisions: []string{releaseprovenance.ExpectedWASIRevision}},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
