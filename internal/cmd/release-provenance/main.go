package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wago-org/net/internal/releaseprovenance"
)

func main() {
	var cfg releaseprovenance.Config
	flag.StringVar(&cfg.OutputDir, "out", "", "release signoff artifact directory")
	flag.StringVar(&cfg.PluginDir, "plugin", "", "networking plugin repository")
	flag.StringVar(&cfg.WagoDir, "wago", "", "Wago audit repository")
	flag.StringVar(&cfg.LnetoDir, "lneto", "", "lneto audit repository")
	flag.StringVar(&cfg.WASIDir, "wasi", "", "WASI audit repository")
	flag.StringVar(&cfg.CurrentNetDir, "current-net", "", "current networking review repository")
	flag.StringVar(&cfg.CurrentWagoDir, "current-wago", "", "current Wago review repository")
	flag.StringVar(&cfg.WorkersDir, "workers", "", "external workers review repository")
	flag.StringVar(&cfg.CrossGOOS, "cross-goos", "linux", "cross-build target GOOS")
	flag.StringVar(&cfg.CrossGOARCH, "cross-goarch", "arm64", "cross-build target GOARCH")
	flag.Parse()
	if cfg.OutputDir == "" || cfg.PluginDir == "" || cfg.WagoDir == "" || cfg.LnetoDir == "" || cfg.WASIDir == "" ||
		cfg.CurrentNetDir == "" || cfg.CurrentWagoDir == "" || cfg.WorkersDir == "" {
		fmt.Fprintln(os.Stderr, "release-provenance: out, plugin, wago, lneto, wasi, current-net, current-wago, and workers are required")
		os.Exit(2)
	}
	if err := releaseprovenance.Write(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
