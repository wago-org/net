// Package register self-registers the Wago networking core extension for custom
// binaries built by `wago pkg build`.
package register

import (
	wagonet "github.com/wago-org/net"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net", func() wago.Extension {
		return wagonet.Init(wagonet.Config{})
	})
}
