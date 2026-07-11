// Package register self-registers the explicit all-protocol Wago networking
// bundle for custom binaries built by `wago pkg build`.
package register

import (
	wagonet "github.com/wago-org/net"
	"github.com/wago-org/net/compat"
	wago "github.com/wago-org/wago"
)

func init() {
	wago.RegisterExtension("net", func() wago.Extension {
		return compat.Init(wagonet.Config{})
	})
}
