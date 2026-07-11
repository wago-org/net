module github.com/wago-org/net

go 1.24

require (
	github.com/soypat/lneto v0.0.0-20260710133615-ab1a0c735a8b
	github.com/wago-org/wago v0.1.0
)

// Wago has not published v0.1.0 yet. Keep the plugin checkout beside a Wago
// checkout for development; dependency-module replace directives are ignored by
// `wago pkg build`, whose generated build module supplies the engine source.
replace github.com/wago-org/wago => ../wago
