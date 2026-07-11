#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
net_dir=$(realpath "${NET_DIR:-$root}")
wago_dir=$(realpath "${WAGO_DIR:-$root/.audit/wago}")
lneto_dir=$(realpath "${LNETO_DIR:-$root/.audit/lneto}")
workers_dir=$(realpath "${WORKERS_DIR:-$root/.wago/workers-plugin}")
out=$(realpath -m "${SIGNOFF_CUSTOM_DIR:-$root/.wago/release-signoff/custom-cli}")

for dir in "$wago_dir" "$lneto_dir" "$workers_dir"; do
  if [[ ! -d "$dir/.git" && ! -f "$dir/.git" ]]; then
    echo "custom-cli: missing repository $dir" >&2
    exit 1
  fi
done
command -v go >/dev/null
command -v tinygo >/dev/null

rm -rf "$out"
mkdir -p "$out/cmd/validate"
cat >"$out/go.mod" <<EOF
module github.com/wago-org/net-signoff

go 1.24

require (
	github.com/wago-org/net v0.0.0
	github.com/wago-org/wago v0.1.0
)

replace github.com/wago-org/net => $net_dir
replace github.com/wago-org/wago => $wago_dir
replace github.com/soypat/lneto => $lneto_dir
replace github.com/wago-org/workers => $workers_dir
EOF
cat >"$out/main.go" <<'EOF'
package main

import (
	_ "github.com/wago-org/net/register"
	"github.com/wago-org/wago/cli/wagocli"
)

func main() { wagocli.Main("net-release-signoff") }
EOF
cat >"$out/cmd/validate/main.go" <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

type inspection struct {
	Capabilities []string `json:"capabilities"`
	Imports      []struct {
		Module string `json:"module"`
	} `json:"imports"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: validate <inspection.json>")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var got inspection
	if err := json.Unmarshal(data, &got); err != nil {
		panic(err)
	}
	wantCapabilities := []string{"net.dns", "net.info", "net.tcp", "net.udp"}
	if !reflect.DeepEqual(got.Capabilities, wantCapabilities) {
		panic(fmt.Sprintf("capabilities = %v, want %v", got.Capabilities, wantCapabilities))
	}
	counts := map[string]int{}
	for _, imp := range got.Imports {
		counts[imp.Module]++
	}
	wantCounts := map[string]int{"wago_net": 1, "wago_net_dns": 6, "wago_net_tcp": 11, "wago_net_udp": 6}
	if len(got.Imports) != 24 || !reflect.DeepEqual(counts, wantCounts) {
		panic(fmt.Sprintf("imports = %d %v, want 24 %v", len(got.Imports), counts, wantCounts))
	}
}
EOF

(
  cd "$out"
  GOWORK=off go mod tidy
  GOWORK=off go build -trimpath -o wago-go .
  GOWORK=off tinygo build -scheduler=tasks -o wago-tinygo .
  ./wago-go plugin inspect net --json >inspection-go.json
  ./wago-tinygo plugin inspect net --json >inspection-tinygo.json
  cmp inspection-go.json inspection-tinygo.json
  GOWORK=off go run ./cmd/validate inspection-go.json
)

echo "custom-cli: standard Go and TinyGo inspection match at $out/inspection-go.json"
