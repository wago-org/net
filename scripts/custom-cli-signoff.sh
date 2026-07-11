#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
net_dir=$(realpath "${NET_DIR:-$root}")
wago_dir=$(realpath "${WAGO_DIR:-$root/.wago/wago-production-97e6f91}")
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

write_cli() {
  local key=$1 package=$2
  mkdir -p "$out/cmd/$key"
  cat >"$out/cmd/$key/main.go" <<EOF
package main

import (
	_ "$package"
	"github.com/wago-org/wago/cli/wagocli"
)

func main() { wagocli.Main("$key-release-signoff") }
EOF
}
write_cli net github.com/wago-org/net/register
keys=(net)
if [[ -d "$net_dir/tcp/register" && -d "$net_dir/udp/register" && -d "$net_dir/dns/register" ]]; then
  write_cli net-tcp github.com/wago-org/net/tcp/register
  write_cli net-udp github.com/wago-org/net/udp/register
  write_cli net-dns github.com/wago-org/net/dns/register
  keys+=(net-tcp net-udp net-dns)
fi

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

type expectation struct {
	capabilities []string
	imports      map[string]int
}

var expectations = map[string]expectation{
	"net": {
		capabilities: []string{"net.dns", "net.info", "net.tcp", "net.udp"},
		imports: map[string]int{"wago_net": 1, "wago_net_dns": 6, "wago_net_tcp": 11, "wago_net_udp": 6},
	},
	"net-tcp": {
		capabilities: []string{"net.info", "net.tcp"},
		imports: map[string]int{"wago_net": 1, "wago_net_tcp": 11},
	},
	"net-udp": {
		capabilities: []string{"net.info", "net.udp"},
		imports: map[string]int{"wago_net": 1, "wago_net_udp": 6},
	},
	"net-dns": {
		capabilities: []string{"net.dns", "net.info"},
		imports: map[string]int{"wago_net": 1, "wago_net_dns": 6},
	},
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: validate <plugin> <inspection.json>")
	}
	want, ok := expectations[os.Args[1]]
	if !ok {
		panic("unknown plugin " + os.Args[1])
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	var got inspection
	if err := json.Unmarshal(data, &got); err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(got.Capabilities, want.capabilities) {
		panic(fmt.Sprintf("capabilities = %v, want %v", got.Capabilities, want.capabilities))
	}
	counts := map[string]int{}
	for _, imp := range got.Imports {
		counts[imp.Module]++
	}
	if !reflect.DeepEqual(counts, want.imports) {
		panic(fmt.Sprintf("imports = %d %v, want %v", len(got.Imports), counts, want.imports))
	}
}
EOF

(
  cd "$out"
  GOWORK=off go mod tidy
  for key in "${keys[@]}"; do
    GOWORK=off go build -trimpath -o "wago-$key-go" "./cmd/$key"
    GOWORK=off tinygo build -scheduler=tasks -o "wago-$key-tinygo" "./cmd/$key"
    "./wago-$key-go" plugin inspect "$key" --json >"inspection-$key-go.json"
    "./wago-$key-tinygo" plugin inspect "$key" --json >"inspection-$key-tinygo.json"
    cmp "inspection-$key-go.json" "inspection-$key-tinygo.json"
    GOWORK=off go run ./cmd/validate "$key" "inspection-$key-go.json"
  done
  cp inspection-net-go.json inspection-go.json
  cp inspection-net-tinygo.json inspection-tinygo.json
)

if ((${#keys[@]} == 4)); then
  echo "custom-cli: standard Go and TinyGo inspection match for net, net-tcp, net-udp, and net-dns at $out"
else
  echo "custom-cli: standard Go and TinyGo aggregate inspection match for historical source without granular bundles at $out"
fi
