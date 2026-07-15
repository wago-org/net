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
command -v python3 >/dev/null

policy="$net_dir/internal/inspectionpolicy/policy.json"
[[ -f $policy ]] || {
  echo "custom-cli: missing inspection policy $policy" >&2
  exit 1
}

rm -rf "$out"
mkdir -p "$out/cmd/validate"
cp "$policy" "$out/inspection-policy.json"
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
python3 - "$policy" "$out/bundles.tsv" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    policy = json.load(stream)
bundles = policy.get("bundles", [])
if not bundles:
    raise SystemExit("custom-cli: inspection policy has no bundles")
rows = []
for bundle in bundles:
    key = bundle.get("key", "")
    package = bundle.get("package", "")
    if not key or not package or "\t" in key + package or "\n" in key + package:
        raise SystemExit("custom-cli: invalid inspection bundle")
    rows.append((key, package))
if rows != sorted(rows):
    raise SystemExit("custom-cli: inspection bundles are not sorted by key")
with open(destination, "w", encoding="utf-8") as stream:
    for key, package in rows:
        stream.write(f"{key}\t{package}\n")
PY

keys=()
while IFS=$'\t' read -r key package; do
  write_cli "$key" "$package"
  keys+=("$key")
done <"$out/bundles.tsv"

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

type policy struct {
	Bundles []expectation `json:"bundles"`
}

type expectation struct {
	Key          string         `json:"key"`
	Capabilities []string       `json:"capabilities"`
	Imports      map[string]int `json:"imports"`
}

func main() {
	if len(os.Args) != 4 {
		panic("usage: validate <policy.json> <plugin> <inspection.json>")
	}
	policyData, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var configured policy
	if err := json.Unmarshal(policyData, &configured); err != nil {
		panic(err)
	}
	var want *expectation
	for index := range configured.Bundles {
		if configured.Bundles[index].Key == os.Args[2] {
			want = &configured.Bundles[index]
			break
		}
	}
	if want == nil {
		panic("unknown plugin " + os.Args[2])
	}
	data, err := os.ReadFile(os.Args[3])
	if err != nil {
		panic(err)
	}
	var got inspection
	if err := json.Unmarshal(data, &got); err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(got.Capabilities, want.Capabilities) {
		panic(fmt.Sprintf("capabilities = %v, want %v", got.Capabilities, want.Capabilities))
	}
	counts := map[string]int{}
	for _, imp := range got.Imports {
		counts[imp.Module]++
	}
	if !reflect.DeepEqual(counts, want.Imports) {
		panic(fmt.Sprintf("imports = %d %v, want %v", len(got.Imports), counts, want.Imports))
	}
}
EOF

inspect_package() {
  local binary=$1 key=$2 output=$3
  if "$binary" pkg inspect --help >/dev/null 2>&1; then
    "$binary" pkg inspect "$key" --json >"$output"
  else
    "$binary" plugin inspect "$key" --json >"$output"
  fi
}

(
  cd "$out"
  GOWORK=off go mod tidy
  for key in "${keys[@]}"; do
    GOWORK=off go build -trimpath -o "wago-$key-go" "./cmd/$key"
    GOWORK=off tinygo build -scheduler=tasks -o "wago-$key-tinygo" "./cmd/$key"
    inspect_package "./wago-$key-go" "$key" "inspection-$key-go.json"
    inspect_package "./wago-$key-tinygo" "$key" "inspection-$key-tinygo.json"
    cmp "inspection-$key-go.json" "inspection-$key-tinygo.json"
    GOWORK=off go run ./cmd/validate inspection-policy.json "$key" "inspection-$key-go.json"
  done
  cp inspection-net-go.json inspection-go.json
  cp inspection-net-tinygo.json inspection-tinygo.json
)

echo "custom-cli: standard Go and TinyGo inspection match for all ${#keys[@]} canonical bundles at $out"
