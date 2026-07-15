#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/ci-dependency-env.sh
source "$root/scripts/lib/ci-dependency-env.sh"
ci_select_dependency_workspace "$root"
cd "$root"

mapfile -t neutral_packages < <(
  go list -test -json ./... | python3 -c '
import json
import sys

source = sys.stdin.read()
decoder = json.JSONDecoder()
offset = 0
packages = []
while offset < len(source):
    while offset < len(source) and source[offset].isspace():
        offset += 1
    if offset == len(source):
        break
    package, offset = decoder.raw_decode(source, offset)
    packages.append(package)

def depends_on_wago(package):
    return any(
        dep == "github.com/wago-org/wago" or dep.startswith("github.com/wago-org/wago/")
        for dep in package.get("Deps", [])
    )

wago_test_packages = {
    package["ForTest"]
    for package in packages
    if package.get("ForTest") and depends_on_wago(package)
}
for package in packages:
    import_path = package["ImportPath"]
    if package.get("ForTest") or import_path.endswith(".test"):
        continue
    if not import_path.startswith("github.com/wago-org/net"):
        continue
    if import_path == "github.com/wago-org/net/internal/dependencytest":
        # These meta-tests spawn `go list` for Wago-dependent fixture graphs.
        continue
    if not depends_on_wago(package) and import_path not in wago_test_packages:
        print(import_path)
'
)
if ((${#neutral_packages[@]} == 0)); then
  echo 'ci-386: no backend-neutral packages found' >&2
  exit 1
fi

printf 'ci-386: testing %d packages whose dependency graph excludes Wago\n' "${#neutral_packages[@]}"
GOOS=linux GOARCH=386 CGO_ENABLED=0 go test "${neutral_packages[@]}"

log=$(mktemp)
trap 'rm -f "$log"' EXIT
if GOOS=linux GOARCH=386 CGO_ENABLED=0 go test ./... >"$log" 2>&1; then
  cat "$log"
  echo 'ci-386: complete repository passed; the recorded Wago blocker is resolved'
  exit 0
fi
cat "$log"

readonly blocker_path='.audit/wago/src/core/compiler/frontend/frontend.go:'
readonly blocker_message='undefined: runtime.HostCtrlFrameBytes'
if ! grep -Fq "$blocker_path" "$log" || ! grep -Fq "$blocker_message" "$log"; then
  echo 'ci-386: full repository failed for a reason other than the recorded Wago blocker' >&2
  exit 1
fi
if grep -E -- '--- FAIL:|panic:' "$log" >/dev/null; then
  echo 'ci-386: tests failed in addition to the recorded Wago compile blocker' >&2
  exit 1
fi
unexpected_diagnostics=$(grep -E '\.go:[0-9]+:[0-9]+:' "$log" | grep -Fv "$blocker_message" || true)
if [[ -n "$unexpected_diagnostics" ]]; then
  printf 'ci-386: unexpected compiler diagnostics:\n%s\n' "$unexpected_diagnostics" >&2
  exit 1
fi

echo 'ci-386: full build remains blocked only by pinned Wago runtime.HostCtrlFrameBytes support' >&2
echo 'ci-386: backend-neutral 386 package tests passed; keep the full attempt visible until Wago supports 386' >&2
