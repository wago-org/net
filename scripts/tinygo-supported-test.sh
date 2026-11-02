#!/usr/bin/env bash
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/ci-dependency-env.sh
source "$root/scripts/lib/ci-dependency-env.sh"
ci_select_dependency_workspace "$root"
cd "$root"

out=$(realpath -m "${TINYGO_LOG_DIR:-$root/.wago/tinygo-supported}")
manifest=$(realpath -m "${TINYGO_EXCLUSION_MANIFEST:-$root/scripts/tinygo-excluded-packages.tsv}")
validate_only=${TINYGO_VALIDATE_ONLY:-0}
module=github.com/wago-org/net
engine=$module/internal/backend/gotls
policy=$root/internal/inspectionpolicy/policy.json

fail() {
  echo "tinygo-supported-test: $*" >&2
  exit 1
}

for command in git go tinygo python3 realpath; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
[[ -f $manifest ]] || fail "missing exclusion manifest: $manifest"
[[ -f $policy ]] || fail "missing inspection policy: $policy"
[[ $out != / && $out != "$root" && $out != "$root/scripts" ]] || fail "unsafe output directory: $out"
case "$validate_only" in 0|1) ;; *) fail "TINYGO_VALIDATE_ONLY must be 0 or 1" ;; esac

rm -rf "$out"
mkdir -p "$out/logs"
work=$(mktemp -d "${TMPDIR:-/tmp}/wago-net-tinygo-supported.XXXXXX")
trap 'rm -rf "$work"' EXIT

# go list ./... intentionally skips testdata. Discover every tracked Go package
# directory so the reviewed TLS composition fixtures remain in the matrix.
mapfile -t directories < <(
  git ls-files '*.go' | while IFS= read -r file; do dirname "$file"; done | LC_ALL=C sort -u
)
((${#directories[@]} != 0)) || fail 'no tracked Go package directories discovered'
list_args=()
for directory in "${directories[@]}"; do
  if [[ $directory == . ]]; then
    list_args+=(.)
  else
    list_args+=("./$directory")
  fi
done
if ! go list -json "${list_args[@]}" >"$work/packages.json" 2>"$work/go-list.err"; then
  cat "$work/go-list.err" >&2
  fail 'repository package discovery failed'
fi

if ! python3 - "$work/packages.json" "$manifest" "$policy" "$out" "$module" "$engine" <<'PY'
import json
import os
import sys

source, manifest_path, policy_path, out, module, engine = sys.argv[1:]

def fail(message):
    raise SystemExit(f"tinygo-supported-test: {message}")

text = open(source, encoding="utf-8").read()
decoder = json.JSONDecoder()
index = 0
packages = []
while index < len(text):
    while index < len(text) and text[index].isspace():
        index += 1
    if index == len(text):
        break
    package, index = decoder.raw_decode(text, index)
    packages.append(package)

by_path = {}
for package in packages:
    path = package.get("ImportPath", "")
    if not path.startswith(module):
        fail(f"discovered package outside repository module: {path!r}")
    if path in by_path:
        fail(f"duplicate discovered package: {path}")
    by_path[path] = package
if not by_path:
    fail("repository package discovery is empty")

rows = []
with open(manifest_path, encoding="utf-8") as stream:
    for line_number, raw in enumerate(stream, 1):
        line = raw.rstrip("\n")
        if not line:
            fail(f"blank exclusion row at line {line_number}")
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1]:
            fail(f"exclusion row {line_number} must contain exactly package and reason")
        if "\r" in line or "\n" in fields[1]:
            fail(f"invalid exclusion row {line_number}")
        rows.append((fields[0], fields[1]))
if not rows:
    fail("exclusion manifest is empty")
if rows != sorted(rows):
    fail("exclusion manifest is not sorted")
paths = [path for path, _ in rows]
if len(paths) != len(set(paths)):
    fail("exclusion manifest contains duplicate packages")
for path, reason in rows:
    if path not in by_path:
        fail(f"expected excluded package disappeared: {path}")
    if not reason.strip():
        fail(f"excluded package has no reason: {path}")

# The only exclusion root is the real standard-Go crypto/tls engine. Any
# repository package depending on it belongs to the exact derived closure.
derived = sorted(
    path for path, package in by_path.items()
    if path == engine or engine in package.get("Deps", [])
)
if paths != derived:
    missing = sorted(set(derived) - set(paths))
    extra = sorted(set(paths) - set(derived))
    fail(f"reviewed exclusion set differs from derived TLS closure: unlisted={missing} stale={extra}")

supported = sorted(set(by_path) - set(paths))
if not supported:
    fail("supported TinyGo package set is empty")
if module + "/tls" not in paths:
    fail("public TLS package must be explicitly standard-Go-only")
if module + "/register" not in supported:
    fail("aggregate register package is absent from TinyGo-supported surface")
if module + "/tls/register" in by_path or os.path.isdir(os.path.join(os.path.dirname(os.path.dirname(manifest_path)), "tls", "register")):
    fail("tls/register must not exist")

with open(policy_path, encoding="utf-8") as stream:
    policy = json.load(stream)
bundles = policy.get("bundles", [])
if len(bundles) != 12:
    fail(f"canonical custom-CLI bundle count is {len(bundles)}, want 12")
keys = [bundle.get("key", "") for bundle in bundles]
if "net-tls" in keys:
    fail("net-tls custom-CLI key must not exist")
if keys != sorted(keys) or len(keys) != len(set(keys)):
    fail("inspection bundle keys must be sorted and unique")
for bundle in bundles:
    package_path = bundle.get("package", "")
    package = by_path.get(package_path)
    if package is None:
        fail(f"canonical bundle package was not discovered: {package_path}")
    if package_path in paths or engine in package.get("Deps", []):
        fail(f"canonical TinyGo custom-CLI bundle depends on TLS: {package_path}")

with open(os.path.join(out, "supported-packages.tsv"), "w", encoding="utf-8") as stream:
    for path in supported:
        stream.write(path + "\n")
with open(os.path.join(out, "excluded-packages.tsv"), "w", encoding="utf-8") as stream:
    for path, reason in rows:
        stream.write(f"{path}\t{reason}\n")
with open(os.path.join(out, "counts.env"), "w", encoding="utf-8") as stream:
    stream.write(f"repository_packages={len(by_path)}\n")
    stream.write(f"supported_packages={len(supported)}\n")
    stream.write(f"excluded_packages={len(paths)}\n")
PY
then
  exit 1
fi

repository_packages=$(sed -n 's/^repository_packages=//p' "$out/counts.env")
supported_packages=$(sed -n 's/^supported_packages=//p' "$out/counts.env")
excluded_packages=$(sed -n 's/^excluded_packages=//p' "$out/counts.env")
tinygo_version=$(tinygo version | tr '\n' ' ' | sed 's/[[:space:]]*$//')
mode=test
[[ $validate_only == 0 ]] || mode=validate-only
cat >"$out/detail.txt" <<EOF
mode=$mode
tinygo_version=$tinygo_version
repository_packages=$repository_packages
supported_packages=$supported_packages
excluded_packages=$excluded_packages
exclusion_root=$engine
EOF
rm "$out/counts.env"

printf 'tinygo-supported-test: repository=%s supported=%s excluded=%s mode=%s\n' \
  "$repository_packages" "$supported_packages" "$excluded_packages" "$mode"
if [[ $validate_only == 1 ]]; then
  echo 'tinygo-supported-test: exclusion boundary validated'
  exit 0
fi

failures=0
attempted=0
while IFS= read -r package; do
  [[ -n $package ]] || continue
  attempted=$((attempted + 1))
  relative=${package#"$module"}
  relative=${relative#/}
  [[ -n $relative ]] || relative=_root
  log="$out/logs/$relative/test.log"
  mkdir -p "$(dirname "$log")"
  printf '\n==> tinygo-supported-test [%d/%d] %s\n' "$attempted" "$supported_packages" "$package"
  if tinygo test "$package" >"$log" 2>&1; then
    printf 'tinygo-supported-test: PASS %s\n' "$package"
  else
    cat "$log" >&2
    printf 'tinygo-supported-test: FAIL %s\n' "$package" >&2
    failures=$((failures + 1))
  fi
done <"$out/supported-packages.tsv"

[[ $attempted == "$supported_packages" ]] || fail "attempted $attempted packages, expected $supported_packages"
if ((failures != 0)); then
  fail "$failures of $attempted supported packages failed"
fi
printf '\ntinygo-supported-test: all %d supported packages passed; %d standard-Go-only packages retained explicitly\n' \
  "$attempted" "$excluded_packages"
