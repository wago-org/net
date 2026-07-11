#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wasi_dir=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
wago_dir=$(realpath "${WAGO_DIR:-$root/.wago/wago-production-97e6f91}")
out=${WASI_UPSTREAM_AUDIT_OUT:-$root/.wago/wasi-upstream-audit-evidence}
require_current=${REQUIRE_CURRENT_WASI:-0}

# shellcheck source=scripts/lib/wasi-preview1-exception.sh
source "$root/scripts/lib/wasi-preview1-exception.sh"

readonly pinned_wasi=3df6c766ad00e83b314da799dbf9a77b409ad19d
readonly reviewed_upstream=1a7eeb215229e05bcb0f09d5cb3280d231739def
readonly reviewed_parent=ab7d597a8517283b0399e09d967b7f02ded1772f

fail() { echo "wasi-upstream-preview1-audit: $*" >&2; exit 1; }

for command in awk git go grep mktemp sed sha256sum tar; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
git -C "$wasi_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "missing WASI repository: $wasi_dir"
git -C "$wago_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "missing Wago repository: $wago_dir"
for revision in "$pinned_wasi" "$reviewed_parent" "$reviewed_upstream"; do
  git -C "$wasi_dir" cat-file -e "$revision^{commit}" 2>/dev/null || fail "missing commit $revision; fetch WASI refs first"
done
git -C "$wasi_dir" merge-base --is-ancestor "$pinned_wasi" "$reviewed_upstream" ||
  fail "reviewed upstream is not a descendant of the pinned WASI revision"

mapfile -t changed < <(git -C "$wasi_dir" diff --name-only "$pinned_wasi..$reviewed_upstream")
expected=(.github/workflows/ci.yml README.md)
[[ ${#changed[@]} -eq ${#expected[@]} ]] || fail "reviewed range changed unexpected files: ${changed[*]}"
for i in "${!expected[@]}"; do
  [[ "${changed[$i]}" == "${expected[$i]}" ]] ||
    fail "reviewed range changed ${changed[$i]}, expected ${expected[$i]}"
done

implementation_inventory() {
  git -C "$wasi_dir" ls-tree -r "$1" |
    grep -v -E $'\t(README.md|.github/workflows/ci.yml)$' |
    sha256sum | awk '{print $1}'
}
pinned_inventory=$(implementation_inventory "$pinned_wasi")
reviewed_inventory=$(implementation_inventory "$reviewed_upstream")
[[ "$pinned_inventory" == "$reviewed_inventory" ]] ||
  fail "implementation tree changed despite the docs/CI-only review classification"

current=$(git -C "$wasi_dir" rev-parse --verify refs/remotes/origin/main 2>/dev/null || true)
printf 'pinned WASI: %s\n' "$pinned_wasi"
printf 'reviewed upstream: %s\n' "$reviewed_upstream"
printf 'current origin/main: %s\n' "${current:-absent}"
printf 'implementation inventory SHA-256: %s\n' "$reviewed_inventory"
if [[ "$current" != "$reviewed_upstream" ]]; then
  echo 'origin/main moved after the reviewed snapshot; fetch and perform a new preview-1 audit'
  [[ "$require_current" == 0 ]] || fail "reviewed upstream snapshot is not current"
fi

rm -rf "$out"
mkdir -p "$out"
tmp=$(mktemp -d "$out/run.XXXXXX")
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/wasi"
git -C "$wasi_dir" archive "$reviewed_upstream" | tar -x -C "$tmp/wasi"
ln -s "$wago_dir" "$tmp/wago"

wasi_preview1_run_exception_matrix "$tmp/wasi" "$out/matrix" ||
  fail "reviewed upstream did not match the exact preview-1 pass/fault matrix"
for evidence in "$out/matrix/"*.txt; do
  sed -i "s#${tmp//\#/\\#}#<isolated-wasi-audit>#g" "$evidence"
done
cp "$out/matrix/fault-blake3sum.txt" "$out/test.txt"

cat >"$out/status.txt" <<EOF
status=accepted-exact-preview1-native-sigsegv-matrix
pinned=$pinned_wasi
reviewed=$reviewed_upstream
implementation_inventory_sha256=$reviewed_inventory
changed_files=.github/workflows/ci.yml,README.md
passing_cases=$(IFS=,; echo "${wasi_preview1_passing_cases[*]}")
fault_cases=$(IFS=,; echo "${wasi_preview1_fault_cases[*]}")
package=$wasi_preview1_package
EOF
cat "$out/status.txt"
echo 'decision=retain-pinned-wasi; reviewed upstream contains documentation and CI only, not a preview-1 crash fix'
echo 'wasi-upstream-preview1-audit: PASS'
