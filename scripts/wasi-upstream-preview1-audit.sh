#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wasi_dir=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
wago_dir=$(realpath "${WAGO_DIR:-$root/.audit/wago}")
out=${WASI_UPSTREAM_AUDIT_OUT:-$root/.wago/wasi-upstream-audit-evidence}
require_current=${REQUIRE_CURRENT_WASI:-0}

readonly pinned_wasi=3df6c766ad00e83b314da799dbf9a77b409ad19d
readonly reviewed_upstream=1a7eeb215229e05bcb0f09d5cb3280d231739def
readonly reviewed_parent=ab7d597a8517283b0399e09d967b7f02ded1772f

fail() { echo "wasi-upstream-preview1-audit: $*" >&2; exit 1; }

for command in awk git go grep mktemp sed sha256sum tar; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
[[ -d "$wasi_dir/.git" ]] || fail "missing WASI repository: $wasi_dir"
[[ -d "$wago_dir/.git" ]] || fail "missing Wago repository: $wago_dir"
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

set +e
(
  cd "$tmp/wasi"
  GOWORK=off go test ./... -count=1
) >"$out/test.txt" 2>&1
status=$?
set -e
sed -i "s#${tmp//\#/\\#}#<isolated-wasi-audit>#g" "$out/test.txt"
if ((status == 0)); then
  fail "reviewed upstream suite passed; remove the exception and review a WASI pin update"
fi
if ! grep -Eqi 'SIGSEGV|segmentation violation' "$out/test.txt" ||
   ! grep -Eqi 'p1|preview.?1' "$out/test.txt"; then
  cat "$out/test.txt" >&2
  fail "reviewed upstream failed outside the documented native preview-1 exception"
fi

cat >"$out/status.txt" <<EOF
status=accepted-preview1-native-sigsegv
pinned=$pinned_wasi
reviewed=$reviewed_upstream
implementation_inventory_sha256=$reviewed_inventory
changed_files=.github/workflows/ci.yml,README.md
EOF
cat "$out/status.txt"
echo 'decision=retain-pinned-wasi; reviewed upstream contains documentation and CI only, not a preview-1 crash fix'
echo 'wasi-upstream-preview1-audit: PASS'
