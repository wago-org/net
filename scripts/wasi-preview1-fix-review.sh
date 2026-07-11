#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_repo=$(realpath "${WAGO_WASI_FIX_DIR:-$root/.wago/wago-wasi-preview1-regabi-fix-97e6f91}")
wasi_repo=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
out=${WASI_FIX_REVIEW_OUT:-$root/.wago/wasi-preview1-fix-review}

readonly fix_revision=5c7f76dba0aa82ca94a1dd644318ed062b03f7cc
readonly fix_tree=442d6a7506260565bccb01e32e016f6dccc25d6c
readonly production_merge=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly production_tree=adbba31c51996f1c1d6d3c2069de8ddf0afd94ee
readonly production_parent1=54499ba5135f69a062e23a7255f4a408d6cecf8c
readonly production_parent2=ffd5ef4b122cbd019897eeea3503789ab5860e4a
readonly reviewed_wasi=1a7eeb215229e05bcb0f09d5cb3280d231739def
readonly reviewed_wasi_tree=9108df32daccfe5a8458e6623d996bcb51f38756
readonly reviewed_wasi_parent=ab7d597a8517283b0399e09d967b7f02ded1772f
readonly trigger_sha256=3d93d0329b190e98c4956e0abe05039954f8bf61a22f833bf5a40af5798f668d

fail() { echo "wasi-preview1-fix-review: $*" >&2; exit 1; }

for command in awk git go grep mktemp realpath sed sha256sum tar; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
for repo in "$wago_repo" "$wasi_repo"; do
  git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "missing Git repository: $repo"
done

verify_commit() {
  local repo=$1 revision=$2 tree=$3
  git -C "$repo" cat-file -e "$revision^{commit}" 2>/dev/null || fail "missing commit $revision in $repo"
  [[ $(git -C "$repo" rev-parse "$revision^{tree}") == "$tree" ]] || fail "tree mismatch for $revision"
}
verify_commit "$wago_repo" "$fix_revision" "$fix_tree"
verify_commit "$wago_repo" "$production_merge" "$production_tree"
verify_commit "$wasi_repo" "$reviewed_wasi" "$reviewed_wasi_tree"

[[ $(git -C "$wago_repo" rev-parse HEAD) == "$fix_revision" ]] || fail "Wago fix review worktree is not at $fix_revision"
[[ -z $(git -C "$wago_repo" status --porcelain) ]] || fail "Wago fix review worktree is dirty"
mapfile -t fix_parents < <(git -C "$wago_repo" show -s --format=%P "$fix_revision")
[[ ${#fix_parents[@]} -eq 1 && ${fix_parents[0]} == "$production_merge" ]] || fail "Wago fix review parent mismatch"
read -r merge_parent1 merge_parent2 extra <<<"$(git -C "$wago_repo" show -s --format=%P "$production_merge")"
[[ -z ${extra:-} && "$merge_parent1" == "$production_parent1" && "$merge_parent2" == "$production_parent2" ]] ||
  fail "production Wago ordered parents changed"
[[ $(git -C "$wasi_repo" show -s --format=%P "$reviewed_wasi") == "$reviewed_wasi_parent" ]] ||
  fail "reviewed WASI parent mismatch"

wasi_status_before=$(git -C "$wasi_repo" status --porcelain=v1 --untracked-files=all)
rm -rf "$out"
mkdir -p "$out"
tmp=$(mktemp -d "$out/run.XXXXXX")
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/wago" "$tmp/wasi"
git -C "$wago_repo" archive "$fix_revision" | tar -x -C "$tmp/wago"
git -C "$wasi_repo" archive "$reviewed_wasi" | tar -x -C "$tmp/wasi"

[[ $(sha256sum "$tmp/wago/src/wago/testdata/wasi-preview1-sync-indirect.wasm" | awk '{print $1}') == "$trigger_sha256" ]] ||
  fail "minimized preview-1 trigger digest mismatch"
cat >"$tmp/wago/src/wago/trap_code_wasi_fix_review_test.go" <<'EOF_HELPER'
package wago

import "errors"

func trapCode(err error) TrapCode {
	var trap *TrapError
	if errors.As(err, &trap) {
		return trap.Code
	}
	return TrapNone
}
EOF_HELPER

(
  cd "$tmp/wago"
  GOWORK=off go test ./src/wago -run '^TestSyncHostLinkedCallIndirectUsesWrapperDescriptors$' -count=1 -v
) >"$out/wago-regression.txt" 2>&1
(
  cd "$tmp/wasi"
  GOWORK=off go test ./... -count=1 -v
) >"$out/wasi-test.txt" 2>&1
sed -i "s#${tmp//\#/\\#}#<isolated-wasi-fix-review>#g" "$out/wago-regression.txt" "$out/wasi-test.txt"
grep -Fq -- '--- PASS: TestSyncHostLinkedCallIndirectUsesWrapperDescriptors' "$out/wago-regression.txt" ||
  fail "focused Wago regression did not pass"
grep -Fq -- '--- PASS: TestWASIApps' "$out/wasi-test.txt" || fail "preview-1 corpus did not pass"
for case in markdown crcsum blake3sum base64x jsonproc script regexmatch bignum; do
  grep -Fq -- "--- PASS: TestWASIApps/$case" "$out/wasi-test.txt" || fail "preview-1 case $case did not pass"
done
if grep -Eqi 'SIGSEGV|segmentation violation|fatal error: fault' "$out/wago-regression.txt" "$out/wasi-test.txt"; then
  fail "fixed review still emitted a native fault"
fi

wasi_status_after=$(git -C "$wasi_repo" status --porcelain=v1 --untracked-files=all)
[[ "$wasi_status_after" == "$wasi_status_before" ]] || fail "WASI source worktree status changed"
cat >"$out/status.txt" <<EOF_STATUS
status=preview1-suite-passes-on-wago-fix-review
wago_fix_revision=$fix_revision
wago_fix_tree=$fix_tree
wago_fix_parent=$production_merge
production_merge=$production_merge
production_merge_tree=$production_tree
production_merge_parents=$production_parent1,$production_parent2
reviewed_wasi=$reviewed_wasi
reviewed_wasi_tree=$reviewed_wasi_tree
trigger_sha256=$trigger_sha256
EOF_STATUS
cat "$out/status.txt"
echo 'decision=Wago register-ABI call_indirect fix is locally validated; production input remains unchanged until the exact fix is reviewed and published'
echo 'wasi-preview1-fix-review: PASS'
