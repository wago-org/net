#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
production_wago_repo=$(realpath "${WAGO_WASI_FIX_DIR:-$root/.wago/wago-wasi-preview1-regabi-fix-97e6f91}")
current_wago_repo=$(realpath "${CURRENT_WAGO_WASI_FIX_DIR:-$root/.wago/wago-current-plugin-lifecycle-1a912c69}")
wasi_repo=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
out=$(realpath -m "${WASI_FIX_REVIEW_OUT:-$root/.wago/wasi-preview1-fix-review}")

readonly production_fix=5c7f76dba0aa82ca94a1dd644318ed062b03f7cc
readonly production_fix_tree=442d6a7506260565bccb01e32e016f6dccc25d6c
readonly production_merge=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly production_tree=adbba31c51996f1c1d6d3c2069de8ddf0afd94ee
readonly production_parent1=54499ba5135f69a062e23a7255f4a408d6cecf8c
readonly production_parent2=ffd5ef4b122cbd019897eeea3503789ab5860e4a
readonly current_integration=5385ea0a7d87332cc3926459ffb20d5cc36aff6e
readonly current_integration_tree=b01ebcbd8ffaa5cb2a3159f2d0b3cf20e35e6735
readonly current_managed=f59d96c61d77a26ec054191fd74a5e1889909dd7
readonly current_managed_tree=5cc1e716d03a4f390277e64471f2d7a1b405db21
readonly current_fix=b17213288cc673b8a6b4e32e29592ae776a5615e
readonly current_fix_tree=3371e2baeb3af5ed08c80b261f0836f21d5033a7
readonly current_main=1a912c699d913fe3e398a5bc33bfdd9fbeeba391
readonly current_main_tree=77f69ddfa2d574174b7534a7adedc110e7c740e4
readonly current_main_parent=e335cc1ef896419994df5fa2f92f9824d010cd14
readonly production_wasi=1a7eeb215229e05bcb0f09d5cb3280d231739def
readonly production_wasi_tree=9108df32daccfe5a8458e6623d996bcb51f38756
readonly production_wasi_parent=ab7d597a8517283b0399e09d967b7f02ded1772f
readonly current_wasi=cbdb9b32a3f28c0e63c7ab40d9c59712162367c4
readonly current_wasi_tree=b77c7e975c29de5bcff9da4464ce50d9b8ad2c65
readonly current_wasi_parent=1a7eeb215229e05bcb0f09d5cb3280d231739def
readonly trigger_sha256=3d93d0329b190e98c4956e0abe05039954f8bf61a22f833bf5a40af5798f668d

fail() { echo "wasi-preview1-fix-review: $*" >&2; exit 1; }

for command in awk git go grep mktemp paste realpath sed sha256sum sort tar tinygo; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
for repo in "$production_wago_repo" "$current_wago_repo" "$wasi_repo"; do
  git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "missing Git repository: $repo"
done

verify_commit() {
  local repo=$1 revision=$2 tree=$3
  git -C "$repo" cat-file -e "$revision^{commit}" 2>/dev/null || fail "missing commit $revision in $repo"
  [[ $(git -C "$repo" rev-parse "$revision^{tree}") == "$tree" ]] || fail "tree mismatch for $revision"
}
verify_commit "$production_wago_repo" "$production_fix" "$production_fix_tree"
verify_commit "$production_wago_repo" "$production_merge" "$production_tree"
verify_commit "$current_wago_repo" "$current_integration" "$current_integration_tree"
verify_commit "$current_wago_repo" "$current_managed" "$current_managed_tree"
verify_commit "$current_wago_repo" "$current_fix" "$current_fix_tree"
verify_commit "$current_wago_repo" "$current_main" "$current_main_tree"
verify_commit "$wasi_repo" "$production_wasi" "$production_wasi_tree"
verify_commit "$wasi_repo" "$current_wasi" "$current_wasi_tree"

[[ $(git -C "$production_wago_repo" rev-parse HEAD) == "$production_fix" ]] ||
  fail "production-derived Wago fix review worktree is not at $production_fix"
[[ $(git -C "$current_wago_repo" rev-parse HEAD) == "$current_integration" ]] ||
  fail "current-main Wago integration review worktree is not at $current_integration"
[[ -z $(git -C "$production_wago_repo" status --porcelain --untracked-files=all) ]] ||
  fail "production-derived Wago fix review worktree is dirty"
[[ -z $(git -C "$current_wago_repo" status --porcelain --untracked-files=all) ]] ||
  fail "current-main Wago fix review worktree is dirty"
[[ $(git -C "$production_wago_repo" show -s --format=%P "$production_fix") == "$production_merge" ]] ||
  fail "production-derived fix parent mismatch"
[[ $(git -C "$current_wago_repo" show -s --format=%P "$current_integration") == "$current_managed" ]] ||
  fail "current-main exact-slot integration parent mismatch"
[[ $(git -C "$current_wago_repo" show -s --format=%P "$current_managed") == "$current_fix" ]] ||
  fail "current-main managed-wrapper integration parent mismatch"
[[ $(git -C "$current_wago_repo" show -s --format=%P "$current_fix") == "$current_main" ]] ||
  fail "current-main preview-1 fix parent mismatch"
[[ $(git -C "$current_wago_repo" show -s --format=%P "$current_main") == "$current_main_parent" ]] ||
  fail "reviewed upstream lifecycle parent mismatch"
read -r merge_parent1 merge_parent2 extra <<<"$(git -C "$production_wago_repo" show -s --format=%P "$production_merge")"
[[ -z ${extra:-} && "$merge_parent1" == "$production_parent1" && "$merge_parent2" == "$production_parent2" ]] ||
  fail "production Wago ordered parents changed"
[[ $(git -C "$wasi_repo" show -s --format=%P "$production_wasi") == "$production_wasi_parent" ]] ||
  fail "production-line WASI parent mismatch"
[[ $(git -C "$wasi_repo" show -s --format=%P "$current_wasi") == "$current_wasi_parent" ]] ||
  fail "current-line WASI parent mismatch"
[[ $(git -C "$wasi_repo" rev-parse refs/remotes/origin/main) == "$current_wasi" ]] ||
  fail "WASI origin/main moved; review the new implementation before changing the current-line input"

patch_id() {
  git -C "$1" show --pretty=format: --no-ext-diff "$2" | git patch-id --stable | awk 'NR == 1 {print $1}'
}
production_patch=$(patch_id "$production_wago_repo" "$production_fix")
current_patch=$(patch_id "$current_wago_repo" "$current_fix")
[[ -n "$production_patch" && "$production_patch" == "$current_patch" ]] ||
  fail "production-derived and current-main fixes are not patch-equivalent"
expected_paths=$'src/wago/instantiate.go\nsrc/wago/testdata/wasi-preview1-sync-indirect.wasm\nsrc/wago/wasi_preview1_sync_indirect_test.go'
for spec in "$production_wago_repo:$production_fix" "$current_wago_repo:$current_fix"; do
  repo=${spec%%:*}
  revision=${spec##*:}
  actual_paths=$(git -C "$repo" diff-tree --no-commit-id --name-only -r "$revision" | sort)
  [[ "$actual_paths" == "$expected_paths" ]] || fail "unexpected paths in fix $revision"
done
managed_paths=$'src/wago/managed_instances.go\nsrc/wago/managed_instances_wrapper_test.go'
[[ $(git -C "$current_wago_repo" diff-tree --no-commit-id --name-only -r "$current_managed" | sort) == "$managed_paths" ]] ||
  fail "unexpected paths in current-main managed-wrapper integration"
slot_paths=$'src/wago/hostcall.go\nsrc/wago/hostlink_test.go'
[[ $(git -C "$current_wago_repo" diff-tree --no-commit-id --name-only -r "$current_integration" | sort) == "$slot_paths" ]] ||
  fail "unexpected paths in current-main exact-slot integration"

# Refresh publication refs from a clean review checkout. This updates only Git
# metadata shared by the linked worktrees; it never resets or compiles the dirty
# user-owned .audit/wago checkout.
git -C "$current_wago_repo" fetch --prune origin
observed_wago_main=$(git -C "$current_wago_repo" rev-parse refs/remotes/origin/main)
wago_remote=$(git -C "$current_wago_repo" ls-remote origin)
refs_for() { awk -v want="$1" '$1 == want {print $2}' | paste -sd, -; }
production_fix_refs=$(printf '%s\n' "$wago_remote" | refs_for "$production_fix")
production_merge_refs=$(printf '%s\n' "$wago_remote" | refs_for "$production_merge")
current_integration_refs=$(printf '%s\n' "$wago_remote" | refs_for "$current_integration")
current_fix_refs=$(printf '%s\n' "$wago_remote" | refs_for "$current_fix")
current_managed_refs=$(printf '%s\n' "$wago_remote" | refs_for "$current_managed")

wasi_status_before=$(git -C "$wasi_repo" status --porcelain=v1 --untracked-files=all)
rm -rf "$out"
mkdir -p "$out"
tmp=$(mktemp -d "$out/run.XXXXXX")
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/production-wago" "$tmp/current-wago" "$tmp/production-wasi" "$tmp/current-wasi"
git -C "$production_wago_repo" archive "$production_fix" | tar -x -C "$tmp/production-wago"
git -C "$current_wago_repo" archive "$current_integration" | tar -x -C "$tmp/current-wago"
git -C "$wasi_repo" archive "$production_wasi" | tar -x -C "$tmp/production-wasi"
git -C "$wasi_repo" archive "$current_wasi" | tar -x -C "$tmp/current-wasi"

for directory in "$tmp/production-wago" "$tmp/current-wago"; do
  [[ $(sha256sum "$directory/src/wago/testdata/wasi-preview1-sync-indirect.wasm" | awk '{print $1}') == "$trigger_sha256" ]] ||
    fail "minimized preview-1 trigger digest mismatch in $directory"
done
cat >"$tmp/production-wago/src/wago/trap_code_wasi_fix_review_test.go" <<'EOF_HELPER'
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
  cd "$tmp/production-wago"
  GOWORK=off go test ./src/wago -run '^TestSyncHostLinkedCallIndirectUsesWrapperDescriptors$' -count=1 -v
) >"$out/production-wago-regression.txt" 2>&1
ln -s "$tmp/production-wago" "$tmp/wago"
(
  cd "$tmp/production-wasi"
  GOWORK=off go test ./... -count=1 -v
) >"$out/production-wasi-test.txt" 2>&1
rm "$tmp/wago"
ln -s "$tmp/current-wago" "$tmp/wago"
(
  cd "$tmp/current-wago"
  GOWORK=off go test ./src/wago -count=1
) >"$out/current-wago-test.txt" 2>&1
(
  cd "$tmp/current-wago"
  GOWORK=off go test -race ./src/wago -run '^(TestSyncHostLinkedCallIndirectUsesWrapperDescriptors|TestManagedVoidTableInvokesSyncHostWrapperDescriptor|TestSynchronousHostCallbackUsesDeclaredSlotWidths)$' -count=1 -v
) >"$out/current-wago-race.txt" 2>&1
(
  cd "$tmp/current-wago"
  GOWORK=off tinygo test ./src/wago
) >"$out/current-wago-tinygo.txt" 2>&1
(
  cd "$tmp/current-wasi"
  GOWORK=off go test ./... -count=1 -v
) >"$out/current-wasi-test.txt" 2>&1
sed -i "s#${tmp//\#/\\#}#<isolated-wasi-fix-review>#g" "$out"/*.txt

grep -Fq -- '--- PASS: TestSyncHostLinkedCallIndirectUsesWrapperDescriptors' "$out/production-wago-regression.txt" ||
  fail "production-wago-regression did not pass the focused regression"
for test in TestSyncHostLinkedCallIndirectUsesWrapperDescriptors TestManagedVoidTableInvokesSyncHostWrapperDescriptor TestSynchronousHostCallbackUsesDeclaredSlotWidths; do
  grep -Fq -- "--- PASS: $test" "$out/current-wago-race.txt" || fail "current-wago-race did not pass $test"
done
for log in production-wasi-test current-wasi-test; do
  grep -Fq -- '--- PASS: TestWASIApps' "$out/$log.txt" || fail "$log did not pass the preview-1 corpus"
  for case in markdown crcsum blake3sum base64x jsonproc script regexmatch bignum; do
    grep -Fq -- "--- PASS: TestWASIApps/$case" "$out/$log.txt" || fail "$log case $case did not pass"
  done
done
if grep -Eqi 'SIGSEGV|segmentation violation|fatal error: fault' "$out"/*.txt; then
  fail "a fixed review still emitted a native fault"
fi

wasi_status_after=$(git -C "$wasi_repo" status --porcelain=v1 --untracked-files=all)
[[ "$wasi_status_after" == "$wasi_status_before" ]] || fail "WASI source worktree status changed"
cat >"$out/publication.txt" <<EOF_PUBLICATION
production_fix_refs=${production_fix_refs:-absent}
production_merge_refs=${production_merge_refs:-absent}
current_integration_refs=${current_integration_refs:-absent}
current_fix_refs=${current_fix_refs:-absent}
current_managed_refs=${current_managed_refs:-absent}
observed_wago_main=$observed_wago_main
reviewed_wago_main=$current_main
EOF_PUBLICATION
cat >"$out/status.txt" <<EOF_STATUS
status=preview1-suite-passes-on-production-fix-and-current-integrated-fix-reviews
production_wago_fix_revision=$production_fix
production_wago_fix_tree=$production_fix_tree
production_wago_fix_parent=$production_merge
production_merge=$production_merge
production_merge_tree=$production_tree
production_merge_parents=$production_parent1,$production_parent2
current_wago_integration_revision=$current_integration
current_wago_integration_tree=$current_integration_tree
current_wago_integration_parent=$current_managed
current_wago_managed_revision=$current_managed
current_wago_managed_tree=$current_managed_tree
current_wago_managed_parent=$current_fix
current_wago_fix_revision=$current_fix
current_wago_fix_tree=$current_fix_tree
current_wago_fix_parent=$current_main
current_wago_main_revision=$current_main
current_wago_main_tree=$current_main_tree
current_wago_main_parent=$current_main_parent
fix_patch_id=$production_patch
production_wasi=$production_wasi
production_wasi_tree=$production_wasi_tree
current_wasi=$current_wasi
current_wasi_tree=$current_wasi_tree
trigger_sha256=$trigger_sha256
EOF_STATUS
cat "$out/status.txt"
cat "$out/publication.txt"
if [[ "$observed_wago_main" == "$current_main" ]]; then
  echo 'moving-main-decision=reviewed Wago main remains current'
else
  echo 'moving-main-decision=Wago main moved; exact fix evidence remains valid, but topology adoption requires fresh semantic ports and re-review'
fi
echo 'decision=patch-equivalent fix commits preserve both lineages; current-main integration adds managed-wrapper and exact callback-slot children; no local Wago subject is treated as published'
echo 'wasi-preview1-fix-review: PASS'
