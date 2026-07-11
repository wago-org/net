#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/production-wago-input.sh
source "$root/scripts/lib/production-wago-input.sh"

fail() { echo "test-production-wago-input: $*" >&2; exit 1; }
expect_failure() {
  local description=$1
  shift
  if "$@" >"$tmp/failure.out" 2>"$tmp/failure.err"; then
    fail "$description unexpectedly passed"
  fi
}
commit_file() {
  local repository=$1 path=$2 content=$3 message=$4
  printf '%s\n' "$content" >"$repository/$path"
  git -C "$repository" add "$path"
  git -C "$repository" commit -q -m "$message"
}

mkdir -p "$root/.wago"
tmp=$(mktemp -d "$root/.wago/production-wago-input-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
source_repo="$tmp/source"
git init -q -b main "$source_repo"
git -C "$source_repo" config user.name 'Release Fixture'
git -C "$source_repo" config user.email release-fixture@example.com
commit_file "$source_repo" base.txt base base
git -C "$source_repo" branch workers
commit_file "$source_repo" main.txt main main
git -C "$source_repo" switch -q workers
commit_file "$source_repo" workers.txt workers workers
git -C "$source_repo" switch -q main
git -C "$source_repo" merge -q --no-ff workers -m merge

revision=$(git -C "$source_repo" rev-parse HEAD)
tree=$(git -C "$source_repo" rev-parse 'HEAD^{tree}')
parent_main=$(git -C "$source_repo" rev-parse HEAD^1)
parent_workers=$(git -C "$source_repo" rev-parse HEAD^2)
printf '%s\n' 'user-owned dirty audit change' >>"$source_repo/main.txt"
source_content_before=$(sha256sum "$source_repo/main.txt")
source_status_before=$(git -C "$source_repo" status --porcelain=v1 -z --untracked-files=all | sha256sum)

substitute="$tmp/substitute"
production_wago_prepare_exact_worktree "$source_repo" "$substitute" \
  "$revision" "$tree" "$parent_main" "$parent_workers"
production_wago_verify_exact_clean_merge "$substitute" fixture \
  "$revision" "$tree" "$parent_main" "$parent_workers"
[[ $(sha256sum "$source_repo/main.txt") == "$source_content_before" ]] ||
  fail 'pre-existing dirty source content was overwritten'
[[ $(git -C "$source_repo" status --porcelain=v1 -z --untracked-files=all | sha256sum) == "$source_status_before" ]] ||
  fail 'pre-existing dirty source status changed'

wrong_head="$tmp/wrong-head"
git -C "$source_repo" worktree add -q --detach "$wrong_head" "$parent_main"
expect_failure 'wrong substitute revision' production_wago_verify_exact_clean_merge "$wrong_head" fixture \
  "$revision" "$tree" "$parent_main" "$parent_workers"
expect_failure 'wrong substitute tree' production_wago_verify_exact_clean_merge "$substitute" fixture \
  "$revision" 0000000000000000000000000000000000000000 "$parent_main" "$parent_workers"
expect_failure 'wrong substitute parent order' production_wago_verify_exact_clean_merge "$substitute" fixture \
  "$revision" "$tree" "$parent_workers" "$parent_main"

printf '%s\n' dirty >>"$substitute/main.txt"
dirty_content=$(sha256sum "$substitute/main.txt")
expect_failure 'dirty substitute verification' production_wago_verify_exact_clean_merge "$substitute" fixture \
  "$revision" "$tree" "$parent_main" "$parent_workers"
expect_failure 'dirty existing substitute preparation' production_wago_prepare_exact_worktree "$source_repo" "$substitute" \
  "$revision" "$tree" "$parent_main" "$parent_workers"
[[ $(sha256sum "$substitute/main.txt") == "$dirty_content" ]] ||
  fail 'dirty substitute was cleaned or overwritten after rejection'
[[ $(sha256sum "$source_repo/main.txt") == "$source_content_before" ]] ||
  fail 'dirty source content changed during negative cases'

production_wago_verify_exact_clean_merge "$root/.wago/wago-production-97e6f91" 'actual production Wago' \
  "$production_wago_revision" "$production_wago_tree" \
  "$production_wago_parent_main" "$production_wago_parent_workers"
WAGO_DIR="$root/.wago/wago-production-97e6f91" "$root/scripts/wago-plugin-plan-compat.sh" >/dev/null
echo 'test-production-wago-input: PASS'
