#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_dir=$(realpath "${WAGO_SOURCE_REPO:-$root/.audit/wago}")
destination=$(realpath -m "${WAGO_DIR:-$root/.wago/wago-production-97e6f91}")

# shellcheck source=scripts/lib/production-wago-input.sh
source "$root/scripts/lib/production-wago-input.sh"

source_status_before=$(git -C "$source_dir" status --porcelain=v1 -z --untracked-files=all | sha256sum)
production_wago_prepare_exact_worktree "$source_dir" "$destination"
source_status_after=$(git -C "$source_dir" status --porcelain=v1 -z --untracked-files=all | sha256sum)
[[ "$source_status_after" == "$source_status_before" ]] ||
  production_wago_fail 'source worktree status changed while preparing the clean substitute'

printf 'production Wago: %s\n' "$production_wago_revision"
printf 'tree: %s\n' "$production_wago_tree"
printf 'ordered parents: %s %s\n' "$production_wago_parent_main" "$production_wago_parent_workers"
printf 'clean worktree: %s\n' "$destination"
printf 'source worktree status: preserved (dirty source content is never cleaned or overwritten)\n'
