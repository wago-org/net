#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=$(realpath "${WAGO_DIR:-$root/.audit/wago}")
require_published=${REQUIRE_PUBLISHED:-0}

readonly merge=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly lifecycle_parent=54499ba5135f69a062e23a7255f4a408d6cecf8c
readonly worker_parent=ffd5ef4b122cbd019897eeea3503789ab5860e4a
readonly reviewed_main_base=8ef17eeb3a74f4982ef64d125282c1dab8c8e240
readonly reviewed_worker_base=0d4f4a46b68e5caadb601d02cd1af92c8fddbc11

fail() { echo "wago-upstream-review: $*" >&2; exit 1; }

[[ -d "$wago_dir/.git" ]] || fail "missing Wago repository: $wago_dir"
for revision in "$merge" "$lifecycle_parent" "$worker_parent" "$reviewed_main_base" "$reviewed_worker_base"; do
  git -C "$wago_dir" cat-file -e "$revision^{commit}" 2>/dev/null || fail "missing commit $revision"
done

read -r actual_merge actual_first actual_second extra < <(git -C "$wago_dir" rev-list --parents -n 1 "$merge")
[[ "$actual_merge" == "$merge" && "$actual_first" == "$lifecycle_parent" && "$actual_second" == "$worker_parent" && -z "${extra:-}" ]] ||
  fail "merge parents changed: $(git -C "$wago_dir" rev-list --parents -n 1 "$merge")"

git -C "$wago_dir" merge-base --is-ancestor "$reviewed_main_base" "$lifecycle_parent" ||
  fail "lifecycle parent no longer descends from reviewed Wago main"
git -C "$wago_dir" merge-base --is-ancestor "$reviewed_worker_base" "$worker_parent" ||
  fail "worker parent no longer descends from its reviewed base"
if git -C "$wago_dir" merge-base --is-ancestor "$lifecycle_parent" "$worker_parent" ||
   git -C "$wago_dir" merge-base --is-ancestor "$worker_parent" "$lifecycle_parent"; then
  fail "reviewed parents are no longer divergent"
fi

remote=${WAGO_REMOTE:-origin}
remote_url=$(git -C "$wago_dir" remote get-url "$remote") || fail "missing remote $remote"
remote_refs=$(git -C "$wago_dir" ls-remote "$remote") || fail "cannot inspect $remote_url"
published_refs=$(printf '%s\n' "$remote_refs" | awk -v want="$merge" '$1 == want {print $2}')

printf 'merge: %s\n' "$merge"
printf 'first-parent lifecycle/reset: %s\n' "$lifecycle_parent"
printf 'second-parent workers: %s\n' "$worker_parent"
printf 'reviewed main base: %s\n' "$reviewed_main_base"
printf 'reviewed worker base: %s\n' "$reviewed_worker_base"
printf 'remote: %s (%s)\n' "$remote" "$remote_url"
for ref in refs/heads/main refs/heads/plugin-improvements refs/heads/pr-232-workers-plugin; do
  value=$(printf '%s\n' "$remote_refs" | awk -v want="$ref" '$2 == want {print $1}')
  printf '%s: %s\n' "$ref" "${value:-absent}"
done
if [[ -n "$published_refs" ]]; then
  printf 'immutable merge object is fetchable at:\n%s\n' "$published_refs"
else
  echo 'immutable merge object is not fetchable from the remote'
  [[ "$require_published" == 0 ]] || fail "publish $merge without rebasing or squashing"
fi

echo 'wago-upstream-review: topology PASS'
