#!/usr/bin/env bash

readonly production_wago_revision=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly production_wago_tree=adbba31c51996f1c1d6d3c2069de8ddf0afd94ee
readonly production_wago_parent_main=54499ba5135f69a062e23a7255f4a408d6cecf8c
readonly production_wago_parent_workers=ffd5ef4b122cbd019897eeea3503789ab5860e4a

production_wago_fail() {
  echo "production-wago-input: $*" >&2
  return 1
}

production_wago_verify_exact_clean_merge() {
  local directory=$1
  local name=${2:-production Wago}
  local revision=${3:-$production_wago_revision}
  local tree=${4:-$production_wago_tree}
  local parent_main=${5:-$production_wago_parent_main}
  local parent_workers=${6:-$production_wago_parent_workers}
  local got_revision got_tree
  local -a commit_line parents

  [[ -d "$directory" ]] || production_wago_fail "missing $name directory: $directory" || return
  git -C "$directory" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    production_wago_fail "$name is not a Git worktree: $directory" || return

  got_revision=$(git -C "$directory" rev-parse HEAD) || return
  [[ "$got_revision" == "$revision" ]] ||
    production_wago_fail "$name HEAD is $got_revision, want $revision" || return
  got_tree=$(git -C "$directory" rev-parse 'HEAD^{tree}') || return
  [[ "$got_tree" == "$tree" ]] ||
    production_wago_fail "$name tree is $got_tree, want $tree" || return

  read -r -a commit_line <<<"$(git -C "$directory" rev-list --parents -n 1 HEAD)"
  parents=("${commit_line[@]:1}")
  [[ ${#parents[@]} -eq 2 ]] ||
    production_wago_fail "$name has ${#parents[@]} parents, want exactly 2" || return
  [[ "${parents[0]}" == "$parent_main" ]] ||
    production_wago_fail "$name first parent is ${parents[0]}, want $parent_main" || return
  [[ "${parents[1]}" == "$parent_workers" ]] ||
    production_wago_fail "$name second parent is ${parents[1]}, want $parent_workers" || return

  if [[ -n $(git -C "$directory" status --porcelain --untracked-files=all) ]]; then
    git -C "$directory" status --short >&2
    production_wago_fail "$name working tree is not clean" || return
  fi
}

production_wago_prepare_exact_worktree() {
  local source=$1 destination=$2
  local revision=${3:-$production_wago_revision}
  local tree=${4:-$production_wago_tree}
  local parent_main=${5:-$production_wago_parent_main}
  local parent_workers=${6:-$production_wago_parent_workers}

  git -C "$source" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    production_wago_fail "source is not a Git worktree: $source" || return
  git -C "$source" cat-file -e "$revision^{commit}" 2>/dev/null ||
    production_wago_fail "source does not contain required commit $revision" || return

  if [[ ! -e "$destination" ]]; then
    mkdir -p "$(dirname "$destination")"
    git -C "$source" worktree add --detach "$destination" "$revision" >/dev/null
  fi
  production_wago_verify_exact_clean_merge "$destination" 'production Wago substitute' \
    "$revision" "$tree" "$parent_main" "$parent_workers"
}
