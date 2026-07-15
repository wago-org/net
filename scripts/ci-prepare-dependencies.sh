#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly wago_revision=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly lneto_revision=ab1a0c735a8b534a1d6322a3e245bc11a09431e7

fetch_exact() {
  local name=$1
  local repository=$2
  local revision=$3
  local destination=$4

  if [[ -d "$destination/.git" ]] &&
     [[ $(git -C "$destination" rev-parse HEAD 2>/dev/null || true) == "$revision" ]]; then
    printf 'ci-dependencies: using existing %s at %s\n' "$name" "$revision"
    return
  fi

  rm -rf "$destination"
  mkdir -p "$destination"
  git -C "$destination" init --quiet
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --quiet --depth=1 origin "$revision"
  git -C "$destination" checkout --quiet --detach FETCH_HEAD
  local actual
  actual=$(git -C "$destination" rev-parse HEAD)
  if [[ "$actual" != "$revision" ]]; then
    echo "ci-dependencies: $name resolved $actual, want $revision" >&2
    exit 1
  fi
  printf 'ci-dependencies: fetched %s at %s\n' "$name" "$revision"
}

mkdir -p "$root/.audit"
fetch_exact Wago https://github.com/wago-org/wago.git "$wago_revision" "$root/.audit/wago"
fetch_exact lneto https://github.com/soypat/lneto.git "$lneto_revision" "$root/.audit/lneto"
