#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly wago_revision=${CI_WAGO_REVISION:-97e6f91e6c822491577faa86f3c30aa5a8fff1e8}
readonly lneto_revision=${CI_LNETO_REVISION:-ab1a0c735a8b534a1d6322a3e245bc11a09431e7}
readonly wago_repository=${CI_WAGO_REPOSITORY:-https://github.com/wago-org/wago.git}
readonly lneto_repository=${CI_LNETO_REPOSITORY:-https://github.com/soypat/lneto.git}
readonly audit_dir=$root/.audit
readonly workspace=$audit_dir/ci.work
readonly environment=$audit_dir/ci.env

module_hashes_before=$(sha256sum "$root/go.mod" "$root/go.sum")

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

verify_selected_module() {
  local module=$1
  local destination=$2
  local selected
  selected=$(GOWORK="$workspace" go list -m -f '{{with .Replace}}{{.Dir}}{{end}}' "$module")
  [[ -n $selected ]] || {
    echo "ci-dependencies: $module has no workspace replacement" >&2
    exit 1
  }
  if [[ $(realpath "$selected") != $(realpath "$destination") ]]; then
    echo "ci-dependencies: $module resolved to $selected, want $destination" >&2
    exit 1
  fi
}

mkdir -p "$audit_dir"
fetch_exact Wago "$wago_repository" "$wago_revision" "$audit_dir/wago"
fetch_exact lneto "$lneto_repository" "$lneto_revision" "$audit_dir/lneto"

cat >"$workspace" <<'EOF'
go 1.24.4

use ..

replace github.com/wago-org/wago => ./wago

replace github.com/soypat/lneto => ./lneto
EOF
printf 'export GOWORK=%q\n' "$workspace" >"$environment"
verify_selected_module github.com/wago-org/wago "$audit_dir/wago"
verify_selected_module github.com/soypat/lneto "$audit_dir/lneto"

module_hashes_after=$(sha256sum "$root/go.mod" "$root/go.sum")
if [[ $module_hashes_after != "$module_hashes_before" ]]; then
  echo 'ci-dependencies: preparation modified go.mod or go.sum' >&2
  exit 1
fi

if [[ -n ${GITHUB_ENV:-} ]]; then
  printf 'GOWORK=%s\n' "$workspace" >>"$GITHUB_ENV"
fi
printf 'ci-dependencies: selected workspace %s\n' "$workspace"
printf 'ci-dependencies: Wago %s at %s\n' "$wago_revision" "$audit_dir/wago"
printf 'ci-dependencies: lneto %s at %s\n' "$lneto_revision" "$audit_dir/lneto"
