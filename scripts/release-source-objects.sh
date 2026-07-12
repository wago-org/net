#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=$(realpath "${WAGO_DIR:-$root/.wago/wago-production-97e6f91}")
lneto_dir=$(realpath "${LNETO_DIR:-$root/.audit/lneto}")
wasi_dir=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
current_net_dir=$(realpath "${CURRENT_NET_DIR:-$root/.wago/net-current-plugin-registration-18615546}")
current_wago_dir=$(realpath "${CURRENT_WAGO_DIR:-$root/.wago/wago-current-plugin-lifecycle-ff04a6b1}")
workers_dir=$(realpath "${WORKERS_DIR:-$root/.wago/workers-plugin}")
out=$(realpath -m "${SOURCE_OBJECT_DIR:-${SIGNOFF_DIR:-$root/.wago/release-signoff}/source-objects}")
subject=${SOURCE_OBJECT_SUBJECT:-$(git -C "$root" rev-parse HEAD)}
allow_outside_artifact_root=${ALLOW_SOURCE_OBJECT_DIR_OUTSIDE_WAGO:-0}
artifact_root=$(realpath -m "$root/.wago")

fail() { echo "release-source-objects: $*" >&2; exit 1; }
path_contains() {
  local parent child
  parent=$(realpath -m "$1")
  child=$(realpath -m "$2")
  [[ "$child" == "$parent" || "$child" == "$parent"/* ]]
}
validate_output_dir() {
  local candidate=$1
  [[ $candidate != / ]] || fail "refusing filesystem root as output directory"
  [[ $candidate != "$HOME" ]] || fail "refusing home directory as output directory"
  ! path_contains "$candidate" "$PWD" || fail "refusing output directory that would remove the current working directory"
  for source in "$root" "$wago_dir" "$lneto_dir" "$wasi_dir" "$current_net_dir" "$current_wago_dir" "$workers_dir"; do
    ! path_contains "$candidate" "$source" || fail "refusing output directory that would remove source repository $source"
  done
  if [[ $allow_outside_artifact_root != 1 ]]; then
    [[ $candidate == "$artifact_root"/* ]] || fail "output must be beneath $artifact_root; set ALLOW_SOURCE_OBJECT_DIR_OUTSIDE_WAGO=1 only for an intentional external artifact directory"
  fi
  [[ $candidate != "$artifact_root" ]] || fail "output must be beneath $artifact_root, not the artifact root itself"
}
[[ $subject =~ ^[0-9a-f]{40}$ ]] || fail "subject must be a full lowercase Git object ID"
git -C "$root" cat-file -e "$subject^{commit}" || fail "plugin subject is unavailable"
validate_output_dir "$out"

cd "$root"
args=(
  -out "$out" -plugin "$root" -subject "$subject"
  -wago "$wago_dir" -lneto "$lneto_dir" -wasi "$wasi_dir"
  -current-net "$current_net_dir" -current-wago "$current_wago_dir" -workers "$workers_dir"
)
if [[ $allow_outside_artifact_root == 1 ]]; then
  args+=( -allow-outside-artifact-root )
fi
GOWORK=off go run ./internal/cmd/release-source-objects "${args[@]}"

echo "release-source-objects: PASS ($out)"
