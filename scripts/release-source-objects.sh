#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=$(realpath "${WAGO_DIR:-$root/.audit/wago}")
lneto_dir=$(realpath "${LNETO_DIR:-$root/.audit/lneto}")
wasi_dir=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
current_net_dir=$(realpath "${CURRENT_NET_DIR:-$root/.wago/net-current-plugin-registration}")
current_wago_dir=$(realpath "${CURRENT_WAGO_DIR:-$root/.wago/wago-current-plugin-lifecycle}")
workers_dir=$(realpath "${WORKERS_DIR:-$root/.wago/workers-plugin}")
out=${SOURCE_OBJECT_DIR:-${SIGNOFF_DIR:-$root/.wago/release-signoff}/source-objects}
subject=${SOURCE_OBJECT_SUBJECT:-$(git -C "$root" rev-parse HEAD)}

fail() { echo "release-source-objects: $*" >&2; exit 1; }
[[ $subject =~ ^[0-9a-f]{40}$ ]] || fail "subject must be a full lowercase Git object ID"
git -C "$root" cat-file -e "$subject^{commit}" || fail "plugin subject is unavailable"

cd "$root"
GOWORK=off go run ./internal/cmd/release-source-objects \
  -out "$out" -plugin "$root" -subject "$subject" \
  -wago "$wago_dir" -lneto "$lneto_dir" -wasi "$wasi_dir" \
  -current-net "$current_net_dir" -current-wago "$current_wago_dir" -workers "$workers_dir"

echo "release-source-objects: PASS ($out)"
