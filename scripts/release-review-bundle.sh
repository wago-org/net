#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_dir=$(realpath "${SIGNOFF_DIR:-$root/.wago/release-signoff}")
bundle=${REVIEW_BUNDLE:-$source_dir.review.tar.gz}
statement=${DISTRIBUTION_STATEMENT:-${bundle%.tar.gz}.distribution.json}
subject=${REVIEW_SUBJECT:-$(git -C "$root" rev-parse HEAD)}

fail() { echo "release-review-bundle: $*" >&2; exit 1; }
[[ -d "$source_dir" ]] || fail "missing signoff directory: $source_dir"
[[ "$bundle" == *.tar.gz ]] || fail "review bundle must use a .tar.gz suffix"
mkdir -p "$(dirname "$bundle")"

cd "$root"
GOWORK=off go run ./internal/cmd/release-review \
  -mode export -source "$source_dir" -out "$bundle" -subject "$subject"
bundle_hash=$(sha256sum "$bundle" | awk '{print $1}')
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify -bundle "$bundle" -subject "$subject" -bundle-sha256 "$bundle_hash"
GOWORK=off go run ./internal/cmd/release-review \
  -mode statement -bundle "$bundle" -out "$statement" -strict-distribution \
  -subject "$subject" -bundle-sha256 "$bundle_hash"

statement_hash=$(sha256sum "$statement" | awk '{print $1}')
printf '%s  %s\n' "$bundle_hash" "$(basename "$bundle")" >"$bundle.sha256"
printf '%s  %s\n' "$statement_hash" "$(basename "$statement")" >"$statement.sha256"
echo "release-review-bundle: PASS ($bundle; sha256: $bundle_hash; statement: $statement; sha256: $statement_hash)"
