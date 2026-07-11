#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bundle=${REVIEW_BUNDLE:-}
statement=${DISTRIBUTION_STATEMENT:-}
signature=${DISTRIBUTION_SIGNATURE:-}
trust_policy=${DISTRIBUTION_TRUST_POLICY:-}
receipt=${PRODUCTION_READINESS_RECEIPT:-}

fail() { echo "release-candidate-readiness: $*" >&2; exit 2; }
[[ -n "$bundle" ]] || fail "REVIEW_BUNDLE is required"
[[ -n "$statement" ]] || fail "DISTRIBUTION_STATEMENT is required"
[[ -n "$signature" ]] || fail "DISTRIBUTION_SIGNATURE is required"
[[ -n "$trust_policy" ]] || fail "DISTRIBUTION_TRUST_POLICY is required"
[[ -n "$receipt" ]] || fail "PRODUCTION_READINESS_RECEIPT is required"

cd "$root"
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify-production-candidate \
  -bundle "$bundle" \
  -statement "$statement" \
  -signature "$signature" \
  -trust-policy "$trust_policy" \
  -out "$receipt"

echo "release-candidate-readiness: PASS"
