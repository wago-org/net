#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

mapfile -t lneto_imports < <(
  grep -RIl 'github.com/soypat/lneto' . \
    --include='*.go' --exclude-dir=.git --exclude-dir=.audit --exclude-dir=.wago \
    | sort
)
if ((${#lneto_imports[@]} == 0)); then
  echo "source-boundary: no lneto imports found" >&2
  exit 1
fi
for file in "${lneto_imports[@]}"; do
  case "$file" in
    ./internal/backend/lneto/*) ;;
    *)
      echo "source-boundary: lneto import escaped backend adapter: $file" >&2
      exit 1
      ;;
  esac
done

if grep -RInE \
  'StackBlocking|StackRetrying|StackGo\(|StartLookupIP|ResultLookupIP|conn\.(Read|Write|Flush)\(|\.ReadFrom\(|\.WriteTo\(' \
  internal/backend/lneto --include='*.go' --exclude='*_test.go'; then
  echo "source-boundary: production backend references a forbidden blocking/backoff API" >&2
  exit 1
fi

if grep -RIl 'github.com/soypat/lneto' . \
  --include='*.go' --exclude-dir=.git --exclude-dir=.audit --exclude-dir=.wago \
  | grep -v '^\./internal/backend/lneto/' >/dev/null; then
  echo "source-boundary: backend-neutral or guest-facing Go source imports lneto" >&2
  exit 1
fi

echo "source-boundary: lneto imports and nonblocking adapter guard passed"
