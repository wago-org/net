#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

readonly checkptr_flag='all=-d=checkptr=2'
readonly root_package=github.com/wago-org/net
readonly namespace_core_package=github.com/wago-org/net/internal/namespace/core
readonly root_allocation_test=TestInstallNamespaceServicesAvoidsPerProtocolScratchForCommonSelections
readonly namespace_allocation_test=TestNamespaceCompositionAvoidsPerServiceHeapGrowthForPlannedSuite

# Compile and initialize every package and its test binary under strict pointer
# instrumentation before applying the two explicit runtime-only exclusions.
go test -run '^$' -gcflags="$checkptr_flag" ./...

mapfile -t full_packages < <(
  go list ./... | while IFS= read -r package; do
    case "$package" in
      "$root_package"|"$namespace_core_package") ;;
      *) printf '%s\n' "$package" ;;
    esac
  done
)
if ((${#full_packages[@]} == 0)); then
  echo 'ci-checkptr: no fully instrumented packages found' >&2
  exit 1
fi

go test -gcflags="$checkptr_flag" "${full_packages[@]}"

echo "ci-checkptr: excluding allocation-only assertion under instrumentation: $root_package/$root_allocation_test"
go test -gcflags="$checkptr_flag" -skip="^${root_allocation_test}$" .

echo "ci-checkptr: excluding allocation-only assertion under instrumentation: $namespace_core_package/$namespace_allocation_test"
go test -gcflags="$checkptr_flag" -skip="^${namespace_allocation_test}$" ./internal/namespace/core

echo 'ci-checkptr: all package code compiled; all non-allocation tests passed under checkptr=2'
