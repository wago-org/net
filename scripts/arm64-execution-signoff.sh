#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${ARM64_SIGNOFF_DIR:-$root/.wago/arm64-execution}
mode=${ARM64_EXECUTION:-auto}
limit=${ARM64_TIMEOUT:-2m}
keep_binary=${KEEP_ARM64_BINARY:-0}

fail() { echo "arm64-execution-signoff: $*" >&2; exit 1; }
for command in go sha256sum timeout; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
case "$mode" in
  auto|required|skip) ;;
  *) fail "ARM64_EXECUTION must be auto, required, or skip (got $mode)" ;;
esac

rm -rf "$out"
mkdir -p "$out"
binary="$out/net-linux-arm64.test"
status_file="$out/status.txt"
runner_file="$out/runner.txt"
log_file="$out/test.txt"

if [[ "$mode" == skip ]]; then
  printf 'status=skipped-disabled\n' | tee "$status_file"
  printf 'runner=none\n' >"$runner_file"
  echo 'arm64-execution-signoff: SKIP (disabled explicitly)'
  exit 0
fi

# This is intentionally distinct from the release gate's GOOS/GOARCH package
# cross-build: it creates an executable test artifact for a bounded smoke run.
(
  cd "$root"
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOWORK=off go test -c -o "$binary" .
)
sha256sum "$binary" | sed "s#  $binary#  net-linux-arm64.test#" >"$out/binary.sha256"

runner_kind=
runner=()
if [[ -n ${ARM64_RUNNER:-} ]]; then
  command -v "$ARM64_RUNNER" >/dev/null || fail "ARM64_RUNNER is not executable: $ARM64_RUNNER"
  runner_kind=custom
  runner=("$ARM64_RUNNER")
elif [[ $(go env GOOS) == linux && $(go env GOARCH) == arm64 ]]; then
  runner_kind=native
elif command -v qemu-aarch64 >/dev/null; then
  runner_kind=qemu
  runner=("$(command -v qemu-aarch64)")
elif command -v qemu-aarch64-static >/dev/null; then
  runner_kind=qemu-static
  runner=("$(command -v qemu-aarch64-static)")
fi

if [[ -z "$runner_kind" ]]; then
  printf 'status=skipped-no-runner\n' | tee "$status_file"
  printf 'runner=none\n' >"$runner_file"
  [[ "$keep_binary" == 1 ]] || rm -f "$binary"
  if [[ "$mode" == required ]]; then
    fail 'no native linux/arm64 or qemu-aarch64 runner is available'
  fi
  echo 'arm64-execution-signoff: SKIP (cross-compiled smoke binary; no execution runner)'
  exit 0
fi

printf 'runner=%s\n' "$runner_kind" >"$runner_file"
printf 'command=%q' timeout >>"$runner_file"
printf ' %q' "$limit" "${runner[@]}" "$binary" >>"$runner_file"
printf ' %q\n' '-test.run=^(TestExtensionMetadataAndABIBinding|TestGuestUDPEmptyTruncationAndFailedMemoryWrites|TestRegisteredGuestTCPTwoNamespaceExchange|TestRegisteredGuestDNSActualBackendSmoke)$' >>"$runner_file"

set +e
timeout "$limit" "${runner[@]}" "$binary" \
  -test.run='^(TestExtensionMetadataAndABIBinding|TestGuestUDPEmptyTruncationAndFailedMemoryWrites|TestRegisteredGuestTCPTwoNamespaceExchange|TestRegisteredGuestDNSActualBackendSmoke)$' \
  -test.count=1 -test.v >"$log_file" 2>&1
run_status=$?
set -e
if ((run_status != 0)); then
  cat "$log_file" >&2
  fail "linux/arm64 smoke failed through $runner_kind with status $run_status"
fi

printf 'status=executed-%s\n' "$runner_kind" | tee "$status_file"
[[ "$keep_binary" == 1 ]] || rm -f "$binary"
echo "arm64-execution-signoff: PASS ($runner_kind)"
