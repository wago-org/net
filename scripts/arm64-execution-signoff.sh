#!/usr/bin/env bash
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${ARM64_SIGNOFF_DIR:-$root/.wago/arm64-execution}
manifest=${ARM64_TEST_MANIFEST:-$root/scripts/arm64-test-binaries.tsv}
mode=${ARM64_EXECUTION:-auto}
limit=${ARM64_TIMEOUT:-2m}
keep_binaries=${KEEP_ARM64_BINARY:-0}

fail() { echo "arm64-execution-signoff: $*" >&2; exit 1; }
for command in go sha256sum timeout python3; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
case "$mode" in
  auto|required|skip) ;;
  *) fail "ARM64_EXECUTION must be auto, required, or skip (got $mode)" ;;
esac
[[ -f $manifest ]] || fail "missing binary manifest: $manifest"
[[ $keep_binaries == 0 || $keep_binaries == 1 ]] || fail "KEEP_ARM64_BINARY must be 0 or 1"

rm -rf "$out"
mkdir -p "$out/logs" "$out/binaries"
cp "$manifest" "$out/manifest.tsv"
if ! python3 - "$out/manifest.tsv" <<'PY'
import os
import sys

rows = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line_number, raw in enumerate(stream, 1):
        fields = raw.rstrip("\n").split("\t")
        if len(fields) != 4 or any(not field for field in fields):
            raise SystemExit(f"arm64-execution-signoff: invalid manifest row {line_number}")
        name, package, pattern, binary = fields
        if not package.startswith("github.com/wago-org/net"):
            raise SystemExit(f"arm64-execution-signoff: package outside repository at row {line_number}")
        if "/" in name or os.path.basename(binary) != binary or not binary.endswith("-linux-arm64.test"):
            raise SystemExit(f"arm64-execution-signoff: invalid artifact name at row {line_number}")
        rows.append(tuple(fields))
if not rows:
    raise SystemExit("arm64-execution-signoff: binary manifest is empty")
if rows != sorted(rows):
    raise SystemExit("arm64-execution-signoff: binary manifest is not sorted")
if len({row[0] for row in rows}) != len(rows) or len({row[3] for row in rows}) != len(rows):
    raise SystemExit("arm64-execution-signoff: duplicate manifest identity or binary")
if not any(row[1] == "github.com/wago-org/net/internal/backend/gotls" for row in rows):
    raise SystemExit("arm64-execution-signoff: Go TLS engine smoke is missing")
if not any(row[1] == "github.com/wago-org/net/internal/backend/lneto/tls" for row in rows):
    raise SystemExit("arm64-execution-signoff: mixed TLS transport smoke is missing")
if not any(row[1] == "github.com/wago-org/net/tls" for row in rows):
    raise SystemExit("arm64-execution-signoff: public TLS smoke is missing")
PY
then
  exit 1
fi

: >"$out/commands.tsv"
: >"$out/binaries.sha256"
compile_failures=0
compiled=0
while IFS=$'\t' read -r name package pattern binary_name; do
  [[ -n $name ]] || continue
  binary="$out/binaries/$binary_name"
  compile_log="$out/logs/$name.compile.txt"
  printf '%s\tcompile\tGOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOWORK=off go test -c -o binaries/%s %s\n' \
    "$name" "$binary_name" "$package" >>"$out/commands.tsv"
  if (
    cd "$root"
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOWORK=off go test -c -o "$binary" "$package"
  ) >"$compile_log" 2>&1; then
    compiled=$((compiled + 1))
    sha256sum "$binary" | sed "s#  $binary#  binaries/$binary_name#" >>"$out/binaries.sha256"
    printf 'arm64-execution-signoff: cross-build PASS %s\n' "$name"
  else
    cat "$compile_log" >&2
    printf 'arm64-execution-signoff: cross-build FAIL %s\n' "$name" >&2
    compile_failures=$((compile_failures + 1))
  fi
done <"$out/manifest.tsv"

binary_count=$(wc -l <"$out/manifest.tsv")
cat >"$out/detail.txt" <<EOF
binaries=$binary_count
compiled=$compiled
compile_failures=$compile_failures
timeout=$limit
EOF
if ((compile_failures != 0)); then
  fail "$compile_failures of $binary_count linux/arm64 test binaries failed to cross-compile"
fi

status_file="$out/status.txt"
runner_file="$out/runner.txt"
if [[ $mode == skip ]]; then
  printf 'status=skipped-disabled\n' | tee "$status_file"
  printf 'runner=none\n' >"$runner_file"
  [[ $keep_binaries == 1 ]] || rm -rf "$out/binaries"
  echo 'arm64-execution-signoff: SKIP execution (all smoke binaries cross-compiled; execution disabled explicitly)'
  exit 0
fi

runner_status=
runner_detail=
runner=()
if [[ -n ${ARM64_RUNNER:-} ]]; then
  command -v "$ARM64_RUNNER" >/dev/null || fail "ARM64_RUNNER is not executable: $ARM64_RUNNER"
  runner_status=custom
  runner_detail=$ARM64_RUNNER
  runner=("$ARM64_RUNNER")
elif [[ $(go env GOOS) == linux && $(go env GOARCH) == arm64 ]]; then
  runner_status=native
  runner_detail=native
elif command -v qemu-aarch64 >/dev/null; then
  runner_status=qemu
  runner_detail=$(command -v qemu-aarch64)
  runner=("$runner_detail")
elif command -v qemu-aarch64-static >/dev/null; then
  runner_status=qemu
  runner_detail=$(command -v qemu-aarch64-static)
  runner=("$runner_detail")
fi

if [[ -z $runner_status ]]; then
  printf 'status=skipped-no-runner\n' | tee "$status_file"
  printf 'runner=none\n' >"$runner_file"
  [[ $keep_binaries == 1 ]] || rm -rf "$out/binaries"
  if [[ $mode == required ]]; then
    fail 'no native linux/arm64, qemu-aarch64, or explicit runner is available'
  fi
  echo 'arm64-execution-signoff: SKIP execution (all smoke binaries cross-compiled; no execution runner)'
  exit 0
fi

printf 'runner=%s\nrunner_command=%s\n' "$runner_status" "$runner_detail" >"$runner_file"
run_failures=0
executed=0
while IFS=$'\t' read -r name package pattern binary_name; do
  [[ -n $name ]] || continue
  binary="$out/binaries/$binary_name"
  log="$out/logs/$name.test.txt"
  printf '%s\texecute\ttimeout %s %s binaries/%s -test.run=%s -test.count=1 -test.v\n' \
    "$name" "$limit" "$runner_detail" "$binary_name" "$pattern" >>"$out/commands.tsv"
  if timeout "$limit" "${runner[@]}" "$binary" -test.run="$pattern" -test.count=1 -test.v >"$log" 2>&1; then
    executed=$((executed + 1))
    printf 'arm64-execution-signoff: execution PASS %s through %s\n' "$name" "$runner_status"
  else
    run_status=$?
    cat "$log" >&2
    printf 'arm64-execution-signoff: execution FAIL %s through %s status=%d\n' "$name" "$runner_status" "$run_status" >&2
    run_failures=$((run_failures + 1))
  fi
done <"$out/manifest.tsv"

printf 'executed=%d\nexecution_failures=%d\n' "$executed" "$run_failures" >>"$out/detail.txt"
if ((run_failures != 0)); then
  fail "$run_failures of $binary_count linux/arm64 smoke binaries failed through $runner_status"
fi
printf 'status=executed-%s\n' "$runner_status" | tee "$status_file"
[[ $keep_binaries == 1 ]] || rm -rf "$out/binaries"
echo "arm64-execution-signoff: PASS ($runner_status; $executed binaries)"
