#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/ci-dependency-env.sh
source "$root/scripts/lib/ci-dependency-env.sh"
ci_select_dependency_workspace "$root"
cd "$root"

benchtime=${BENCHTIME:-100ms}
count=${BENCHCOUNT:-1}
cpu=${BENCHCPU:-1}
log_dir=${BENCH_LOG_DIR:-}

fail() {
  echo "benchmark-smoke: $*" >&2
  exit 1
}

command -v go >/dev/null || fail 'missing required command: go'
command -v python3 >/dev/null || fail 'missing required command: python3'
[[ -n $log_dir ]] || fail 'BENCH_LOG_DIR must not be empty'
[[ -n $benchtime ]] || fail 'BENCHTIME must not be empty'
[[ $count =~ ^[1-9][0-9]*$ ]] || fail 'BENCHCOUNT must be a positive integer'
[[ $cpu =~ ^[1-9][0-9]*$ ]] || fail 'BENCHCPU must be a positive integer'
[[ ! -e $log_dir ]] || fail "BENCH_LOG_DIR already exists: $log_dir"
mkdir -p "$log_dir/logs"

work=$(mktemp -d "${TMPDIR:-/tmp}/wago-net-benchmark-smoke.XXXXXX")
trap 'rm -rf "$work"' EXIT

discovery_json="$work/discovery.json"
targets="$log_dir/targets.tsv"
if ! go test -json -count=1 -run '^$' -list '^Benchmark' ./... >"$discovery_json"; then
  cat "$discovery_json" >&2
  fail 'target discovery failed; emitted discovery JSON above'
fi

python3 - "$discovery_json" "$targets" <<'PY'
import json
import re
import sys

source, destination = sys.argv[1:]
target = re.compile(r"^Benchmark[A-Za-z0-9_]+$")
pairs = set()
with open(source, encoding="utf-8") as stream:
    for line_number, line in enumerate(stream, 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"benchmark-smoke: invalid go test JSON at line {line_number}: {error}")
        package = event.get("Package", "")
        output = event.get("Output", "").strip()
        if package and target.fullmatch(output):
            pairs.add((package, output))
with open(destination, "w", encoding="utf-8") as stream:
    for package, name in sorted(pairs):
        stream.write(f"{package}\t{name}\n")
PY

mapfile -t pairs <"$targets"
((${#pairs[@]} != 0)) || fail 'no benchmarks discovered'
packages=$(cut -f1 "$targets" | LC_ALL=C sort -u | wc -l)
detail="targets=${#pairs[@]} packages=$packages benchtime=$benchtime count=$count cpu=$cpu benchmem=true"
printf '%s\n' "$detail" | tee "$log_dir/detail.txt"

failures=0
for index in "${!pairs[@]}"; do
  IFS=$'\t' read -r package target <<<"${pairs[$index]}"
  printf '\n==> benchmark-smoke [%d/%d] %s %s\n' "$((index + 1))" "${#pairs[@]}" "$package" "$target"
  package_log_dir="$log_dir/logs/$package"
  mkdir -p "$package_log_dir"
  command=(go test "$package" -run '^$' -bench "^${target}$" -benchmem -benchtime="$benchtime" -count="$count" -cpu="$cpu")
  if GOMAXPROCS="$cpu" "${command[@]}" 2>&1 | tee "$package_log_dir/$target.log"; then
    printf 'benchmark-smoke: PASS %s %s\n' "$package" "$target"
  else
    printf 'benchmark-smoke: FAIL %s %s\n' "$package" "$target" >&2
    failures=$((failures + 1))
  fi
done

if ((failures != 0)); then
  fail "$failures of ${#pairs[@]} benchmarks failed"
fi
printf '\nbenchmark-smoke: all %d discovered benchmarks passed\n' "${#pairs[@]}"
