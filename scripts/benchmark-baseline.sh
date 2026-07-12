#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-$root/benchmarks/baseline.txt}
count=${BENCH_COUNT:-5}
benchtime=${BENCH_TIME:-200ms}
cpu=${BENCH_CPU:-1}

mkdir -p "$(dirname "$out")"
cd "$root"

source_head=$(git rev-parse HEAD)
if [[ -n $(git status --porcelain --untracked-files=all) ]]; then
  source_tree=modified
else
  source_tree=clean
fi

{
  printf 'wago-net performance baseline\n'
  printf 'source_head: %s\n' "$source_head"
  printf 'source_tree: %s\n' "$source_tree"
  printf 'go: %s\n' "$(go version)"
  printf 'goos: %s\n' "$(go env GOOS)"
  printf 'goarch: %s\n' "$(go env GOARCH)"
  printf 'kernel: %s\n' "$(uname -srmo)"
  if command -v lscpu >/dev/null 2>&1; then
    printf 'cpu: %s\n' "$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)"
  fi
  printf 'gomaxprocs: %s\n' "$cpu"
  printf 'samples: %s\n' "$count"
  printf 'benchtime: %s\n\n' "$benchtime"
  GOMAXPROCS="$cpu" go test ./... -run '^$' -bench '^Benchmark' -benchmem \
    -benchtime="$benchtime" -count="$count" -cpu="$cpu"
} | tee "$out"
