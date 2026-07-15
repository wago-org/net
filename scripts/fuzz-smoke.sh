#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

fuzztime=${FUZZTIME:-1s}
log_dir=${FUZZ_LOG_DIR:-}

fail() {
  echo "fuzz-smoke: $*" >&2
  exit 1
}

command -v go >/dev/null || fail 'missing required command: go'
command -v python3 >/dev/null || fail 'missing required command: python3'
[[ -n $fuzztime ]] || fail 'FUZZTIME must not be empty'

work=$(mktemp -d "${TMPDIR:-/tmp}/wago-net-fuzz-smoke.XXXXXX")
trap 'rm -rf "$work"' EXIT

discovery_json="$work/discovery.json"
targets="$work/targets.tsv"
if ! go test -json -count=1 -run '^$' -list '^Fuzz' ./... >"$discovery_json"; then
  cat "$discovery_json" >&2
  fail 'target discovery failed; emitted discovery JSON above'
fi

python3 - "$discovery_json" "$targets" <<'PY'
import json
import re
import sys

source, destination = sys.argv[1:]
target = re.compile(r"^Fuzz[A-Za-z0-9_]+$")
pairs = set()
with open(source, encoding="utf-8") as stream:
    for line_number, line in enumerate(stream, 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"fuzz-smoke: invalid go test JSON at line {line_number}: {error}")
        package = event.get("Package", "")
        output = event.get("Output", "").strip()
        if package and target.fullmatch(output):
            pairs.add((package, output))
with open(destination, "w", encoding="utf-8") as stream:
    for package, name in sorted(pairs):
        stream.write(f"{package}\t{name}\n")
PY

mapfile -t pairs <"$targets"
((${#pairs[@]} != 0)) || fail 'no fuzz targets discovered'

packages=$(cut -f1 "$targets" | LC_ALL=C sort -u | wc -l)
printf 'fuzz-smoke: discovered %d targets in %d packages; duration=%s each\n' "${#pairs[@]}" "$packages" "$fuzztime"

if [[ -n $log_dir ]]; then
  mkdir -p "$log_dir"
  cp "$targets" "$log_dir/targets.tsv"
fi

failures=0
for index in "${!pairs[@]}"; do
  IFS=$'\t' read -r package target <<<"${pairs[$index]}"
  printf '\n==> fuzz-smoke [%d/%d] %s %s\n' "$((index + 1))" "${#pairs[@]}" "$package" "$target"
  command=(go test "$package" -run '^$' -fuzz "^${target}$" -fuzztime="$fuzztime")
  if [[ -n $log_dir ]]; then
    package_log_dir="$log_dir/$package"
    mkdir -p "$package_log_dir"
    if "${command[@]}" 2>&1 | tee "$package_log_dir/$target.log"; then
      printf 'fuzz-smoke: PASS %s %s\n' "$package" "$target"
    else
      printf 'fuzz-smoke: FAIL %s %s\n' "$package" "$target" >&2
      failures=$((failures + 1))
    fi
  elif "${command[@]}"; then
    printf 'fuzz-smoke: PASS %s %s\n' "$package" "$target"
  else
    printf 'fuzz-smoke: FAIL %s %s\n' "$package" "$target" >&2
    failures=$((failures + 1))
  fi
done

if ((failures != 0)); then
  fail "$failures of ${#pairs[@]} fuzz targets failed"
fi
printf '\nfuzz-smoke: all %d discovered targets passed\n' "${#pairs[@]}"
