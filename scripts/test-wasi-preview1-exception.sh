#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/wasi-preview1-exception.sh
source "$root/scripts/lib/wasi-preview1-exception.sh"

tmp=$(mktemp -d)
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

write_exact() {
  local file=$1 case_name=${2:-blake3sum} addr=${3:-0x1094}
  local pc=${4:-$addr}
  cat >"$file" <<EOF
=== RUN   TestWASIApps
=== RUN   TestWASIApps/$case_name
unexpected fault address $addr
fatal error: fault
[signal SIGSEGV: segmentation violation code=0x1 addr=$addr pc=$pc]
runtime: g 7: unexpected return pc for runtime.sigpanic called from $pc
FAIL	github.com/wago-org/wasi/p1	0.004s
FAIL
EOF
}

expect_rejected() {
  local name=$1 file=$2 case_name=${3:-blake3sum}
  if wasi_preview1_assert_exact_fault "$file" "$case_name" >/dev/null 2>&1; then
    echo "test-wasi-preview1-exception: accepted invalid fixture: $name" >&2
    exit 1
  fi
}

write_exact "$tmp/exact.txt"
wasi_preview1_assert_exact_fault "$tmp/exact.txt" blake3sum

write_exact "$tmp/wrong-case.txt" script
expect_rejected wrong-case "$tmp/wrong-case.txt" blake3sum

write_exact "$tmp/wrong-pc.txt" blake3sum 0x1094 0x1095
expect_rejected wrong-pc "$tmp/wrong-pc.txt"

write_exact "$tmp/missing-runtime.txt"
grep -v '^runtime:' "$tmp/missing-runtime.txt" >"$tmp/missing-runtime.filtered"
expect_rejected missing-runtime "$tmp/missing-runtime.filtered"

write_exact "$tmp/extra-test.txt"
sed -i '2i=== RUN   TestWASIApps/markdown' "$tmp/extra-test.txt"
expect_rejected extra-test "$tmp/extra-test.txt"

write_exact "$tmp/unrelated.txt"
sed -i '3ipanic: unrelated host failure' "$tmp/unrelated.txt"
expect_rejected unrelated-failure "$tmp/unrelated.txt"

write_exact "$tmp/wrong-package.txt"
sed -i 's#github.com/wago-org/wasi/p1#github.com/wago-org/wasi/unstable#' "$tmp/wrong-package.txt"
expect_rejected wrong-package "$tmp/wrong-package.txt"

echo 'test-wasi-preview1-exception: PASS'
