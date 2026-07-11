#!/usr/bin/env bash

readonly wasi_preview1_package=github.com/wago-org/wasi/p1
readonly -a wasi_preview1_passing_cases=(markdown crcsum base64x jsonproc)
readonly -a wasi_preview1_fault_cases=(blake3sum script regexmatch bignum)

wasi_preview1_exception_fail() {
  echo "wasi-preview1-exception: $*" >&2
  return 1
}

wasi_preview1_assert_exact_fault() {
  local file=$1 case_name=$2
  [[ -s "$file" ]] || { wasi_preview1_exception_fail "empty fault output for $case_name"; return 1; }

  local -a runs
  mapfile -t runs < <(grep '^=== RUN   ' "$file" || true)
  [[ ${#runs[@]} -eq 2 ]] || {
    wasi_preview1_exception_fail "$case_name ran ${#runs[@]} tests, want exact parent and subtest"; return 1;
  }
  [[ ${runs[0]} == '=== RUN   TestWASIApps' && ${runs[1]} == "=== RUN   TestWASIApps/$case_name" ]] || {
    wasi_preview1_exception_fail "$case_name test identity mismatch"; return 1;
  }

  [[ $(grep -Fxc 'fatal error: fault' "$file" || true) -eq 1 ]] || {
    wasi_preview1_exception_fail "$case_name missing unique fatal fault"; return 1;
  }
  local signal_line runtime_line
  signal_line=$(grep -E '^\[signal SIGSEGV: segmentation violation code=0x1 addr=0x[0-9a-f]+ pc=0x[0-9a-f]+\]$' "$file" || true)
  [[ $(printf '%s\n' "$signal_line" | grep -c . || true) -eq 1 ]] || {
    wasi_preview1_exception_fail "$case_name missing unique SIGSEGV signature"; return 1;
  }
  [[ $signal_line =~ addr=(0x[0-9a-f]+)[[:space:]]pc=(0x[0-9a-f]+) ]] || {
    wasi_preview1_exception_fail "$case_name could not parse fault addresses"; return 1;
  }
  local fault_addr=${BASH_REMATCH[1]} fault_pc=${BASH_REMATCH[2]}
  [[ $fault_addr == "$fault_pc" ]] || {
    wasi_preview1_exception_fail "$case_name fault address $fault_addr differs from PC $fault_pc"; return 1;
  }

  runtime_line=$(grep -E '^runtime: g [0-9]+: unexpected return pc for runtime\.sigpanic called from 0x[0-9a-f]+$' "$file" || true)
  [[ $(printf '%s\n' "$runtime_line" | grep -c . || true) -eq 1 ]] || {
    wasi_preview1_exception_fail "$case_name missing unique runtime return-PC signature"; return 1;
  }
  [[ $runtime_line =~ called[[:space:]]from[[:space:]](0x[0-9a-f]+)$ && ${BASH_REMATCH[1]} == "$fault_pc" ]] || {
    wasi_preview1_exception_fail "$case_name runtime return PC does not match the native fault"; return 1;
  }
  grep -Eq "^FAIL[[:space:]]+$wasi_preview1_package([[:space:]]|$)" "$file" || {
    wasi_preview1_exception_fail "$case_name did not fail the exact p1 package"; return 1;
  }
  if grep -Eqi 'panic:|compile:|instantiate:|trap:|timed out|deadline exceeded' "$file"; then
    wasi_preview1_exception_fail "$case_name contained an unrelated failure signature"
    return 1
  fi
}

wasi_preview1_run_exception_matrix() {
  local repo=$1 out=$2
  mkdir -p "$out"

  (
    cd "$repo"
    GOWORK=off go test ./... -count=1 -skip '^TestWASIApps$'
  ) >"$out/non-corpus.txt" 2>&1 || {
    cat "$out/non-corpus.txt" >&2
    wasi_preview1_exception_fail "non-corpus WASI tests failed"
    return 1
  }

  local case_name status
  for case_name in "${wasi_preview1_passing_cases[@]}"; do
    (
      cd "$repo"
      GOWORK=off go test ./p1 -count=1 -v -run "^TestWASIApps/$case_name$"
    ) >"$out/pass-$case_name.txt" 2>&1 || {
      cat "$out/pass-$case_name.txt" >&2
      wasi_preview1_exception_fail "expected passing preview-1 case failed: $case_name"
      return 1
    }
    grep -Fq -- "--- PASS: TestWASIApps/$case_name" "$out/pass-$case_name.txt" || {
      wasi_preview1_exception_fail "passing preview-1 case was not selected exactly: $case_name"
      return 1
    }
  done

  for case_name in "${wasi_preview1_fault_cases[@]}"; do
    set +e
    (
      ulimit -c 0
      cd "$repo"
      GOWORK=off go test ./p1 -count=1 -v -run "^TestWASIApps/$case_name$"
    ) >"$out/fault-$case_name.txt" 2>&1
    status=$?
    set -e
    [[ $status -eq 1 ]] || {
      cat "$out/fault-$case_name.txt" >&2
      wasi_preview1_exception_fail "$case_name exited $status, want go test status 1"
      return 1
    }
    wasi_preview1_assert_exact_fault "$out/fault-$case_name.txt" "$case_name" || return 1
  done

  cat >"$out/status.txt" <<EOF
status=accepted-exact-preview1-native-sigsegv-matrix
passing_cases=$(IFS=,; echo "${wasi_preview1_passing_cases[*]}")
fault_cases=$(IFS=,; echo "${wasi_preview1_fault_cases[*]}")
package=$wasi_preview1_package
signature=fatal-error-fault,sigsegv-code-0x1-equal-addr-pc,runtime-sigpanic-same-return-pc
EOF
}
