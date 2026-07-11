#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=$(realpath "${WAGO_DIR:-$root/.audit/wago}")
lneto_dir=$(realpath "${LNETO_DIR:-$root/.audit/lneto}")
wasi_dir=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
current_net_dir=$(realpath "${CURRENT_NET_DIR:-$root/.wago/net-current-plugin-registration-18615546}")
current_wago_dir=$(realpath "${CURRENT_WAGO_DIR:-$root/.wago/wago-current-plugin-lifecycle-18615546}")
workers_dir=$(realpath "${WORKERS_DIR:-$root/.wago/workers-plugin}")
fuzztime=${FUZZTIME:-3s}
run_wasi=${RUN_WASI:-1}
allow_dirty=${ALLOW_DIRTY:-0}
out=${SIGNOFF_DIR:-$root/.wago/release-signoff}

readonly expected_wago=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly expected_wago_parent_main=54499ba5135f69a062e23a7255f4a408d6cecf8c
readonly expected_wago_parent_workers=ffd5ef4b122cbd019897eeea3503789ab5860e4a
readonly expected_lneto=ab1a0c735a8b534a1d6322a3e245bc11a09431e7
readonly expected_wasi=3df6c766ad00e83b314da799dbf9a77b409ad19d
readonly expected_current_net=173b38a4d5a0db0e6058544576942a46b9d543df
readonly expected_current_wago=8131d967211871936793a4f129164ec0cd928ea9
readonly expected_workers=1e9139756d8a3c631c59c00b028038c83bfa8341

log() { printf '\n==> %s\n' "$*"; }
fail() { echo "release-signoff: $*" >&2; exit 1; }
record_check() {
  local name=$1 status=$2 detail=${3:-}
  [[ "$name$status$detail" != *$'\t'* && "$name$status$detail" != *$'\n'* ]] || fail "invalid check record"
  printf '%s\t%s' "$name" "$status" >>"$checks"
  [[ -z "$detail" ]] || printf '\t%s' "$detail" >>"$checks"
  printf '\n' >>"$checks"
}
repo_head() { git -C "$1" rev-parse HEAD; }
assert_head() {
  local dir=$1 want=$2 name=$3
  local got
  got=$(repo_head "$dir")
  [[ "$got" == "$want" ]] || fail "$name HEAD is $got, want $want"
}
assert_clean() {
  local dir=$1 name=$2
  if [[ -n $(git -C "$dir" status --porcelain --untracked-files=all) ]]; then
    git -C "$dir" status --short >&2
    fail "$name working tree is not clean"
  fi
}

for command in git go tinygo grep cmp sed sha256sum; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
for dir in "$root" "$wago_dir" "$lneto_dir" "$wasi_dir" "$current_net_dir" "$current_wago_dir" "$workers_dir"; do
  [[ -d "$dir" ]] || fail "missing repository directory: $dir"
done

log "verify pinned audit repositories"
assert_head "$wago_dir" "$expected_wago" Wago
assert_head "$lneto_dir" "$expected_lneto" lneto
assert_head "$wasi_dir" "$expected_wasi" WASI
assert_head "$current_net_dir" "$expected_current_net" 'current networking review'
assert_head "$current_wago_dir" "$expected_current_wago" 'current Wago review'
assert_head "$workers_dir" "$expected_workers" 'external workers'
[[ $(git -C "$wago_dir" rev-parse HEAD^1) == "$expected_wago_parent_main" ]] || fail "Wago lifecycle parent drifted"
[[ $(git -C "$wago_dir" rev-parse HEAD^2) == "$expected_wago_parent_workers" ]] || fail "Wago worker parent drifted"
if [[ $allow_dirty != 1 ]]; then
  assert_clean "$root" plugin
  assert_clean "$wago_dir" Wago
  assert_clean "$lneto_dir" lneto
  assert_clean "$wasi_dir" WASI
  assert_clean "$current_net_dir" 'current networking review'
  assert_clean "$current_wago_dir" 'current Wago review'
  assert_clean "$workers_dir" 'external workers'
fi
[[ $(realpath "$root/../wago") == $(realpath "$wago_dir") ]] || fail "../wago does not resolve to the pinned Wago audit checkout"

rm -rf "$out"
mkdir -p "$out"
checks="$out/checks.tsv"
: >"$checks"
record_check pinned-revisions pass 'exact audit revisions and ordered Wago parents'
record_check initial-clean-trees pass 'plugin, production inputs, current plugin reviews, and external workers'
WAGO_DIR="$wago_dir" "$root/scripts/wago-plugin-plan-compat.sh" | tee "$out/wago-plugin-plan-compat.txt"
record_check wago-plugin-plan-compat pass 'reviewed redesign requires migration; networking pin unchanged'
CURRENT_WAGO_DIR="$current_wago_dir" CURRENT_NET_DIR="$current_net_dir" WORKERS_DIR="$workers_dir" \
  "$root/scripts/current-plugin-topology-audit.sh" | tee "$out/current-plugin-topology.txt"
record_check current-plugin-topology-audit pass 'moving refs refreshed; explicit publication truth; pooling unsupported'
if grep -q '^adoption mode: adopted$' "$out/current-plugin-topology.txt"; then
  current_plugin_publication=adopted
else
  current_plugin_publication=review-only
fi
if grep -q '^production decision: exact ordered-parent Wago merge is fetchable$' "$out/current-plugin-topology.txt"; then
  production_wago_publication=published
else
  production_wago_publication=unpublished
fi
cat >"$out/publication.txt" <<EOF
current_plugin=$current_plugin_publication
production_wago_merge=$production_wago_publication
external_workers=published
pooling=unsupported
publisher_authentication=external-required
hosted_release_automation=disabled
EOF
WASI_DIR="$wasi_dir" WAGO_DIR="$wago_dir" WASI_UPSTREAM_AUDIT_OUT="$out/wasi-upstream" \
  "$root/scripts/wasi-upstream-preview1-audit.sh" | tee "$out/wasi-upstream-preview1-audit.txt"
record_check wasi-upstream-preview1-audit accepted-exception 'reviewed docs/CI-only upstream still reaches the native preview-1 SIGSEGV; pin retained'
printf 'go: %s\n' "$(go version)" | tee "$out/toolchains.txt"
printf 'tinygo: %s\n' "$(tinygo version | tr '\n' ' ')" | tee -a "$out/toolchains.txt"
printf 'plugin: %s\nWago: %s\nlneto: %s\nWASI: %s\ncurrent net review: %s\ncurrent Wago review: %s\nworkers: %s\n' \
  "$(repo_head "$root")" "$(repo_head "$wago_dir")" "$(repo_head "$lneto_dir")" "$(repo_head "$wasi_dir")" \
  "$(repo_head "$current_net_dir")" "$(repo_head "$current_wago_dir")" "$(repo_head "$workers_dir")" \
  | tee "$out/revisions.txt"

log "plugin standard Go, workspace-independent, race, vet, list, and tidy"
cd "$root"
go test ./... -count=1
record_check go-test-workspace pass
GOWORK=off go test ./... -count=1
record_check go-test-module pass
go test -race ./... -count=1
record_check go-test-race pass
go vet ./...
record_check go-vet pass
go list ./... >"$out/packages.txt"
record_check go-list pass
GOWORK=off go mod tidy
git diff --exit-code -- go.mod go.sum
record_check go-mod-tidy pass 'no module-file changes'

log "bounded fuzz corpus smoke ($fuzztime each)"
go test ./internal/backend/lneto/dns -run '^$' -fuzz '^FuzzDNSWireResponse$' -fuzztime="$fuzztime" | tee "$out/fuzz-dns-wire.txt"
record_check fuzz-dns-wire pass "$fuzztime"
go test ./internal/abi/dns -run '^$' -fuzz '^FuzzDNSV1Layouts$' -fuzztime="$fuzztime" | tee "$out/fuzz-dns-layout.txt"
record_check fuzz-dns-layout pass "$fuzztime"
go test ./internal/abi/tcp -run '^$' -fuzz '^FuzzV1Layouts$' -fuzztime="$fuzztime" | tee "$out/fuzz-tcp-layout.txt"
record_check fuzz-tcp-layout pass "$fuzztime"
go test ./internal/abi/udp -run '^$' -fuzz '^FuzzReceiveResultV1$' -fuzztime="$fuzztime" | tee "$out/fuzz-udp-layout.txt"
record_check fuzz-udp-layout pass "$fuzztime"
go test ./internal/abi/core -run '^$' -fuzz '^FuzzV1Layouts$' -fuzztime="$fuzztime" | tee "$out/fuzz-shared-layout.txt"
record_check fuzz-shared-layout pass "$fuzztime"
go test . -run '^$' -fuzz '^FuzzGuestDNSMemory$' -fuzztime="$fuzztime" | tee "$out/fuzz-dns-guest.txt"
record_check fuzz-dns-guest pass "$fuzztime"
go test . -run '^$' -fuzz '^FuzzGuestTCPStreamMemory$' -fuzztime="$fuzztime" | tee "$out/fuzz-tcp-guest.txt"
record_check fuzz-tcp-guest pass "$fuzztime"
go test . -run '^$' -fuzz '^FuzzGuestUDPPollMemory$' -fuzztime="$fuzztime" | tee "$out/fuzz-udp-guest.txt"
record_check fuzz-udp-guest pass "$fuzztime"

log "benchmarks"
go test . -run '^$' -bench 'BenchmarkGuest(UDP|TCP)Poll$' -benchmem -count=1 | tee "$out/bench-guest-poll.txt"
record_check benchmark-guest-poll pass 'benchmem count=1'
go test ./internal/backend/lneto/udp -run '^$' -bench '^BenchmarkUDPDatagramQueueRoundTrip$' -benchmem -count=1 | tee "$out/bench-udp-queue.txt"
record_check benchmark-udp-queue pass 'benchmem count=1'

log "TinyGo and cross-compile"
GOWORK=off tinygo test ./...
record_check tinygo-test pass
cross_goos=${CROSS_GOOS:-linux}
cross_goarch=${CROSS_GOARCH:-arm64}
GOOS=$cross_goos GOARCH=$cross_goarch CGO_ENABLED=0 GOWORK=off go build ./...
record_check cross-build pass "$cross_goos/$cross_goarch CGO_ENABLED=0"

log "bounded linux/arm64 execution smoke"
ARM64_SIGNOFF_DIR="$out/arm64" "$root/scripts/arm64-execution-signoff.sh"
arm64_status=$(sed -n 's/^status=//p' "$out/arm64/status.txt")
[[ -n "$arm64_status" ]] || fail 'arm64 execution status is missing'
record_check arm64-execution "$arm64_status"

log "source boundaries and custom package inspection"
"$root/scripts/check-source-boundaries.sh"
record_check source-boundaries pass 'lneto imports and blocking API guard'
WAGO_DIR="$wago_dir" LNETO_DIR="$lneto_dir" SIGNOFF_CUSTOM_DIR="$out/custom-cli" \
  "$root/scripts/custom-cli-signoff.sh"
record_check custom-cli-inspection pass 'Go and TinyGo byte-identical for granular TCP/UDP/DNS and explicit all-protocol bundles'

helper="$wago_dir/src/wago/trap_code_release_signoff_test.go"
cleanup() { rm -f "$helper"; }
trap cleanup EXIT
[[ ! -e "$helper" ]] || fail "temporary Wago trap helper already exists"
cat >"$helper" <<'EOF'
package wago

import "errors"

func trapCode(err error) TrapCode {
	var trap *TrapError
	if errors.As(err, &trap) {
		return trap.Code
	}
	return TrapNone
}
EOF

log "Wago merged lifecycle/worker tests"
(
  cd "$wago_dir"
  GOWORK=off go test ./src/wago ./internal/genfacade -count=1
  GOWORK=off go test -race ./src/wago \
    -run 'TestWorkers|TestInstanceBeforeClose|TestInstanceCloseLifecycle|TestLifecycle|TestRuntimeRequireReinstantiation|TestClass' \
    -count=1
)
record_check wago-lifecycle-worker-tests pass 'src/wago, genfacade, and focused race suite'
cleanup

log "lneto audit suite"
(
  cd "$lneto_dir"
  GOWORK=off go test ./... -count=1
)
record_check lneto-test pass

if [[ $run_wasi == 1 ]]; then
  log "WASI audit suite (known native p1 SIGSEGV is the only accepted failure)"
  set +e
  (
    cd "$wasi_dir"
    GOWORK=off go test ./... -count=1
  ) >"$out/wasi-test.txt" 2>&1
  wasi_status=$?
  set -e
  if ((wasi_status != 0)); then
    if ! grep -Eqi 'SIGSEGV|segmentation violation' "$out/wasi-test.txt" || ! grep -Eqi 'p1|preview.?1' "$out/wasi-test.txt"; then
      cat "$out/wasi-test.txt" >&2
      fail "WASI failed outside the documented native p1 exception"
    fi
    echo "WASI: accepted documented native p1 SIGSEGV" | tee "$out/wasi-status.txt"
    record_check wasi-preview1-native-sigsegv accepted-exception 'pinned native preview-1 suite reached the documented SIGSEGV signature'
  else
    echo "WASI: full suite passed; remove the documented exception" | tee "$out/wasi-status.txt"
    record_check wasi-test pass 'full pinned suite passed'
  fi
else
  echo "WASI: skipped by RUN_WASI=$run_wasi" | tee "$out/wasi-status.txt"
  record_check wasi-test skipped "RUN_WASI=$run_wasi"
fi

trap - EXIT
cleanup
log "final clean-tree verification"
if [[ $allow_dirty != 1 ]]; then
  assert_clean "$root" plugin
  assert_clean "$wago_dir" Wago
  assert_clean "$lneto_dir" lneto
  assert_clean "$wasi_dir" WASI
  assert_clean "$current_net_dir" 'current networking review'
  assert_clean "$current_wago_dir" 'current Wago review'
  assert_clean "$workers_dir" 'external workers'
  record_check final-clean-trees pass 'plugin, production inputs, current plugin reviews, and external workers'
else
  echo "release-signoff: final clean-tree check skipped by ALLOW_DIRTY=1"
  record_check final-clean-trees skipped 'ALLOW_DIRTY=1'
fi

log "immutable source-object review packs"
WAGO_DIR="$wago_dir" LNETO_DIR="$lneto_dir" WASI_DIR="$wasi_dir" \
  CURRENT_NET_DIR="$current_net_dir" CURRENT_WAGO_DIR="$current_wago_dir" WORKERS_DIR="$workers_dir" \
  SOURCE_OBJECT_DIR="$out/source-objects" SOURCE_OBJECT_SUBJECT="$(repo_head "$root")" \
  "$root/scripts/release-source-objects.sh"
record_check source-object-packs pass 'production pins plus exact current Wago/net/workers review source trees'

log "isolated current plugin adoption gate"
CURRENT_REVIEW_SOURCE_DIR="$out/source-objects" CURRENT_REVIEW_OUT="$out/current-plugin-review" \
  "$root/scripts/current-plugin-review-signoff.sh"
record_check current-plugin-review-signoff pass 'immutable reconstruction; initially empty GOMODCACHE; network disabled; exact module and go.sum inventory; granular plus aggregate inspection; linked-child cleanup; TinyGo'

log "deterministic release provenance"
GOWORK=off go run ./internal/cmd/release-provenance \
  -out "$out" -plugin "$root" -wago "$wago_dir" -lneto "$lneto_dir" -wasi "$wasi_dir" \
  -current-net "$current_net_dir" -current-wago "$current_wago_dir" -workers "$workers_dir" \
  -cross-goos "$cross_goos" -cross-goarch "$cross_goarch"
(
  cd "$out"
  sha256sum -c evidence.sha256
  sha256sum -c provenance.sha256
)

log "standalone deterministic review bundle"
SIGNOFF_DIR="$out" REVIEW_BUNDLE="$out.review.tar.gz" REVIEW_SUBJECT="$(repo_head "$root")" \
  "$root/scripts/release-review-bundle.sh"

echo "release-signoff: PASS (artifacts: $out; provenance: $out/provenance.json; review bundle: $out.review.tar.gz)"
