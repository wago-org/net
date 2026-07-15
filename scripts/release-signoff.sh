#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=$(realpath "${WAGO_DIR:-$root/.wago/wago-production-97e6f91}")
lneto_dir=$(realpath "${LNETO_DIR:-$root/.audit/lneto}")
wasi_dir=$(realpath "${WASI_DIR:-$root/.audit/wasi}")
current_net_dir=$(realpath "${CURRENT_NET_DIR:-$root/.wago/net-current-plugin-registration-18615546}")
current_wago_dir=$(realpath "${CURRENT_WAGO_DIR:-$root/.wago/wago-current-plugin-lifecycle-ff04a6b1}")
workers_dir=$(realpath "${WORKERS_DIR:-$root/.wago/workers-plugin}")
fuzztime=${FUZZTIME:-3s}
run_wasi=${RUN_WASI:-1}
allow_dirty=${ALLOW_DIRTY:-0}
out=$(realpath -m "${SIGNOFF_DIR:-$root/.wago/release-signoff}")
allow_outside_artifact_root=${ALLOW_SIGNOFF_DIR_OUTSIDE_WAGO:-0}
artifact_root=$(realpath -m "$root/.wago")

# shellcheck source=scripts/lib/production-wago-input.sh
source "$root/scripts/lib/production-wago-input.sh"
# shellcheck source=scripts/lib/wasi-preview1-exception.sh
source "$root/scripts/lib/wasi-preview1-exception.sh"

readonly expected_wago=$production_wago_revision
readonly expected_wago_tree=$production_wago_tree
readonly expected_wago_parent_main=$production_wago_parent_main
readonly expected_wago_parent_workers=$production_wago_parent_workers
readonly expected_lneto=ab1a0c735a8b534a1d6322a3e245bc11a09431e7
readonly expected_wasi=3df6c766ad00e83b314da799dbf9a77b409ad19d
readonly expected_current_net=362ddf815904340aefc526d4bc57e1c7a24d36c9
readonly expected_current_wago=d556b20ff8667a8ae17b1ca399c74a949ac78f2f
readonly expected_workers=1e9139756d8a3c631c59c00b028038c83bfa8341

log() { printf '\n==> %s\n' "$*"; }
fail() { echo "release-signoff: $*" >&2; exit 1; }
path_contains() {
  local parent child
  parent=$(realpath -m "$1")
  child=$(realpath -m "$2")
  [[ "$child" == "$parent" || "$child" == "$parent"/* ]]
}
validate_signoff_dir() {
  local candidate=$1
  [[ $candidate != / ]] || fail "refusing filesystem root as signoff directory"
  [[ $candidate != "$HOME" ]] || fail "refusing home directory as signoff directory"
  ! path_contains "$candidate" "$PWD" || fail "refusing signoff directory that would remove the current working directory"
  for source in "$root" "$wago_dir" "$lneto_dir" "$wasi_dir" "$current_net_dir" "$current_wago_dir" "$workers_dir"; do
    ! path_contains "$candidate" "$source" || fail "refusing signoff directory that would remove source repository $source"
  done
  if [[ $allow_outside_artifact_root != 1 ]]; then
    [[ $candidate == "$artifact_root"/* ]] || fail "signoff output must be beneath $artifact_root; set ALLOW_SIGNOFF_DIR_OUTSIDE_WAGO=1 only for an intentional external artifact directory"
  fi
  [[ $candidate != "$artifact_root" ]] || fail "signoff output must be beneath $artifact_root, not the artifact root itself"
}
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

for command in git go tinygo grep cmp mktemp sed sha256sum; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
for dir in "$root" "$wago_dir" "$lneto_dir" "$wasi_dir" "$current_net_dir" "$current_wago_dir" "$workers_dir"; do
  [[ -d "$dir" ]] || fail "missing repository directory: $dir"
done
validate_signoff_dir "$out"

log "verify pinned audit repositories"
production_wago_verify_exact_clean_merge "$wago_dir" Wago "$expected_wago" "$expected_wago_tree" \
  "$expected_wago_parent_main" "$expected_wago_parent_workers"
assert_head "$lneto_dir" "$expected_lneto" lneto
assert_head "$wasi_dir" "$expected_wasi" WASI
assert_head "$current_net_dir" "$expected_current_net" 'current networking review'
assert_head "$current_wago_dir" "$expected_current_wago" 'current Wago review'
assert_head "$workers_dir" "$expected_workers" 'external workers'
if [[ $allow_dirty != 1 ]]; then
  assert_clean "$root" plugin
  assert_clean "$wago_dir" Wago
  assert_clean "$lneto_dir" lneto
  assert_clean "$wasi_dir" WASI
  assert_clean "$current_net_dir" 'current networking review'
  assert_clean "$current_wago_dir" 'current Wago review'
  assert_clean "$workers_dir" 'external workers'
fi

rm -rf "$out"
mkdir -p "$out" "$root/.wago"
module_input=$(mktemp -d "$root/.wago/release-module-input.XXXXXX")
helper=
cleanup() {
  [[ -z "$helper" ]] || rm -f "$helper"
  rm -rf "$module_input"
}
trap cleanup EXIT
release_mod="$module_input/net-release.mod"
release_sum="$module_input/net-release.sum"
release_work="$module_input/net-release.work"
cp "$root/go.mod" "$release_mod"
cp "$root/go.sum" "$release_sum"
go mod edit -modfile="$release_mod" -replace="github.com/wago-org/wago=$wago_dir"
go mod edit -modfile="$release_mod" -replace="github.com/soypat/lneto=$lneto_dir"
cat >"$release_work" <<EOF
go 1.24.4

use $root

replace github.com/wago-org/wago => $wago_dir
replace github.com/soypat/lneto => $lneto_dir
EOF
release_goflags="${GOFLAGS:+$GOFLAGS }-modfile=$release_mod"
checks="$out/checks.tsv"
: >"$checks"
record_check pinned-revisions pass 'exact audit revisions and ordered Wago parents'
record_check initial-clean-trees pass 'plugin, production inputs, current plugin reviews, and external workers'
WAGO_DIR="$wago_dir" "$root/scripts/wago-plugin-plan-compat.sh" | tee "$out/wago-plugin-plan-compat.txt"
record_check wago-plugin-plan-compat pass 'reviewed redesign requires migration; networking pin unchanged'
CURRENT_WAGO_DIR="$current_wago_dir" CURRENT_NET_DIR="$current_net_dir" WORKERS_DIR="$workers_dir" \
  "$root/scripts/current-plugin-topology-audit.sh" | tee "$out/current-plugin-topology.txt"
record_check current-plugin-topology-audit pass 'moving refs refreshed; explicit publication truth; pooling unsupported'
CURRENT_WAGO_WASI_FIX_DIR="$current_wago_dir" WASI_DIR="$wasi_dir" WASI_FIX_REVIEW_OUT="$out/wasi-fix-review" \
  "$root/scripts/wasi-preview1-fix-review.sh" | tee "$out/wasi-preview1-fix-review.txt"
record_check wasi-preview1-fix-review pass 'patch-equivalent production/current Wago fixes; upstream lifecycle lineage; managed-wrapper and exact-slot integrations; standard/race/TinyGo and both complete WASI suites'
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
record_check wasi-upstream-preview1-audit accepted-exception 'reviewed docs/CI-only upstream matches the exact four-pass/four-fault p1 matrix; pin retained'
printf 'go: %s\n' "$(go version)" | tee "$out/toolchains.txt"
printf 'tinygo: %s\n' "$(tinygo version | tr '\n' ' ')" | tee -a "$out/toolchains.txt"
printf 'plugin: %s\nWago: %s\nlneto: %s\nWASI: %s\ncurrent net review: %s\ncurrent Wago review: %s\nworkers: %s\n' \
  "$(repo_head "$root")" "$(repo_head "$wago_dir")" "$(repo_head "$lneto_dir")" "$(repo_head "$wasi_dir")" \
  "$(repo_head "$current_net_dir")" "$(repo_head "$current_wago_dir")" "$(repo_head "$workers_dir")" \
  | tee "$out/revisions.txt"

log "plugin standard Go, workspace-independent, race, vet, list, and tidy"
cd "$root"
GOWORK="$release_work" go test ./... -count=1
record_check go-test-workspace pass 'isolated workspace selects exact clean production Wago'
GOWORK=off GOFLAGS="$release_goflags" go test ./... -count=1
record_check go-test-module pass 'generated modfile selects exact clean production Wago'
GOWORK="$release_work" go test -race ./... -count=1
record_check go-test-race pass
GOWORK="$release_work" go vet ./...
record_check go-vet pass
GOWORK="$release_work" go list ./... >"$out/packages.txt"
record_check go-list pass
GOWORK=off GOFLAGS="$release_goflags" go mod tidy
cp "$release_mod" "$release_mod.after-tidy"
cp "$release_sum" "$release_sum.after-tidy"
GOWORK=off GOFLAGS="$release_goflags" go mod tidy
cmp "$release_mod.after-tidy" "$release_mod"
cmp "$release_sum.after-tidy" "$release_sum"
git diff --exit-code -- go.mod go.sum
record_check go-mod-tidy pass 'generated release module is idempotent; repository module files unchanged'

log "bounded discovered fuzz smoke ($fuzztime each)"
GOWORK="$release_work" FUZZTIME="$fuzztime" FUZZ_LOG_DIR="$out/fuzz" \
  "$root/scripts/fuzz-smoke.sh" | tee "$out/fuzz-smoke.txt"
record_check fuzz-smoke pass "all discovered targets; $fuzztime each"

log "benchmarks"
GOMAXPROCS=1 GOWORK="$release_work" go test ./... -run '^$' -bench '^Benchmark' -benchmem -benchtime=100ms -count=1 -cpu=1 | tee "$out/bench-runtime.txt"
record_check benchmark-runtime pass 'all runtime benchmarks; benchmem; 100ms; count=1; cpu=1'

log "TinyGo and cross-compile"
GOWORK=off GOFLAGS="$release_goflags" tinygo test ./...
record_check tinygo-test pass
cross_goos=${CROSS_GOOS:-linux}
cross_goarch=${CROSS_GOARCH:-arm64}
GOOS=$cross_goos GOARCH=$cross_goarch CGO_ENABLED=0 GOWORK=off GOFLAGS="$release_goflags" go build ./...
record_check cross-build pass "$cross_goos/$cross_goarch CGO_ENABLED=0"

log "bounded linux/arm64 execution smoke"
GOFLAGS="$release_goflags" ARM64_SIGNOFF_DIR="$out/arm64" "$root/scripts/arm64-execution-signoff.sh"
arm64_status=$(sed -n 's/^status=//p' "$out/arm64/status.txt")
[[ -n "$arm64_status" ]] || fail 'arm64 execution status is missing'
record_check arm64-execution "$arm64_status"

log "source boundaries and custom package inspection"
"$root/scripts/check-source-boundaries.sh"
record_check source-boundaries pass 'lneto imports and blocking API guard'
WAGO_DIR="$wago_dir" LNETO_DIR="$lneto_dir" SIGNOFF_CUSTOM_DIR="$out/custom-cli" \
  "$root/scripts/custom-cli-signoff.sh"
record_check custom-cli-inspection pass 'Go and TinyGo byte-identical for all 11 granular protocol bundles and the explicit all-protocol bundle'

helper="$wago_dir/src/wago/trap_code_release_signoff_test.go"
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
rm -f "$helper"
helper=

log "lneto audit suite"
(
  cd "$lneto_dir"
  GOWORK=off go test ./... -count=1
)
record_check lneto-test pass

if [[ $run_wasi == 1 ]]; then
  log "WASI audit suite (exact four-pass/four-fault p1 matrix is the only accepted exception)"
  wasi_preview1_run_exception_matrix "$wasi_dir" "$out/wasi-matrix" ||
    fail "pinned WASI did not match the exact preview-1 exception matrix"
  cp "$out/wasi-matrix/fault-blake3sum.txt" "$out/wasi-test.txt"
  cat "$out/wasi-matrix/status.txt" >"$out/wasi-status.txt"
  cat "$out/wasi-status.txt"
  record_check wasi-preview1-native-sigsegv accepted-exception 'pinned p1: markdown/crcsum/base64x/jsonproc pass; blake3sum/script/regexmatch/bignum match the exact native SIGSEGV signature'
else
  echo "WASI: skipped by RUN_WASI=$run_wasi" | tee "$out/wasi-status.txt"
  record_check wasi-test skipped "RUN_WASI=$run_wasi"
fi

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
GOWORK=off GOFLAGS="$release_goflags" go run ./internal/cmd/release-provenance \
  -out "$out" -plugin "$root" -wago "$wago_dir" -lneto "$lneto_dir" -wasi "$wasi_dir" \
  -current-net "$current_net_dir" -current-wago "$current_wago_dir" -workers "$workers_dir" \
  -cross-goos "$cross_goos" -cross-goarch "$cross_goarch"
(
  cd "$out"
  sha256sum -c evidence.sha256
  sha256sum -c provenance.sha256
)

log "standalone deterministic review bundle"
GOFLAGS="$release_goflags" SIGNOFF_DIR="$out" REVIEW_BUNDLE="$out.review.tar.gz" REVIEW_SUBJECT="$(repo_head "$root")" \
  "$root/scripts/release-review-bundle.sh"

trap - EXIT
cleanup
echo "release-signoff: PASS (artifacts: $out; provenance: $out/provenance.json; review bundle: $out.review.tar.gz)"
