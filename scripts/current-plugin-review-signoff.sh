#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_dir=$(realpath "${CURRENT_REVIEW_SOURCE_DIR:-${SIGNOFF_DIR:-$root/.wago/release-signoff}/source-objects}")
out=$(realpath -m "${CURRENT_REVIEW_OUT:-${SIGNOFF_DIR:-$root/.wago/release-signoff}/current-plugin-review}")
work=$(realpath -m "${CURRENT_REVIEW_WORK_DIR:-$root/.wago/current-plugin-review-work}")

readonly net_revision=173b38a4d5a0db0e6058544576942a46b9d543df
readonly net_tree=ca7534943e653a6c04c63ec458fc00feb6350799
readonly net_parent=164ee79e98d7e51bf3553fb18b46fd2044b223aa
readonly wago_revision=540c453de318a8385d63ee335e4fd881a628aafc
readonly wago_tree=94168ab93497a9288029d47bdf37cc9f6b6e4049
readonly wago_parent=90018dadbc70c8620984bab71f1eace347c29fa8
readonly workers_revision=1e9139756d8a3c631c59c00b028038c83bfa8341
readonly workers_tree=ca79d1fb02f19ae15d7b166ffc179c01f9a7c212
readonly workers_parent1=5cb4efff83f0a519311fcf03b63496433f2901f0
readonly workers_parent2=08466d04599d7c0da88d4c5cda73a62c775a8dfc
readonly lneto_revision=ab1a0c735a8b534a1d6322a3e245bc11a09431e7
readonly lneto_tree=8de698038293064eb0fd722760ac64290a639b57
readonly lneto_parent=3c1f0e028100ff9485e87a13a8401b675f13321c
readonly wasi_revision=3df6c766ad00e83b314da799dbf9a77b409ad19d
readonly wasi_tree=469e546e384ec9666e7891ab4663c2970f312aed
readonly wasi_parent=91380ea777572a5b88213e7c024adb662cec0c12

readonly net_go_mod_sha256=a037a556a408b0a8e7c5361558cb08504d6a3ba288c365cf24d5d9705eda6568
readonly net_go_sum_sha256=37cac65481cb9f3c8b697f426f812797bc7d8edcb3ecabbb80cf539f1a379d67
readonly wago_go_mod_sha256=85a0a672140a9a14a81dce5b0755b032aa940db500f7ec822912b151b521d48f
readonly workers_go_mod_sha256=81b171ec361acd6395b433ed9ec57ccc141624f3a66497bd415e86459ade5261
readonly workers_go_sum_sha256=13e2826b68f3dbe148975e2be548f711475e0f5a8ece64321adb37ff11a2a777
readonly lneto_go_mod_sha256=2b066ca89578f9e928a6b45db7cbef62cefaa40d8e61d8274c4234e667279396
readonly wasi_go_mod_sha256=395c8f91aa2528b0f41fd4d1630907eed5455948e40aff23da61566e3cc40f4c

fail() { echo "current-plugin-review-signoff: $*" >&2; exit 1; }
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

for command in git go tinygo cmp realpath sed paste sha256sum find grep cut; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
[[ -d "$source_dir" ]] || fail "missing source-object directory: $source_dir"
rm -rf "$out" "$work"
mkdir -p "$out" "$work"

checkout_pack() {
  local name=$1 revision=$2 tree=$3
  shift 3
  local directory=$work/$name pack=$source_dir/$name.pack
  [[ -f "$pack" ]] || fail "missing source-object pack: $pack"
  git init --quiet "$directory"
  git -C "$directory" index-pack --stdin <"$pack" >/dev/null
  git -C "$directory" cat-file -e "$revision^{commit}" 2>/dev/null || fail "$name revision is absent from its pack"
  [[ $(git -C "$directory" rev-parse "$revision^{tree}") == "$tree" ]] || fail "$name tree does not match the bound review tree"
  local actual_parents
  actual_parents=$(git -C "$directory" cat-file -p "$revision" | sed -n 's/^parent //p' | paste -sd ' ' -)
  [[ "$actual_parents" == "$*" ]] || fail "$name ordered parents are '$actual_parents', want '$*'"
  printf '%s\n' "$revision" >"$directory/.git/shallow"
  git -C "$directory" checkout --quiet --detach "$revision"
}

checkout_pack net-current-review "$net_revision" "$net_tree" "$net_parent"
checkout_pack wago-current-review "$wago_revision" "$wago_tree" "$wago_parent"
checkout_pack workers-current "$workers_revision" "$workers_tree" "$workers_parent1" "$workers_parent2"
checkout_pack lneto "$lneto_revision" "$lneto_tree" "$lneto_parent"
checkout_pack wasi "$wasi_revision" "$wasi_tree" "$wasi_parent"

mv "$work/net-current-review" "$work/net"
mv "$work/wago-current-review" "$work/wago"
mv "$work/workers-current" "$work/workers"

require_sha256() {
  local file=$1 want=$2 name=$3 actual
  actual=$(sha256sum "$file" | cut -d ' ' -f 1)
  [[ "$actual" == "$want" ]] || fail "$name SHA-256 is $actual, want $want"
}
require_sha256 "$work/net/go.mod" "$net_go_mod_sha256" 'net go.mod'
require_sha256 "$work/net/go.sum" "$net_go_sum_sha256" 'net go.sum'
require_sha256 "$work/wago/go.mod" "$wago_go_mod_sha256" 'Wago go.mod'
require_sha256 "$work/workers/go.mod" "$workers_go_mod_sha256" 'workers go.mod'
require_sha256 "$work/workers/go.sum" "$workers_go_sum_sha256" 'workers go.sum'
require_sha256 "$work/lneto/go.mod" "$lneto_go_mod_sha256" 'lneto go.mod'
require_sha256 "$work/wasi/go.mod" "$wasi_go_mod_sha256" 'WASI go.mod'

cat >"$work/go.work" <<EOF
go 1.24.4

use (
	./net
	./wago
	./workers
	./lneto
)
EOF

cat >"$out/module-inventory.txt" <<EOF
module github.com/soypat/lneto $lneto_revision $lneto_tree lneto $lneto_go_mod_sha256 none
module github.com/wago-org/net $net_revision $net_tree net-current-review $net_go_mod_sha256 $net_go_sum_sha256
module github.com/wago-org/wago $wago_revision $wago_tree wago-current-review $wago_go_mod_sha256 none
module github.com/wago-org/wasi $wasi_revision $wasi_tree wasi $wasi_go_mod_sha256 none
module github.com/wago-org/workers $workers_revision $workers_tree workers-current $workers_go_mod_sha256 $workers_go_sum_sha256
sum github.com/soypat/lneto v0.0.0-20260710133615-ab1a0c735a8b h1:qcoYcwWsFVI7zu0SRqhGD+B07R8o+sLFHwZQ/LtsHkM=
sum github.com/soypat/lneto v0.0.0-20260710133615-ab1a0c735a8b/go.mod h1:Be5PjwoYukvHFiUXxpYi8+ppH2F/gw/vjGBvFdv+Ti8=
sum github.com/wago-org/wago v0.0.0-20260711053856-7d89b98c854d h1:fzJn6UlsGwiqwyTN+Si6oFoETUhUoJ/Rphhx94M5Pqc=
sum github.com/wago-org/wago v0.0.0-20260711053856-7d89b98c854d/go.mod h1:d44S+59u6VHeqEaIZBKTeB8viyswTP97O9IKA6Gyzc4=
sum github.com/wago-org/workers v0.0.0-20260711080606-1e9139756d8a h1:I832KhInH+NdDVyoA18dwCErTrfduemWY7fccozgXSw=
sum github.com/wago-org/workers v0.0.0-20260711080606-1e9139756d8a/go.mod h1:lRgtcCNsXr30h+ZovoKMGhKMvk6slR1cwFDZ7HoBo2g=
EOF
printf 'net: %s\nWago: %s\nworkers: %s\nlneto: %s\nWASI: %s\n' \
  "$net_revision" "$wago_revision" "$workers_revision" "$lneto_revision" "$wasi_revision" >"$out/revisions.txt"

gomodcache=$work/gomodcache
mkdir -p "$gomodcache"
export GOMODCACHE="$gomodcache" GOPROXY=off GOSUMDB=off

(
  cd "$work/net"
  GOWORK="$work/go.work" go test ./... -count=1
) 2>&1 | tee "$out/go-test.txt"
(
  cd "$work/net"
  GOWORK="$work/go.work" go test -race . -run '^TestExternalWorkersPluginRetiresLinkedNetworkingState$' -count=5
) 2>&1 | tee "$out/external-workers-race.txt"
(
  cd "$work/net"
  GOWORK="$work/go.work" go vet ./...
) 2>&1 | tee "$out/go-vet.txt"
(
  cd "$work/workers"
  GOWORK="$work/go.work" go test ./... -count=1
  GOWORK="$work/go.work" go test -race ./... -count=1
  GOWORK="$work/go.work" go vet ./...
) 2>&1 | tee "$out/workers.txt"
(
  cd "$work/net"
  GOWORK="$work/go.work" tinygo test ./...
) 2>&1 | tee "$out/tinygo-test.txt"

NET_DIR="$work/net" WAGO_DIR="$work/wago" LNETO_DIR="$work/lneto" WORKERS_DIR="$work/workers" \
  SIGNOFF_CUSTOM_DIR="$out/custom-cli" "$root/scripts/custom-cli-signoff.sh" 2>&1 | tee "$out/custom-cli.txt"

cmp "$out/custom-cli/inspection-go.json" "$out/custom-cli/inspection-tinygo.json"
if find "$gomodcache" -type f ! -path "$gomodcache/cache/lock" -print -quit | grep -q .; then
  find "$gomodcache" -type f ! -path "$gomodcache/cache/lock" -print >&2
  fail 'cold module cache unexpectedly acquired module files'
fi
echo 'current-plugin-review-signoff: PASS (pack-only local modules; initially empty GOMODCACHE with no module payload; network disabled; exact go.sum evidence; granular and aggregate inspection; linked-child cleanup)'
